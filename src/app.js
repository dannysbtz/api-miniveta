const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const { rateLimit } = require("express-rate-limit");
const { offlineExpiration } = require("./offline-expiry");
const { ISSUER, SESSION_AUDIENCE, OFFLINE_AUDIENCE, DEVICE_CHALLENGE_AUDIENCE } = require("./config");
const DeviceChallenge = require("./device-challenge");
const { parseDevicePublicKey, verifyDeviceProof } = require("./device-crypto");
const { listPendingRequests, approveDeviceRequest, rejectDeviceRequest } = require("./device-requests");

const { normalizeUsername } = require("./username");

function createApp({ User, Challenge = DeviceChallenge, config, clock = () => Date.now(), loginLimit = 10, challengeLimit = 30 }) {
  const app = express();
  app.set("trust proxy", "loopback");
  const dummyHash = bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), 12);
  const nowSeconds = () => Math.floor(clock() / 1000);
  const active = (user) => user.subscription && user.subscription.status === "active" &&
    offlineExpiration(nowSeconds(), user.subscription.endsAt) > nowSeconds();
  const userInfo = (user) => ({ id: String(user._id), name: user.name });
  const subscriptionInfo = (user) => ({ status: user.subscription.status, endsAt: user.subscription.endsAt.toISOString() });
  const adminUserInfo = (user) => ({
    id: String(user._id),
    username: user.username,
    name: user.name,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    sessionVersion: user.sessionVersion,
    subscription: {
      ...subscriptionInfo(user),
      paidAt: user.subscription.paidAt ? user.subscription.paidAt.toISOString() : null,
    },
    devices: (user.devices || []).map(({ fingerprint, status, createdAt, updatedAt, requestId }) => ({ fingerprint, status, createdAt, updatedAt, requestId })),
  });

  function offlineToken(user, deviceKey) {
    const issuedAt = nowSeconds();
    return jwt.sign({
      name: user.name,
      deviceKey,
      subscriptionEndsAt: user.subscription.endsAt.toISOString(),
      token_use: "offline",
      iat: issuedAt,
      exp: offlineExpiration(issuedAt, user.subscription.endsAt),
    }, config.privateKey, { algorithm: "RS256", issuer: ISSUER, audience: OFFLINE_AUDIENCE, subject: String(user._id) });
  }

  function sessionToken(user, deviceKey) {
    return jwt.sign({ ver: user.sessionVersion, deviceKey, token_use: "session", iat: nowSeconds() }, config.sessionSecret, {
      algorithm: "HS256", expiresIn: "30d", issuer: ISSUER, audience: SESSION_AUDIENCE, subject: String(user._id),
    });
  }

  app.use(cors({ allowedHeaders: ["Content-Type", "Authorization", "X-Device-Challenge", "X-Device-Proof", "X-Admin-Key"] }));
  app.use("/api/auth", (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  app.use("/api/admin", (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  app.use(express.json({ limit: "8kb" }));
  app.get("/api/health", (_req, res) => res.json({ ok: true, message: "API Miniventa running" }));

  app.post("/api/auth/device-challenge", rateLimit({ windowMs: 15 * 60 * 1000, limit: challengeLimit, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "too_many_attempts" } }), async (_req, res, next) => {
    try {
      const jti = crypto.randomBytes(32).toString("base64url");
      const issuedAt = nowSeconds();
      await Challenge.create({ jti, expiresAt: new Date((issuedAt + 120) * 1000) });
      const challenge = jwt.sign({ token_use: "device-challenge", iat: issuedAt, exp: issuedAt + 120, jti }, config.sessionSecret, {
        algorithm: "HS256", issuer: ISSUER, audience: DEVICE_CHALLENGE_AUDIENCE,
      });
      return res.json({ challenge });
    } catch (error) { return next(error); }
  });

  app.post("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: loginLimit, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "too_many_attempts" } }), async (req, res, next) => {
    try {
      const { username, password, devicePublicKey, deviceChallenge, deviceProof } = req.body || {};
      const normalizedUsername = normalizeUsername(username);
      if (!normalizedUsername || typeof password !== "string" || Buffer.byteLength(password) > 72 ||
          typeof deviceChallenge !== "string" || typeof deviceProof !== "string") {
        return res.status(400).json({ error: "invalid_request" });
      }
      let device;
      try {
        device = parseDevicePublicKey(devicePublicKey);
      } catch {
        return res.status(401).json({ error: "invalid_device_proof" });
      }
      if (!await consumeDeviceProof(device.key, deviceChallenge, deviceProof)) return res.status(401).json({ error: "invalid_device_proof" });
      const user = await User.findOne({ username: normalizedUsername }).select("+passwordHash");
      const matches = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);
      if (!user || !matches) return res.status(401).json({ error: "invalid_credentials" });
      if (!active(user)) return res.status(403).json({ error: "subscription_inactive" });
      const devices = user.devices || [];
      const activeDevice = devices.find((entry) => entry.status === "active");
      const matchingActive = activeDevice?.fingerprint === device.fingerprint;
      if (!matchingActive) {
        const now = new Date(clock());
        const pending = devices.find((entry) => entry.fingerprint === device.fingerprint && entry.status === "pending");
        if (pending) return res.status(202).json({ error: "device_change_pending", requestId: pending.requestId });
        const requestId = crypto.randomUUID();
        const status = devices.length === 0 ? "active" : "pending";
        const entry = { fingerprint: device.fingerprint, publicKey: device.publicKey, status, createdAt: now, updatedAt: now, requestId };
        if (status === "active") {
          const inserted = await User.updateOne({ _id: user._id, devices: { $not: { $elemMatch: { status: "active" } } } }, { $push: { devices: entry } });
          if (!inserted.modifiedCount) {
            const latest = await User.findById(user._id);
            const winner = latest?.devices?.find((item) => item.status === "active");
            if (winner?.fingerprint !== device.fingerprint) return createPendingRequest(User, user, device, now, res);
          }
        } else {
          return createPendingRequest(User, user, device, now, res);
        }
      }
      return res.json({ sessionToken: sessionToken(user, device.fingerprint), offlineToken: offlineToken(user, device.fingerprint), user: userInfo(user), subscription: subscriptionInfo(user) });
    } catch (error) { return next(error); }
  });

  async function requireSession(req, res, next) {
    const authorization = req.get("authorization") || "";
    const match = /^Bearer ([^\s]+)$/i.exec(authorization);
    if (!match) return res.status(401).json({ error: "invalid_session" });
    let payload;
    try {
      payload = jwt.verify(match[1], config.sessionSecret, { algorithms: ["HS256"], issuer: ISSUER, audience: SESSION_AUDIENCE, clockTimestamp: nowSeconds() });
      if (payload.token_use !== "session" || typeof payload.sub !== "string" || !Number.isInteger(payload.ver) || !/^[a-f\d]{64}$/.test(payload.deviceKey || "")) throw new Error("invalid session");
    } catch {
      return res.status(401).json({ error: "invalid_session" });
    }
    try {
      if (!/^[a-f\d]{24}$/i.test(payload.sub)) return res.status(401).json({ error: "invalid_session" });
      const userQuery = User.findById(payload.sub);
      const user = await (typeof userQuery.select === "function" ? userQuery.select("+devices.publicKey") : userQuery);
      if (!user || user.sessionVersion !== payload.ver) return res.status(401).json({ error: "invalid_session" });
      const device = (user.devices || []).find((entry) => entry.status === "active" && entry.fingerprint === payload.deviceKey);
      if (!device || typeof device.publicKey !== "string") return res.status(401).json({ error: "invalid_session" });
      let parsedDevice;
      try { parsedDevice = parseDevicePublicKey(device.publicKey); }
      catch { return res.status(401).json({ error: "invalid_session" }); }
      if (parsedDevice.fingerprint !== payload.deviceKey ||
          !await consumeDeviceProof(parsedDevice.key, req.get("X-Device-Challenge"), req.get("X-Device-Proof"))) {
        return res.status(401).json({ error: "invalid_session" });
      }
      if (!active(user)) return res.status(403).json({ error: "subscription_inactive" });
      req.deviceKey = payload.deviceKey;
      req.user = user;
      return next();
    } catch (error) { return next(error); }
  }

  app.get("/api/auth/access", requireSession, (req, res) => res.json({ user: userInfo(req.user), subscription: subscriptionInfo(req.user) }));
  app.post("/api/auth/renew", requireSession, (req, res) => res.json({ offlineToken: offlineToken(req.user, req.deviceKey), user: userInfo(req.user), subscription: subscriptionInfo(req.user) }));

  function requireAdmin(req, res, next) {
    if (!config.adminApiKey) return res.status(503).json({ error: "admin_not_configured" });
    const supplied = req.get("X-Admin-Key") || "";
    const expectedBuffer = Buffer.from(config.adminApiKey);
    const suppliedBuffer = Buffer.from(supplied);
    if (expectedBuffer.length !== suppliedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, suppliedBuffer)) {
      return res.status(401).json({ error: "invalid_admin_key" });
    }
    return next();
  }

  app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
    try {
      const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";
      const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const filter = escapedSearch ? { $or: [{ username: new RegExp(escapedSearch, "i") }, { name: new RegExp(escapedSearch, "i") }] } : {};
      const users = await User.find(filter)
        .select("username name createdAt updatedAt sessionVersion subscription devices.fingerprint devices.status devices.createdAt devices.updatedAt devices.requestId")
        .sort({ updatedAt: -1 })
        .limit(500);
      return res.json({ users: users.map(adminUserInfo) });
    } catch (error) { return next(error); }
  });

  app.post("/api/admin/users", requireAdmin, async (req, res, next) => {
    try {
      const { username: rawUsername, name: rawName, password, status, endsAt, paidAt } = req.body || {};
      const username = normalizeUsername(rawUsername);
      const name = typeof rawName === "string" ? rawName.trim() : "";
      const validDate = (value) => typeof value === "string" &&
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) && !Number.isNaN(new Date(value).getTime());
      if (!username || !name || name.length > 100 || typeof password !== "string" ||
          Buffer.byteLength(password) < 12 || Buffer.byteLength(password) > 72 || /[\r\n]/.test(password) ||
          !["active", "inactive"].includes(status) || !validDate(endsAt) || (paidAt !== null && !validDate(paidAt))) {
        return res.status(400).json({ error: "invalid_request" });
      }
      const parsedEndsAt = new Date(endsAt);
      if (status === "active" && parsedEndsAt <= new Date(clock())) return res.status(400).json({ error: "invalid_request" });
      const user = await User.create({
        username,
        name,
        passwordHash: await bcrypt.hash(password, 12),
        sessionVersion: 0,
        devices: [],
        subscription: { status, endsAt: parsedEndsAt, paidAt: paidAt ? new Date(paidAt) : null },
      });
      return res.status(201).json({ user: adminUserInfo(user) });
    } catch (error) {
      if (error.code === 11000) return res.status(409).json({ error: "username_exists" });
      return next(error);
    }
  });

  app.patch("/api/admin/users/:id/access", requireAdmin, async (req, res, next) => {
    try {
      const { status, endsAt, paidAt } = req.body || {};
      if (!/^[a-f\d]{24}$/i.test(req.params.id) || !["active", "inactive"].includes(status) ||
          typeof endsAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(endsAt) ||
          (paidAt !== null && (typeof paidAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(paidAt)))) {
        return res.status(400).json({ error: "invalid_request" });
      }
      const parsedEndsAt = new Date(endsAt);
      const parsedPaidAt = paidAt === null ? null : new Date(paidAt);
      if (Number.isNaN(parsedEndsAt.getTime()) || (paidAt !== null && Number.isNaN(parsedPaidAt.getTime())) ||
          (status === "active" && parsedEndsAt <= new Date(clock()))) {
        return res.status(400).json({ error: "invalid_request" });
      }
      const user = await User.findOneAndUpdate({ _id: req.params.id }, {
        $set: { subscription: { status, endsAt: parsedEndsAt, paidAt: parsedPaidAt } },
        $inc: { sessionVersion: 1 },
      }, { new: true, runValidators: true });
      if (!user) return res.status(404).json({ error: "user_not_found" });
      return res.json({ user: adminUserInfo(user) });
    } catch (error) { return next(error); }
  });

  app.post("/api/admin/users/:id/revoke-sessions", requireAdmin, async (req, res, next) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: "invalid_request" });
      const user = await User.findOneAndUpdate({ _id: req.params.id }, { $inc: { sessionVersion: 1 } }, { new: true });
      if (!user) return res.status(404).json({ error: "user_not_found" });
      return res.json({ user: adminUserInfo(user) });
    } catch (error) { return next(error); }
  });

  app.get("/api/admin/device-requests", requireAdmin, async (_req, res, next) => {
    try { return res.json({ requests: await listPendingRequests(User) }); }
    catch (error) { return next(error); }
  });

  app.post("/api/admin/device-requests/:requestId/approve", requireAdmin, async (req, res, next) => {
    try {
      const requests = await listPendingRequests(User);
      const pending = requests.find((entry) => entry.requestId === req.params.requestId);
      if (!pending) return res.status(404).json({ error: "request_not_found" });
      const approved = await approveDeviceRequest(User, pending.username, pending.requestId, new Date(clock()));
      return res.json({ approved });
    } catch (error) { return next(error); }
  });

  app.post("/api/admin/device-requests/:requestId/reject", requireAdmin, async (req, res, next) => {
    try {
      const requests = await listPendingRequests(User);
      const pending = requests.find((entry) => entry.requestId === req.params.requestId);
      if (!pending) return res.status(404).json({ error: "request_not_found" });
      const rejected = await rejectDeviceRequest(User, pending.username, pending.requestId, new Date(clock()));
      return res.json({ rejected });
    } catch (error) { return next(error); }
  });

  app.use((error, _req, res, _next) => {
    if (error.type === "entity.parse.failed" || error.type === "entity.too.large") return res.status(error.status).json({ error: "invalid_request" });
    console.error("Error de API:", error.message);
    return res.status(500).json({ error: "internal_error" });
  });

  async function consumeDeviceProof(publicKey, challengeToken, proof) {
    let challengePayload;
    try {
      challengePayload = jwt.verify(challengeToken, config.sessionSecret, {
        algorithms: ["HS256"], issuer: ISSUER, audience: DEVICE_CHALLENGE_AUDIENCE, clockTimestamp: nowSeconds(),
      });
      if (challengePayload.token_use !== "device-challenge" || typeof challengePayload.jti !== "string" ||
          !Number.isInteger(challengePayload.iat) || challengePayload.iat > nowSeconds() ||
          challengePayload.exp - challengePayload.iat !== 120 || !verifyDeviceProof(publicKey, challengeToken, proof)) return false;
    } catch {
      return false;
    }
    const consumed = await Challenge.findOneAndDelete({ jti: challengePayload.jti, expiresAt: { $gt: new Date(clock()) } });
    return Boolean(consumed);
  }

  return app;
}

async function createPendingRequest(User, user, device, now, res) {
  const pending = (user.devices || []).find((entry) => entry.fingerprint === device.fingerprint && entry.status === "pending");
  if (pending) return res.status(202).json({ error: "device_change_pending", requestId: pending.requestId });
  const entry = { fingerprint: device.fingerprint, publicKey: device.publicKey, status: "pending", createdAt: now, updatedAt: now, requestId: crypto.randomUUID() };
  const inserted = await User.updateOne({ _id: user._id, devices: { $not: { $elemMatch: { fingerprint: device.fingerprint, status: "pending" } } } }, { $push: { devices: entry } });
  if (!inserted.modifiedCount) {
    const latest = await User.findById(user._id);
    const existing = latest?.devices?.find((item) => item.fingerprint === device.fingerprint && item.status === "pending");
    if (existing) return res.status(202).json({ error: "device_change_pending", requestId: existing.requestId });
    throw new Error("No se pudo crear la solicitud de cambio de dispositivo");
  }
  return res.status(202).json({ error: "device_change_pending", requestId: entry.requestId });
}

module.exports = { createApp };