const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const request = require("supertest");
const { createApp } = require("../src/app");
const { approveDeviceRequest } = require("../src/device-requests");
const { ISSUER, OFFLINE_AUDIENCE, DEVICE_CHALLENGE_AUDIENCE } = require("../src/config");

const rsaKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const config = { privateKey: rsaKeys.privateKey, publicKey: rsaKeys.publicKey, sessionSecret: "a-secure-test-secret-with-at-least-32-bytes" };
const password = "correct-horse-battery";
const passwordHash = bcrypt.hashSync(password, 4);
const baseTime = Date.parse("2026-01-01T00:00:00Z");
const devicePair = () => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicKeyPem = (pair) => pair.publicKey.export({ type: "spki", format: "pem" });

function fixture(loginLimit = 100, challengeLimit = 30) {
  let time = baseTime;
  const user = {
    _id: "507f1f77bcf86cd799439011", username: "usuario", name: "Ana", passwordHash, sessionVersion: 1, devices: [],
    subscription: { status: "active", endsAt: new Date(baseTime + 30 * 86400000) },
  };
  const challenges = new Map();
  const Challenge = {
    create: async (challenge) => { challenges.set(challenge.jti, challenge); return challenge; },
    findOneAndDelete: async ({ jti, expiresAt }) => {
      const challenge = challenges.get(jti);
      if (!challenge || challenge.expiresAt <= expiresAt.$gt) return null;
      challenges.delete(jti);
      return challenge;
    },
  };
  const User = {
    findOne: (query) => ({ select: async () => query.username === user.username ? user : null }),
    findById: async (id) => id === user._id ? user : null,
    updateOne: async (filter, update) => {
      const condition = filter.devices.$not.$elemMatch;
      const duplicate = user.devices.some((device) => Object.entries(condition).every(([key, value]) => device[key] === value));
      if (duplicate) return { modifiedCount: 0 };
      user.devices.push(update.$push.devices);
      return { modifiedCount: 1 };
    },
    findOneAndUpdate: async (filter, update) => {
      if (filter.username !== user.username || !user.devices.some((item) => item.requestId === filter.devices.$elemMatch.requestId && item.status === "pending")) return null;
      const requestId = filter.devices.$elemMatch.requestId;
      for (const item of user.devices) {
        if (item.requestId === requestId && item.status === "pending") Object.assign(item, { status: "active", updatedAt: update.$set["devices.$[pending].updatedAt"] });
        else if (item.status === "active") Object.assign(item, { status: "revoked", updatedAt: update.$set["devices.$[active].updatedAt"] });
      }
      user.sessionVersion += update.$inc.sessionVersion;
      return user;
    },
  };
  const app = createApp({ User, Challenge, config, clock: () => time, loginLimit, challengeLimit });
  return { app, user, challenges, advance: (milliseconds) => { time += milliseconds; }, now: () => Math.floor(time / 1000) };
}

async function login(app, pair = devicePair(), fields = {}) {
  const challengeResponse = await request(app).post("/api/auth/device-challenge").send({});
  const challenge = challengeResponse.body.challenge;
  const devicePublicKey = publicKeyPem(pair);
  const deviceProof = crypto.sign("sha256", Buffer.from(challenge), pair.privateKey).toString("base64url");
  return request(app).post("/api/auth/login").send({ username: "  USUARIO  ", password, devicePublicKey, deviceChallenge: challenge, deviceProof, ...fields });
}

async function authenticatedRequest(app, method, path, sessionToken, pair, challenge) {
  const token = challenge || (await request(app).post("/api/auth/device-challenge").send({})).body.challenge;
  const proof = crypto.sign("sha256", Buffer.from(token), pair.privateKey).toString("base64url");
  return request(app)[method](path)
    .set("Authorization", `Bearer ${sessionToken}`)
    .set("X-Device-Challenge", token)
    .set("X-Device-Proof", proof);
}

function verifyOffline(token, clockTimestamp) {
  return jwt.verify(token, rsaKeys.publicKey, { algorithms: ["RS256"], issuer: ISSUER, audience: OFFLINE_AUDIENCE, clockTimestamp });
}

test("rate limits use the client IP forwarded by the trusted local proxy", async () => {
  const { app } = fixture(1);
  const firstIp = "198.51.100.10";
  const secondIp = "198.51.100.11";
  const first = () => request(app).post("/api/auth/login").set("X-Forwarded-For", firstIp).send({});

  assert.equal((await first()).status, 400);
  assert.equal((await first()).status, 429);
  assert.equal((await request(app).post("/api/auth/login").set("X-Forwarded-For", secondIp).send({})).status, 400);
});

test("reto firmado cumple issuer/audience/expiración y primer dispositivo recibe tokens ligados", async () => {
  const { app, user, now, challenges } = fixture();
  assert.deepEqual((await request(app).get("/api/health")).body, { ok: true, message: "API Miniventa running" });
  const challengeResponse = await request(app).post("/api/auth/device-challenge");
  const challenge = jwt.verify(challengeResponse.body.challenge, config.sessionSecret, { algorithms: ["HS256"], issuer: ISSUER, audience: DEVICE_CHALLENGE_AUDIENCE, clockTimestamp: now() });
  assert.equal(challenge.exp - challenge.iat, 120);
  assert.equal(challenges.size, 1);
  const pair = devicePair();
  const devicePublicKey = publicKeyPem(pair);
  const deviceProof = crypto.sign("sha256", Buffer.from(challengeResponse.body.challenge), pair.privateKey).toString("base64url");
  const credentials = { username: "usuario", password, devicePublicKey, deviceChallenge: challengeResponse.body.challenge, deviceProof };
  const response = await request(app).post("/api/auth/login").send(credentials);
  assert.equal(response.status, 200);
  assert.equal(response.headers["cache-control"], "no-store");
  const offline = verifyOffline(response.body.offlineToken, now());
  assert.equal(offline.sub, user._id);
  assert.equal(offline.name, "Ana");
  assert.equal(offline.deviceKey, user.devices[0].fingerprint);
  assert.equal(offline.subscriptionEndsAt, user.subscription.endsAt.toISOString());
  assert.equal(offline.exp - offline.iat, 7 * 86400);
  const session = jwt.verify(response.body.sessionToken, config.sessionSecret, { algorithms: ["HS256"], issuer: ISSUER, audience: "miniventa-session", clockTimestamp: now() });
  assert.equal(session.deviceKey, offline.deviceKey);
  assert.equal((await authenticatedRequest(app, "get", "/api/auth/access", response.body.sessionToken, pair)).status, 200);
  assert.equal((await request(app).get("/api/auth/access").auth(response.body.offlineToken, { type: "bearer" })).status, 401);
  assert.equal((await request(app).post("/api/auth/login").send(credentials)).status, 401);
  assert.equal((await login(app, pair)).status, 200);
});

test("new device is pending without tokens, and duplicate requests reuse requestId", async () => {
  const { app, user } = fixture();
  assert.equal((await login(app)).status, 200);
  const secondPair = devicePair();
  const first = await login(app, secondPair);
  const retry = await login(app, secondPair);
  assert.equal(first.status, 202);
  assert.deepEqual(Object.keys(first.body).sort(), ["error", "requestId"]);
  assert.equal(first.body.error, "device_change_pending");
  assert.equal(retry.status, 202);
  assert.equal(retry.body.requestId, first.body.requestId);
  assert.equal(user.devices.filter((device) => device.status === "pending").length, 1);
});

test("a new identity is not auto-activated when device history already exists", async () => {
  const { app, user } = fixture();
  user.devices.push({ fingerprint: "a".repeat(64), publicKey: "revoked-key", status: "revoked", requestId: crypto.randomUUID(), createdAt: new Date(baseTime), updatedAt: new Date(baseTime) });
  const response = await login(app, devicePair());
  assert.equal(response.status, 202);
  assert.equal(user.devices.filter((device) => device.status === "active").length, 0);
  assert.equal(user.devices.filter((device) => device.status === "pending").length, 1);
});

test("wrong key proof and expired challenge are rejected", async () => {
  const setup = fixture();
  const pair = devicePair();
  const wrongPair = devicePair();
  const challenge = (await request(setup.app).post("/api/auth/device-challenge")).body.challenge;
  const invalid = await request(setup.app).post("/api/auth/login").send({ username: "usuario", password, devicePublicKey: publicKeyPem(pair), deviceChallenge: challenge, deviceProof: crypto.sign("sha256", Buffer.from(challenge), wrongPair.privateKey).toString("base64url") });
  assert.equal(invalid.status, 401);
  const wrongIssuer = jwt.sign({ token_use: "device-challenge", iat: setup.now(), exp: setup.now() + 120, jti: "not-stored" }, config.sessionSecret, { algorithm: "HS256", issuer: "wrong-issuer", audience: DEVICE_CHALLENGE_AUDIENCE });
  const wrongIssuerProof = crypto.sign("sha256", Buffer.from(wrongIssuer), pair.privateKey).toString("base64url");
  assert.equal((await request(setup.app).post("/api/auth/login").send({ username: "usuario", password, devicePublicKey: publicKeyPem(pair), deviceChallenge: wrongIssuer, deviceProof: wrongIssuerProof })).status, 401);
  const expiredProof = crypto.sign("sha256", Buffer.from(challenge), pair.privateKey).toString("base64url");
  setup.advance(121000);
  const expired = await request(setup.app).post("/api/auth/login").send({ username: "usuario", password, devicePublicKey: publicKeyPem(pair), deviceChallenge: challenge, deviceProof: expiredProof });
  assert.equal(expired.status, 401);
});

test("session routes require a fresh one-time proof from the active device key", async () => {
  const { app, user } = fixture();
  const pair = devicePair();
  const loggedIn = await login(app, pair);
  const accessPath = "/api/auth/access";
  const renewPath = "/api/auth/renew";

  assert.equal((await request(app).get(accessPath).auth(loggedIn.body.sessionToken, { type: "bearer" })).status, 401);
  assert.equal((await request(app).post(renewPath).auth(loggedIn.body.sessionToken, { type: "bearer" })).status, 401);

  const challenge = (await request(app).post("/api/auth/device-challenge")).body.challenge;
  const wrongPair = devicePair();
  const badProof = crypto.sign("sha256", Buffer.from(challenge), wrongPair.privateKey).toString("base64url");
  const badAccess = await request(app).get(accessPath)
    .auth(loggedIn.body.sessionToken, { type: "bearer" })
    .set("X-Device-Challenge", challenge)
    .set("X-Device-Proof", badProof);
  assert.equal(badAccess.status, 401);

  assert.equal((await authenticatedRequest(app, "get", accessPath, loggedIn.body.sessionToken, pair, challenge)).status, 200);
  assert.equal((await authenticatedRequest(app, "get", accessPath, loggedIn.body.sessionToken, pair, challenge)).status, 401);

  const renewed = await authenticatedRequest(app, "post", renewPath, loggedIn.body.sessionToken, pair);
  assert.equal(renewed.status, 200);
  assert.ok(renewed.body.offlineToken);

  user.devices[0].status = "revoked";
  assert.equal((await authenticatedRequest(app, "post", renewPath, loggedIn.body.sessionToken, pair)).status, 401);
});

test("device challenge endpoint is rate limited and CORS allows DPoP headers", async () => {
  const { app } = fixture();
  const preflight = await request(app).options("/api/auth/access")
    .set("Origin", "https://example.test")
    .set("Access-Control-Request-Method", "GET")
    .set("Access-Control-Request-Headers", "authorization,x-device-challenge,x-device-proof,x-admin-key");
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers["access-control-allow-headers"], /x-device-challenge/i);
  assert.match(preflight.headers["access-control-allow-headers"], /x-device-proof/i);
  assert.match(preflight.headers["access-control-allow-headers"], /x-admin-key/i);

  const limited = fixture(100, 1);
  assert.equal((await request(limited.app).post("/api/auth/device-challenge")).status, 200);
  assert.equal((await request(limited.app).post("/api/auth/device-challenge")).status, 429);
});

test("approval replaces only active device, invalidates sessions, and revoked identity must request approval again", async () => {
  const { app, user, now, advance } = fixture();
  const oldPair = devicePair();
  const oldLogin = await login(app, oldPair);
  const newPair = devicePair();
  const pending = await login(app, newPair);
  const approved = await approveDeviceRequest({
    findOneAndUpdate: async (filter, update) => {
      if (filter.username !== user.username || !user.devices.some((item) => item.requestId === filter.devices.$elemMatch.requestId && item.status === "pending")) return null;
      const requestId = filter.devices.$elemMatch.requestId;
      for (const item of user.devices) {
        if (item.requestId === requestId && item.status === "pending") Object.assign(item, { status: "active", updatedAt: update.$set["devices.$[pending].updatedAt"] });
        else if (item.status === "active") Object.assign(item, { status: "revoked", updatedAt: update.$set["devices.$[active].updatedAt"] });
      }
      user.sessionVersion += update.$inc.sessionVersion;
      return user;
    },
  }, "usuario", pending.body.requestId, new Date(now() * 1000));
  assert.equal(approved.requestId, pending.body.requestId);
  assert.deepEqual(user.devices.map((device) => device.status), ["revoked", "active"]);
  assert.equal(user.sessionVersion, 2);
  assert.equal((await authenticatedRequest(app, "get", "/api/auth/access", oldLogin.body.sessionToken, oldPair)).status, 401);
  assert.equal(verifyOffline(oldLogin.body.offlineToken, now()).deviceKey, user.devices[0].fingerprint);
  advance(7 * 86400000);
  assert.throws(() => verifyOffline(oldLogin.body.offlineToken, now()), { name: "TokenExpiredError" });
  const nextLogin = await login(app, newPair);
  assert.equal(nextLogin.status, 200);
  assert.equal(verifyOffline(nextLogin.body.offlineToken, now()).deviceKey, user.devices[1].fingerprint);
  const reinstall = await login(app, oldPair);
  assert.equal(reinstall.status, 202);
  assert.match(reinstall.body.requestId, /^[a-f\d-]{36}$/i);
  assert.equal((await authenticatedRequest(app, "post", "/api/auth/renew", oldLogin.body.sessionToken, oldPair)).status, 401);
});

test("subscription checks, offline expiry, malformed login and rate limiting remain enforced", async () => {
  const { app, user, advance, now } = fixture();
  const loggedInPair = devicePair();
  const loggedIn = await login(app, loggedInPair);
  user.subscription.status = "inactive";
  assert.equal((await login(app)).status, 403);
  assert.equal((await authenticatedRequest(app, "post", "/api/auth/renew", loggedIn.body.sessionToken, loggedInPair)).status, 403);
  user.subscription.status = "active";
  user.subscription.endsAt = new Date((now() + 3600) * 1000);
  const renewed = await authenticatedRequest(app, "post", "/api/auth/renew", loggedIn.body.sessionToken, loggedInPair);
  assert.equal(verifyOffline(renewed.body.offlineToken, now()).exp, now() + 3600);
  advance(3600000);
  assert.equal((await authenticatedRequest(app, "post", "/api/auth/renew", loggedIn.body.sessionToken, loggedInPair)).status, 403);
  for (const body of [{ email: "usuario", password }, { username: "  ", password }, { username: "usuario", password }]) {
    assert.equal((await request(app).post("/api/auth/login").send(body)).status, 400);
  }
  const limited = fixture(1);
  assert.equal((await login(limited.app)).status, 200);
  assert.equal((await login(limited.app)).status, 429);
});

test("bad credentials do not issue tokens and malformed JSON is not cached", async () => {
  const { app } = fixture();
  const invalid = await login(app, devicePair(), { password: "wrong" });
  assert.equal(invalid.status, 401);
  assert.deepEqual(invalid.body, { error: "invalid_credentials" });
  const malformed = await request(app).post("/api/auth/login").set("Content-Type", "application/json").send("{");
  assert.equal(malformed.status, 400);
  assert.equal(malformed.headers["cache-control"], "no-store");
});

test("admin API authenticates operators, manages access and invalidates sessions", async () => {
  const adminApiKey = "a-long-admin-api-key-for-tests-at-least-32-bytes";
  const requestId = crypto.randomUUID();
  const rejectedRequestId = crypto.randomUUID();
  let createdUser;
  const adminUser = {
    _id: "507f1f77bcf86cd799439011",
    username: "cliente",
    name: "Cliente Demo",
    sessionVersion: 4,
    createdAt: new Date(baseTime),
    updatedAt: new Date(baseTime),
    subscription: { status: "active", endsAt: new Date(baseTime + 30 * 86400000) },
    devices: [
      { fingerprint: "a".repeat(64), publicKey: "private-device-key", status: "active", requestId: crypto.randomUUID(), createdAt: new Date(baseTime), updatedAt: new Date(baseTime) },
      { fingerprint: "b".repeat(64), publicKey: "pending-device-key", status: "pending", requestId, createdAt: new Date(baseTime), updatedAt: new Date(baseTime) },
      { fingerprint: "c".repeat(64), publicKey: "another-pending-key", status: "pending", requestId: rejectedRequestId, createdAt: new Date(baseTime), updatedAt: new Date(baseTime) },
    ],
  };
  const User = {
    create: async (document) => {
      createdUser = { ...document, _id: "507f1f77bcf86cd799439012", createdAt: new Date(baseTime), updatedAt: new Date(baseTime) };
      return createdUser;
    },
    find: () => ({
      select() { return this; },
      sort() { return this; },
      limit() { return this; },
      then(resolve, reject) { return Promise.resolve([adminUser]).then(resolve, reject); },
    }),
    findOneAndUpdate: async (filter, update) => {
      if (filter._id !== adminUser._id && filter.username !== adminUser.username) return null;
      if (filter.devices && !adminUser.devices.some((device) => device.requestId === filter.devices.$elemMatch.requestId && device.status === "pending")) return null;
      if (update.$set?.subscription) adminUser.subscription = update.$set.subscription;
      if (update.$set?.["devices.$[pending].status"]) {
        const activeDevices = adminUser.devices.filter((device) => device.status === "active");
        const target = adminUser.devices.find((device) => device.requestId === filter.devices.$elemMatch.requestId && device.status === "pending");
        target.status = update.$set["devices.$[pending].status"];
        target.updatedAt = update.$set["devices.$[pending].updatedAt"];
        if (target.status === "active") {
          activeDevices.forEach((device) => {
            device.status = "revoked";
            device.updatedAt = update.$set["devices.$[active].updatedAt"];
          });
        }
      }
      if (update.$inc?.sessionVersion) adminUser.sessionVersion += update.$inc.sessionVersion;
      return adminUser;
    },
  };
  const app = createApp({ User, config: { ...config, adminApiKey } });
  const admin = request(app).get("/api/admin/users").set("X-Admin-Key", adminApiKey);

  assert.equal((await request(app).get("/api/admin/users")).status, 401);
  const invalidCreate = await request(app).post("/api/admin/users").set("X-Admin-Key", adminApiKey).send({
    username: "nuevo", name: "Cliente Nuevo", password: "corta", status: "active",
    endsAt: "2027-01-01T00:00:00.000Z", paidAt: "2026-11-24T00:00:00.000Z",
  });
  assert.equal(invalidCreate.status, 400);
  const created = await request(app).post("/api/admin/users").set("X-Admin-Key", adminApiKey).send({
    username: " NUEVO ", name: "Cliente Nuevo", password: "una-clave-segura-123", status: "active",
    endsAt: "2027-01-01T00:00:00.000Z", paidAt: "2026-11-24T00:00:00.000Z",
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.user.username, "nuevo");
  assert.equal(created.body.user.subscription.paidAt, "2026-11-24T00:00:00.000Z");
  assert.notEqual(createdUser.passwordHash, "una-clave-segura-123");

  const listed = await admin;
  assert.equal(listed.status, 200);
  assert.equal(listed.headers["cache-control"], "no-store");
  assert.equal(listed.body.users[0].devices[0].publicKey, undefined);
  assert.equal(listed.body.users[0].sessionVersion, 4);
  assert.equal((await request(app).get("/api/admin/device-requests").set("X-Admin-Key", adminApiKey)).body.requests.length, 2);

  const inactive = await request(app).patch(`/api/admin/users/${adminUser._id}/access`).set("X-Admin-Key", adminApiKey).send({
    status: "inactive",
    endsAt: "2027-01-01T00:00:00.000Z",
    paidAt: "2026-11-24T00:00:00.000Z",
  });
  assert.equal(inactive.status, 200);
  assert.equal(inactive.body.user.subscription.status, "inactive");
  assert.equal(adminUser.sessionVersion, 5);

  const approved = await request(app).post(`/api/admin/device-requests/${requestId}/approve`).set("X-Admin-Key", adminApiKey);
  assert.equal(approved.status, 200);
  assert.equal(adminUser.devices[1].status, "active");
  assert.equal(adminUser.devices[0].status, "revoked");
  assert.equal(adminUser.sessionVersion, 6);

  const rejected = await request(app).post(`/api/admin/device-requests/${rejectedRequestId}/reject`).set("X-Admin-Key", adminApiKey);
  assert.equal(rejected.status, 200);
  assert.equal(adminUser.devices[2].status, "revoked");
  const revoked = await request(app).post(`/api/admin/users/${adminUser._id}/revoke-sessions`).set("X-Admin-Key", adminApiKey);
  assert.equal(revoked.status, 200);
  assert.equal(adminUser.sessionVersion, 7);
});