const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const mongoose = require("mongoose");
const request = require("supertest");
const { createApp } = require("../src/app");
const User = require("../src/user");

test("Mongo persists device requests and CLIs approve/revoke devices and invalidate sessions", { skip: process.env.RUN_MONGO_INTEGRATION !== "1", timeout: 60000 }, async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "miniventa-mongo-test-"));
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  const uri = `mongodb://127.0.0.1:${port}/miniventa-test?serverSelectionTimeoutMS=500`;
  const server = spawn("mongod", ["--dbpath", directory, "--port", String(port), "--bind_ip", "127.0.0.1", "--quiet"], { stdio: "ignore" });
  let spawnError;
  server.on("error", (error) => { spawnError = error; });
  try {
    let connected = false;
    for (let attempt = 0; attempt < 30 && !connected; attempt++) {
      if (spawnError) throw spawnError;
      try { await mongoose.connect(uri); connected = true; }
      catch { await new Promise((resolve) => setTimeout(resolve, 200)); }
    }
    assert.ok(connected, "MongoDB de prueba no arrancó");
    const runCli = (status) => spawnSync(process.execPath, ["scripts/manage-user.js", "--username", "  USUARIO  ", "--name", "Ana", "--status", status, "--ends-at", "2099-01-01T00:00:00Z"], {
      cwd: path.join(__dirname, ".."), env: { ...process.env, MONGODB_URI: uri }, input: "test-password-123\n", encoding: "utf8", timeout: 15000,
    });
    const created = runCli("active");
    assert.equal(created.status, 0, created.stderr);
    await assert.rejects(User.create({ username: " USUARIO ", name: "Duplicado", passwordHash: "hash", subscription: { status: "active", endsAt: new Date("2099-01-01T00:00:00Z") } }), { code: 11000 });
    const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const app = createApp({ User, config: { ...keys, sessionSecret: "test-session-secret-with-at-least-32-bytes" } });
    const loginWithDevice = async (pair) => {
      const challenge = (await request(app).post("/api/auth/device-challenge")).body.challenge;
      const devicePublicKey = pair.publicKey.export({ type: "spki", format: "pem" });
      const deviceProof = crypto.sign("sha256", Buffer.from(challenge), pair.privateKey).toString("base64url");
      return request(app).post("/api/auth/login").send({ username: "usuario", password: "test-password-123", devicePublicKey, deviceChallenge: challenge, deviceProof });
    };
    const authenticatedRequest = async (method, endpoint, sessionToken, pair) => {
      const challenge = (await request(app).post("/api/auth/device-challenge")).body.challenge;
      const proof = crypto.sign("sha256", Buffer.from(challenge), pair.privateKey).toString("base64url");
      return request(app)[method](endpoint)
        .set("Authorization", `Bearer ${sessionToken}`)
        .set("X-Device-Challenge", challenge)
        .set("X-Device-Proof", proof);
    };
    const oldPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const loggedIn = await loginWithDevice(oldPair);
    assert.equal(loggedIn.status, 200);
    const newPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const challenge = (await request(app).post("/api/auth/device-challenge")).body.challenge;
    const newPublicKey = newPair.publicKey.export({ type: "spki", format: "pem" });
    const newProof = crypto.sign("sha256", Buffer.from(challenge), newPair.privateKey).toString("base64url");
    const pending = await request(app).post("/api/auth/login").send({ username: "usuario", password: "test-password-123", devicePublicKey: newPublicKey, deviceChallenge: challenge, deviceProof: newProof });
    assert.equal(pending.status, 202);
    const env = { ...process.env, MONGODB_URI: uri };
    const listed = spawnSync(process.execPath, ["scripts/device-requests.js"], { cwd: path.join(__dirname, ".."), env, encoding: "utf8", timeout: 15000 });
    assert.equal(listed.status, 0, listed.stderr);
    const requests = JSON.parse(listed.stdout);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].requestId, pending.body.requestId);
    assert.equal(Object.hasOwn(requests[0], "publicKey"), false);
    const approved = spawnSync(process.execPath, ["scripts/device-approve.js", "--username", "usuario", "--request-id", pending.body.requestId], { cwd: path.join(__dirname, ".."), env, encoding: "utf8", timeout: 15000 });
    assert.equal(approved.status, 0, approved.stderr);
    const persisted = await User.findOne({ username: "usuario" });
    assert.deepEqual(persisted.devices.map((device) => device.status), ["revoked", "active"]);
    assert.equal(persisted.sessionVersion, 2);
    assert.equal((await authenticatedRequest("get", "/api/auth/access", loggedIn.body.sessionToken, oldPair)).status, 401);
    const newLogin = await loginWithDevice(newPair);
    assert.equal(newLogin.status, 200);
    assert.equal((await authenticatedRequest("get", "/api/auth/access", newLogin.body.sessionToken, newPair)).status, 200);
    const updated = runCli("inactive");
    assert.equal(updated.status, 0, updated.stderr);
    const response = await authenticatedRequest("get", "/api/auth/access", newLogin.body.sessionToken, newPair);
    assert.equal(response.status, 401);
    assert.equal((await loginWithDevice(newPair)).status, 403);
    assert.equal(await User.countDocuments({ username: "usuario" }), 1);
  } finally {
    await mongoose.disconnect();
    if (server.exitCode === null && !spawnError) {
      server.kill("SIGTERM");
      await new Promise((resolve) => server.once("exit", resolve));
    }
    await fs.rm(directory, { recursive: true, force: true });
  }
});