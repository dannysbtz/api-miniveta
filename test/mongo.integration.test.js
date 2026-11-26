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
const SubscriptionPayment = require("../src/subscription-payment");
const ContactRequest = require("../src/contact-request");

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
    const adminApiKey = "a-long-admin-api-key-for-tests-at-least-32-bytes";
    const app = createApp({ User, config: { ...keys, adminApiKey, sessionSecret: "test-session-secret-with-at-least-32-bytes" } });
    const submitted = await request(app).post("/api/contact").type("form").send({ nombre: "Ana", correo: "ana@example.com", descripcion: "Una consulta", consentimiento: "on" });
    assert.equal(submitted.status, 201);
    const contact = await ContactRequest.findOne({ correo: "ana@example.com" });
    assert.equal(contact.nombre, "Ana");
    assert.equal(contact.consentimiento, true);
    const contacts = await request(app).get("/api/admin/contact-requests").set("X-Admin-Key", adminApiKey);
    assert.equal(contacts.body.requests[0]._id, String(contact._id));
    assert.equal((await request(app).delete(`/api/admin/contact-requests/${contact._id}`).set("X-Admin-Key", adminApiKey)).status, 200);
    assert.equal(await ContactRequest.countDocuments(), 0);
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
    await User.updateOne({ username: "usuario" }, { $set: { "subscription.priceCents": 32000, "subscription.paidAt": new Date("2026-01-01T00:00:00Z") } });
    const updated = runCli("inactive");
    assert.equal(updated.status, 0, updated.stderr);
    const response = await authenticatedRequest("get", "/api/auth/access", newLogin.body.sessionToken, newPair);
    assert.equal(response.status, 401);
    assert.equal((await loginWithDevice(newPair)).status, 403);
    assert.equal(await User.countDocuments({ username: "usuario" }), 1);
    const finalUser = await User.findOne({ username: "usuario" });
    assert.equal(finalUser.subscription.priceCents, 32000);
    assert.equal(finalUser.subscription.paidAt.toISOString(), "2026-01-01T00:00:00.000Z");
  } finally {
    await mongoose.disconnect();
    if (server.exitCode === null && !spawnError) {
      server.kill("SIGTERM");
      await new Promise((resolve) => server.once("exit", resolve));
    }
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("Mongo transaction commits and retries payments without losing historical revenue", { skip: process.env.RUN_MONGO_INTEGRATION !== "1", timeout: 60000 }, async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "miniventa-payments-test-"));
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  const uri = `mongodb://127.0.0.1:${port}/miniventa-payments-test?directConnection=true&serverSelectionTimeoutMS=500`;
  const server = spawn("mongod", ["--dbpath", directory, "--port", String(port), "--bind_ip", "127.0.0.1", "--replSet", "test-rs", "--quiet"], { stdio: "ignore" });
  let spawnError;
  server.on("error", (error) => { spawnError = error; });
  try {
    let connected = false;
    for (let attempt = 0; attempt < 30 && !connected; attempt++) {
      if (spawnError) throw spawnError;
      try { await mongoose.connect(uri, { autoCreate: false, autoIndex: false }); connected = true; }
      catch { await new Promise((resolve) => setTimeout(resolve, 200)); }
    }
    assert.ok(connected, "MongoDB de prueba no arrancó");
    await mongoose.connection.db.admin().command({ replSetInitiate: { _id: "test-rs", members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    let writable = false;
    for (let attempt = 0; attempt < 50 && !writable; attempt++) {
      try { writable = (await mongoose.connection.db.admin().command({ hello: 1 })).isWritablePrimary; }
      catch { writable = false; }
      if (!writable) await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.ok(writable, "El replica set no eligió un primario");
    await User.createCollection();
    await SubscriptionPayment.createCollection();
    await User.createIndexes();
    await SubscriptionPayment.createIndexes();
    const user = await User.create({ username: "cliente-pago", name: "Cliente", passwordHash: "hash", subscription: { status: "inactive", endsAt: new Date("2026-01-01T00:00:00Z"), priceCents: 32000 } });
    const adminApiKey = "a-long-admin-api-key-for-tests-at-least-32-bytes";
    const config = { adminApiKey };
    const body = { requestId: crypto.randomUUID(), amountCents: 32000, paidAt: "2026-01-01T00:00:00.000Z", endsAt: "2099-01-01T00:00:00.000Z" };
    const failingPayment = { findOne: SubscriptionPayment.findOne.bind(SubscriptionPayment), create: async () => { throw new Error("simulated payment failure"); } };
    const failed = await request(createApp({ User, Payment: failingPayment, config })).post(`/api/admin/users/${user.id}/confirm-payment`).set("X-Admin-Key", adminApiKey).send(body);
    assert.equal(failed.status, 500);
    assert.equal((await User.findById(user.id)).subscription.status, "inactive");
    assert.equal(await SubscriptionPayment.countDocuments(), 0);
    const app = createApp({ User, config });
    assert.equal((await request(app).post(`/api/admin/users/${user.id}/confirm-payment`).set("X-Admin-Key", adminApiKey).send(body)).status, 200);
    assert.equal((await request(app).post(`/api/admin/users/${user.id}/confirm-payment`).set("X-Admin-Key", adminApiKey).send(body)).status, 200);
    const earlier = { ...body, requestId: crypto.randomUUID(), endsAt: "2098-01-01T00:00:00.000Z" };
    assert.equal((await request(app).post(`/api/admin/users/${user.id}/confirm-payment`).set("X-Admin-Key", adminApiKey).send(earlier)).status, 409);
    assert.equal(await SubscriptionPayment.countDocuments(), 1);
    assert.equal((await User.findById(user.id)).sessionVersion, 1);
    assert.equal((await request(app).delete(`/api/admin/users/${user.id}`).set("X-Admin-Key", adminApiKey)).status, 200);
    const income = await request(app).get("/api/admin/payments").set("X-Admin-Key", adminApiKey);
    assert.equal(income.body.totalCents, 32000);
    assert.equal(income.body.count, 1);
  } finally {
    await mongoose.disconnect();
    if (server.exitCode === null && !spawnError) {
      server.kill("SIGTERM");
      await new Promise((resolve) => server.once("exit", resolve));
    }
    await fs.rm(directory, { recursive: true, force: true });
  }
});