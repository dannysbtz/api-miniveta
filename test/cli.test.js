const test = require("node:test");
const assert = require("node:assert/strict");
const { PassThrough } = require("node:stream");
const { readPassword } = require("../scripts/manage-user");
const { normalizeUsername } = require("../src/username");
const User = require("../src/user");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

test("interactive password input is hidden and restores terminal mode", async () => {
  const input = new PassThrough();
  input.isTTY = true;
  const modes = [];
  input.setRawMode = (mode) => modes.push(mode);
  let output = "";
  const pending = readPassword(input, { write: (text) => { output += text; } });
  input.write("test-password-123\r");
  assert.equal(await pending, "test-password-123");
  assert.deepEqual(modes, [true, false]);
  assert.equal(input.listenerCount("data"), 0);
  assert.ok(!output.includes("test-password-123"));
  input.destroy();
});

test("username is normalized consistently and has a unique index", async () => {
  assert.equal(normalizeUsername("  ＵＳＵＡＲＩＯ  "), "usuario");
  assert.equal(normalizeUsername("usuario sin correo"), "usuario sin correo");
  for (const value of [" ", "x".repeat(255), "bad\u0000name", null]) assert.equal(normalizeUsername(value), null);
  const user = new User({ username: "  USUARIO  ", name: "Ana", passwordHash: "hash", subscription: { status: "active", endsAt: new Date() } });
  await user.validate();
  assert.equal(user.username, "usuario");
  assert.ok(User.schema.indexes().some(([fields, options]) => fields.username === 1 && options.unique));
});

test("CLI accepts a generic username and rejects invalid names before connecting", () => {
  const run = (username) => spawnSync(process.execPath, ["scripts/manage-user.js", "--username", username, "--name", "Ana", "--status", "active", "--ends-at", "2099-01-01T00:00:00Z"], { cwd: path.join(__dirname, ".."), env: { ...process.env, MONGODB_URI: "" }, encoding: "utf8" });
  assert.match(run(" Mi Usuario ").stderr, /MONGODB_URI no está definida/);
  assert.match(run("   ").stderr, /Uso:/);
});