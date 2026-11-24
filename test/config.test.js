const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { loadConfig } = require("../src/config");

test("configuration validates keys and public-key export contains only PEM", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "miniventa-key-test-"));
  try {
    const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privatePath = path.join(directory, "private.pem");
    const publicPath = path.join(directory, "public.pem");
    await fs.writeFile(privatePath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    await fs.writeFile(publicPath, keys.publicKey.export({ type: "spki", format: "pem" }));
    const env = { SESSION_SECRET: "a-secret-with-at-least-thirty-two-bytes", OFFLINE_PRIVATE_KEY_PATH: privatePath, OFFLINE_PUBLIC_KEY_PATH: publicPath };
    assert.equal(loadConfig(env).privateKey.asymmetricKeyType, "rsa");
    assert.throws(() => loadConfig({ ...env, SESSION_SECRET: "short" }));
    const exported = spawnSync(process.execPath, ["scripts/export-public-key.js"], { cwd: path.join(__dirname, ".."), env: { ...process.env, ...env }, encoding: "utf8" });
    assert.equal(exported.status, 0, exported.stderr);
    assert.match(exported.stdout, /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/);
    assert.equal(crypto.createPublicKey(exported.stdout).asymmetricKeyType, "rsa");
    const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    await fs.writeFile(publicPath, other.publicKey.export({ type: "spki", format: "pem" }));
    assert.throws(() => loadConfig(env), /no forman un par/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});