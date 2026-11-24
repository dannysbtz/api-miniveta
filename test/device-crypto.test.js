const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { parseDevicePublicKey, verifyDeviceProof } = require("../src/device-crypto");

test("P-256 SPKI fingerprint is canonical and ECDSA proof signs the exact challenge", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = pair.publicKey.export({ type: "spki", format: "pem" });
  const parsed = parseDevicePublicKey(spki);
  const challenge = "signed-server-challenge.token";
  const proof = crypto.sign("sha256", Buffer.from(challenge), pair.privateKey).toString("base64url");

  assert.equal(parsed.fingerprint, crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex"));
  assert.equal(parsed.publicKey, spki);
  assert.equal(verifyDeviceProof(parsed.key, challenge, proof), true);
  assert.equal(verifyDeviceProof(parsed.key, `${challenge}.`, proof), false);
  assert.equal(verifyDeviceProof(parsed.key, challenge, "not-a-signature"), false);
  assert.throws(() => parseDevicePublicKey(crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" })), /invalid_device_key/);
});