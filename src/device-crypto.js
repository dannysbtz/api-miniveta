const crypto = require("node:crypto");

function parseDevicePublicKey(value) {
  if (typeof value !== "string" || value.length > 2048) throw new Error("invalid_device_key");
  let key;
  try { key = crypto.createPublicKey(value); }
  catch { throw new Error("invalid_device_key"); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails.namedCurve !== "prime256v1") {
    throw new Error("invalid_device_key");
  }
  const der = key.export({ type: "spki", format: "der" });
  return {
    key,
    publicKey: key.export({ type: "spki", format: "pem" }),
    fingerprint: crypto.createHash("sha256").update(der).digest("hex"),
  };
}

function verifyDeviceProof(publicKey, challenge, proof) {
  if (typeof challenge !== "string" || typeof proof !== "string" || proof.length > 512 || !/^[A-Za-z0-9_-]+$/.test(proof)) return false;
  let signature;
  try { signature = Buffer.from(proof, "base64url"); }
  catch { return false; }
  return crypto.verify("sha256", Buffer.from(challenge, "utf8"), publicKey, signature);
}

module.exports = { parseDevicePublicKey, verifyDeviceProof };