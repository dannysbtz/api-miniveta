const fs = require("node:fs");
const crypto = require("node:crypto");

const ISSUER = "miniventa-api";
const SESSION_AUDIENCE = "miniventa-session";
const OFFLINE_AUDIENCE = "miniventa-offline";
const DEVICE_CHALLENGE_AUDIENCE = "miniventa-device-challenge";

function loadConfig(env = process.env) {
  if (!env.SESSION_SECRET || Buffer.byteLength(env.SESSION_SECRET) < 32) {
    throw new Error("SESSION_SECRET debe tener al menos 32 bytes");
  }
  if (env.ADMIN_API_KEY && Buffer.byteLength(env.ADMIN_API_KEY) < 32) {
    throw new Error("ADMIN_API_KEY debe tener al menos 32 bytes");
  }
  if (!env.OFFLINE_PRIVATE_KEY_PATH || !env.OFFLINE_PUBLIC_KEY_PATH) {
    throw new Error("Configure OFFLINE_PRIVATE_KEY_PATH y OFFLINE_PUBLIC_KEY_PATH");
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(env.OFFLINE_PRIVATE_KEY_PATH));
  const publicKey = crypto.createPublicKey(fs.readFileSync(env.OFFLINE_PUBLIC_KEY_PATH));
  if (privateKey.asymmetricKeyType !== "rsa" || publicKey.asymmetricKeyType !== "rsa" ||
      privateKey.asymmetricKeyDetails.modulusLength < 2048 || publicKey.asymmetricKeyDetails.modulusLength < 2048) {
    throw new Error("Las claves offline deben ser RSA de al menos 2048 bits");
  }
  const derived = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const supplied = publicKey.export({ type: "spki", format: "der" });
  if (!derived.equals(supplied)) throw new Error("Las claves offline no forman un par");
  return { sessionSecret: env.SESSION_SECRET, privateKey, publicKey, adminApiKey: env.ADMIN_API_KEY };
}

module.exports = { loadConfig, ISSUER, SESSION_AUDIENCE, OFFLINE_AUDIENCE, DEVICE_CHALLENGE_AUDIENCE };