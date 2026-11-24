const fs = require("node:fs");
const crypto = require("node:crypto");
require("dotenv").config({ quiet: true });

try {
  if (!process.env.OFFLINE_PUBLIC_KEY_PATH) throw new Error("OFFLINE_PUBLIC_KEY_PATH no está definida");
  const key = crypto.createPublicKey(fs.readFileSync(process.env.OFFLINE_PUBLIC_KEY_PATH));
  if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error("Se requiere una clave pública RSA de al menos 2048 bits");
  process.stdout.write(key.export({ type: "spki", format: "pem" }));
} catch (error) {
  console.error("No se pudo exportar la clave pública:", error.message);
  process.exitCode = 1;
}