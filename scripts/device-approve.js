const { parseArgs } = require("node:util");
const mongoose = require("mongoose");
require("dotenv").config({ quiet: true });
const User = require("../src/user");
const { approveDeviceRequest } = require("../src/device-requests");

async function main() {
  const { values } = parseArgs({ options: { username: { type: "string" }, "request-id": { type: "string" } }, strict: true });
  if (!values.username || !values["request-id"]) throw new Error("Uso: npm run device:approve -- --username usuario --request-id id");
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI no está definida");
  await mongoose.connect(process.env.MONGODB_URI);
  await User.init();
  const approved = await approveDeviceRequest(User, values.username, values["request-id"]);
  console.log(`Dispositivo aprobado para ${approved.username}; el dispositivo anterior fue revocado y las sesiones invalidadas.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error("No se pudo aprobar el dispositivo:", error.message);
    process.exitCode = 1;
  }).finally(() => mongoose.disconnect());
}

module.exports = { main };