const mongoose = require("mongoose");
require("dotenv").config({ quiet: true });
const User = require("../src/user");
const { listPendingRequests } = require("../src/device-requests");

async function main() {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI no está definida");
  await mongoose.connect(process.env.MONGODB_URI);
  await User.init();
  const requests = await listPendingRequests(User);
  process.stdout.write(`${JSON.stringify(requests, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error("No se pudieron listar las solicitudes:", error.message);
    process.exitCode = 1;
  }).finally(() => mongoose.disconnect());
}

module.exports = { main };