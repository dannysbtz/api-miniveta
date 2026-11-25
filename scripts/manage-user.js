const { parseArgs } = require("node:util");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
require("dotenv").config({ quiet: true });
const User = require("../src/user");
const { normalizeUsername } = require("../src/username");

async function readPassword(inputStream = process.stdin, outputStream = process.stderr) {
  if (!inputStream.isTTY) {
    let input = "";
    for await (const chunk of inputStream) {
      input += chunk.toString();
      if (Buffer.byteLength(input) > 1024) throw new Error("Entrada de contraseña demasiado larga");
    }
    return input.replace(/\r?\n$/, "");
  }
  outputStream.write("Contraseña (no se muestra): ");
  inputStream.setRawMode(true);
  inputStream.resume();
  return new Promise((resolve, reject) => {
    let input = "";
    function onData(chunk) {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") {
          cleanup();
          reject(new Error("Operación cancelada"));
          return;
        }
        if (character === "\r" || character === "\n") {
          cleanup();
          resolve(input);
          return;
        }
        if (character === "\u007f" || character === "\b") input = Array.from(input).slice(0, -1).join("");
        else input += character;
        if (Buffer.byteLength(input) > 1024) {
          cleanup();
          reject(new Error("Entrada de contraseña demasiado larga"));
          return;
        }
      }
    }
    function cleanup() {
      inputStream.removeListener("data", onData);
      inputStream.setRawMode(false);
      inputStream.pause();
      outputStream.write("\n");
    }
    inputStream.on("data", onData);
  });
}

async function main() {
  const { values } = parseArgs({ options: {
    username: { type: "string" }, name: { type: "string" },
    status: { type: "string" }, "ends-at": { type: "string" },
  }, strict: true });
  const username = normalizeUsername(values.username);
  const name = values.name?.trim();
  if (!username ||
      !name || name.length > 100 || !["active", "inactive"].includes(values.status) ||
      !values["ends-at"] || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(values["ends-at"])) {
    throw new Error("Uso: npm run user:manage -- --username usuario --name nombre --status active|inactive --ends-at fecha-ISO-con-zona");
  }
  const endsAt = new Date(values["ends-at"]);
  if (Number.isNaN(endsAt.getTime()) || (values.status === "active" && endsAt <= new Date())) {
    throw new Error("Fecha inválida o suscripción activa ya vencida");
  }
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI no está definida");
  const password = await readPassword();
  if (Buffer.byteLength(password) < 12 || Buffer.byteLength(password) > 72 || /[\r\n]/.test(password)) {
    throw new Error("La contraseña debe tener entre 12 y 72 bytes y no contener saltos de línea");
  }
  const passwordHash = await bcrypt.hash(password, 12);
  await mongoose.connect(process.env.MONGODB_URI);
  await User.init();
  const user = await User.findOneAndUpdate({ username }, {
    $set: { username, name, passwordHash, "subscription.status": values.status, "subscription.endsAt": endsAt },
    $inc: { sessionVersion: 1 },
  }, { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: false });
  console.log(`Usuario ${user._id} guardado; sesiones anteriores invalidadas.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error("No se pudo guardar el usuario:", error.message);
    process.exitCode = 1;
  }).finally(() => mongoose.disconnect());
}

module.exports = { readPassword };