const dotenv = require("dotenv");
const mongoose = require("mongoose");
const { createApp } = require("./app");
const { loadConfig } = require("./config");
const User = require("./user");

dotenv.config();

async function startServer() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI no esta definida en el archivo .env");
    }
    const config = loadConfig();
    await mongoose.connect(process.env.MONGODB_URI);
    await User.init();
    console.log("MongoDB conectada correctamente");

    const app = createApp({ User, config });
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Servidor backend escuchando en http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Error al iniciar el servidor:", error.message);
    process.exit(1);
  }
}

startServer();
