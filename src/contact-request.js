const mongoose = require("mongoose");

const contactRequestSchema = new mongoose.Schema({
  nombre: { type: String, required: true, maxlength: 100 },
  empresa: { type: String, maxlength: 150 },
  correo: { type: String, required: true, maxlength: 254 },
  telefono: { type: String, maxlength: 40 },
  tipo: { type: String, maxlength: 40 },
  descripcion: { type: String, required: true, maxlength: 4000 },
  consentimiento: { type: Boolean, required: true },
}, { timestamps: true });

module.exports = mongoose.model("ContactRequest", contactRequestSchema);