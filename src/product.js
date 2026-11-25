const mongoose = require("mongoose");

const productSchema = new mongoose.Schema({
  number: { type: String, required: true, trim: true, maxlength: 40, unique: true },
  name: { type: String, required: true, trim: true, maxlength: 150 },
  priceCents: { type: Number, required: true, min: 0, validate: Number.isSafeInteger },
}, { timestamps: true });

module.exports = mongoose.model("Product", productSchema);