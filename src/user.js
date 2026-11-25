const mongoose = require("mongoose");
const { normalizeUsername } = require("./username");

const deviceSchema = new mongoose.Schema({
  fingerprint: { type: String, required: true, match: /^[a-f\d]{64}$/ },
  publicKey: { type: String, required: true, select: false },
  status: { type: String, enum: ["pending", "active", "revoked"], required: true },
  createdAt: { type: Date, required: true },
  updatedAt: { type: Date, required: true },
  requestId: { type: String, required: true },
}, { _id: false });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, set: normalizeUsername },
  name: { type: String, required: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  sessionVersion: { type: Number, required: true, default: 0 },
  devices: { type: [deviceSchema], default: [] },
  subscription: {
    status: { type: String, enum: ["active", "inactive"], required: true },
    endsAt: { type: Date, required: true },
    paidAt: { type: Date, default: null },
    priceCents: { type: Number, required: true, min: 0, default: 0 },
  },
}, { timestamps: true });

userSchema.index({ "devices.status": 1, "devices.fingerprint": 1 });
userSchema.index({ "devices.status": 1, "devices.requestId": 1 });

module.exports = mongoose.model("User", userSchema);