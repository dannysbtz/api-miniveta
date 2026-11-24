const mongoose = require("mongoose");

const deviceChallengeSchema = new mongoose.Schema({
  jti: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
}, { timestamps: true });

module.exports = mongoose.models.DeviceChallenge || mongoose.model("DeviceChallenge", deviceChallengeSchema);