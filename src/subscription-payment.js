const mongoose = require("mongoose");

const subscriptionPaymentSchema = new mongoose.Schema({
  requestId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  username: { type: String, required: true },
  name: { type: String, required: true },
  amountCents: { type: Number, required: true, min: 1 },
  paidAt: { type: Date, required: true },
  endsAt: { type: Date, required: true },
  recordedAt: { type: Date, required: true },
}, { versionKey: false });

subscriptionPaymentSchema.index({ paidAt: -1 });

module.exports = mongoose.model("SubscriptionPayment", subscriptionPaymentSchema);
