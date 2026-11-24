const { normalizeUsername } = require("./username");

async function listPendingRequests(User) {
  const users = await User.find({ "devices.status": "pending" }).select("username devices");
  return users.flatMap((user) => (user.devices || [])
    .filter((device) => device.status === "pending")
    .map((device) => ({
      username: user.username,
      requestId: device.requestId,
      fingerprint: device.fingerprint,
      createdAt: device.createdAt,
    })));
}

async function approveDeviceRequest(User, usernameValue, requestId, now = new Date()) {
  const username = normalizeUsername(usernameValue);
  if (!username || typeof requestId !== "string" || !/^[a-f\d-]{36}$/i.test(requestId)) throw new Error("Usuario o request-id inválido");
  const user = await User.findOneAndUpdate({
    username,
    devices: { $elemMatch: { requestId, status: "pending" } },
  }, {
    $set: {
      "devices.$[pending].status": "active",
      "devices.$[pending].updatedAt": now,
      "devices.$[active].status": "revoked",
      "devices.$[active].updatedAt": now,
    },
    $inc: { sessionVersion: 1 },
  }, {
    new: true,
    arrayFilters: [
      { "pending.requestId": requestId, "pending.status": "pending" },
      { "active.status": "active" },
    ],
  });
  if (!user) throw new Error("No existe una solicitud pending para ese usuario y request-id");
  return { username: user.username, requestId, fingerprint: user.devices.find((device) => device.requestId === requestId).fingerprint };
}

async function rejectDeviceRequest(User, usernameValue, requestId, now = new Date()) {
  const username = normalizeUsername(usernameValue);
  if (!username || typeof requestId !== "string" || !/^[a-f\d-]{36}$/i.test(requestId)) throw new Error("Usuario o request-id inválido");
  const user = await User.findOneAndUpdate({
    username,
    devices: { $elemMatch: { requestId, status: "pending" } },
  }, {
    $set: {
      "devices.$[pending].status": "revoked",
      "devices.$[pending].updatedAt": now,
    },
  }, {
    new: true,
    arrayFilters: [{ "pending.requestId": requestId, "pending.status": "pending" }],
  });
  if (!user) throw new Error("No existe una solicitud pending para ese usuario y request-id");
  return { username: user.username, requestId };
}

module.exports = { listPendingRequests, approveDeviceRequest, rejectDeviceRequest };