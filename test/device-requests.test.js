const test = require("node:test");
const assert = require("node:assert/strict");
const { listPendingRequests, approveDeviceRequest } = require("../src/device-requests");

function fixture() {
  const users = [{
    username: "usuario", sessionVersion: 4, passwordHash: "must-not-leak", devices: [
      { fingerprint: "a".repeat(64), publicKey: "PRIVATE-DEVICE-METADATA", requestId: "11111111-1111-4111-8111-111111111111", status: "active", createdAt: new Date(0), updatedAt: new Date(0) },
      { fingerprint: "b".repeat(64), publicKey: "ANOTHER-KEY", requestId: "22222222-2222-4222-8222-222222222222", status: "pending", createdAt: new Date(1), updatedAt: new Date(1) },
    ],
  }];
  const User = {
    find: () => ({ select: async () => users.filter((user) => user.devices.some((device) => device.status === "pending")) }),
    findOneAndUpdate: async (filter, update) => {
      const user = users.find((item) => item.username === filter.username && item.devices.some((device) => device.requestId === filter.devices.$elemMatch.requestId && device.status === "pending"));
      if (!user) return null;
      const requestId = filter.devices.$elemMatch.requestId;
      for (const device of user.devices) {
        if (device.requestId === requestId && device.status === "pending") Object.assign(device, { status: "active", updatedAt: update.$set["devices.$[pending].updatedAt"] });
        else if (device.status === "active") Object.assign(device, { status: "revoked", updatedAt: update.$set["devices.$[active].updatedAt"] });
      }
      user.sessionVersion += update.$inc.sessionVersion;
      return user;
    },
  };
  return { User, users };
}

test("pending request listing exposes identifiers only, never key or account secrets", async () => {
  const { User } = fixture();
  const result = await listPendingRequests(User);
  assert.deepEqual(result, [{ username: "usuario", requestId: "22222222-2222-4222-8222-222222222222", fingerprint: "b".repeat(64), createdAt: new Date(1) }]);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE-DEVICE-METADATA|ANOTHER-KEY|must-not-leak|password/i);
});

test("approval activates only the requested pending device and increments session version", async () => {
  const { User, users } = fixture();
  const approved = await approveDeviceRequest(User, " USUARIO ", "22222222-2222-4222-8222-222222222222", new Date(2));
  assert.equal(approved.fingerprint, "b".repeat(64));
  assert.deepEqual(users[0].devices.map((device) => device.status), ["revoked", "active"]);
  assert.equal(users[0].sessionVersion, 5);
  await assert.rejects(approveDeviceRequest(User, "usuario", "22222222-2222-4222-8222-222222222222"), /No existe una solicitud pending/);
});