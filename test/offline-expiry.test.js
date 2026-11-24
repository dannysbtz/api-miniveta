const test = require("node:test");
const assert = require("node:assert/strict");
const { OFFLINE_SECONDS, offlineExpiration } = require("../src/offline-expiry");

test("offline expiration is capped at seven days or subscription end", () => {
  const now = 1700000000;
  assert.equal(offlineExpiration(now, new Date((now + 30 * 86400) * 1000)), now + OFFLINE_SECONDS);
  assert.equal(offlineExpiration(now, new Date((now + 3600) * 1000)), now + 3600);
});