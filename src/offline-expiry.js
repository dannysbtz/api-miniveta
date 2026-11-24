const OFFLINE_SECONDS = 7 * 24 * 60 * 60;

function offlineExpiration(nowSeconds, subscriptionEndsAt) {
  return Math.min(nowSeconds + OFFLINE_SECONDS, Math.floor(subscriptionEndsAt.getTime() / 1000));
}

module.exports = { OFFLINE_SECONDS, offlineExpiration };