function normalizeUsername(value) {
  if (typeof value !== "string") return null;
  const username = value.normalize("NFKC").trim().toLowerCase();
  return username && username.length <= 254 && !/[\u0000-\u001f\u007f]/.test(username) ? username : null;
}

module.exports = { normalizeUsername };