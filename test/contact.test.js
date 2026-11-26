const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const { createApp } = require("../src/app");

const key = "a-long-admin-api-key-for-tests-at-least-32-bytes";
const input = { nombre: " Ana ", empresa: "Empresa", correo: "ana@example.com", telefono: "", tipo: "otro", descripcion: "Necesito información", consentimiento: "on" };

function fixture(contactLimit = 5) {
  const requests = [];
  const Contact = {
    create: async (data) => { requests.push({ _id: "507f1f77bcf86cd799439011", ...data }); },
    find: () => ({ sort: () => ({ limit: async () => [...requests] }) }),
    findByIdAndDelete: async (id) => {
      const index = requests.findIndex((entry) => entry._id === id);
      return index < 0 ? null : requests.splice(index, 1)[0];
    },
  };
  return { app: createApp({ User: {}, Contact, config: { adminApiKey: key }, contactLimit }), requests };
}

test("formulario se valida, persiste y se consulta y elimina con autorización", async () => {
  const { app, requests } = fixture(20);
  for (const invalid of [{ nombre: " " }, { correo: "incorrecto" }, { descripcion: "" }, { consentimiento: "" }, { tipo: "otro-desconocido" }, { nombre: ["Ana", "Otra"] }, { descripcion: "a".repeat(4001) }]) {
    assert.equal((await request(app).post("/api/contact").type("form").send({ ...input, ...invalid })).status, 400);
  }
  assert.equal(requests.length, 0);
  const result = await request(app).post("/api/contact").type("form").send(input);
  assert.equal(result.status, 201);
  assert.match(result.text, /Solicitud recibida/);
  assert.equal(result.headers["cache-control"], "no-store");
  assert.deepEqual(requests[0], { _id: "507f1f77bcf86cd799439011", ...input, nombre: "Ana", consentimiento: true });
  assert.equal((await request(app).get("/api/admin/contact-requests")).status, 401);
  const listed = await request(app).get("/api/admin/contact-requests").set("X-Admin-Key", key);
  assert.deepEqual(listed.body.requests, requests);
  assert.equal((await request(app).delete(`/api/admin/contact-requests/${requests[0]._id}`)).status, 401);
  assert.equal((await request(app).delete(`/api/admin/contact-requests/${requests[0]._id}`).set("X-Admin-Key", key)).status, 200);
  assert.equal(requests.length, 0);
});

test("límite de solicitudes y fallo de persistencia no confirman el envío", async () => {
  const { app } = fixture(1);
  assert.equal((await request(app).post("/api/contact").type("form").send(input)).status, 201);
  const limited = await request(app).post("/api/contact").type("form").send(input);
  assert.equal(limited.status, 429);
  assert.equal(limited.headers["cache-control"], "no-store");
  const failingApp = createApp({ User: {}, Contact: { create: async () => { throw new Error("database unavailable"); } }, config: {} });
  assert.equal((await request(failingApp).post("/api/contact").type("form").send(input)).status, 500);
});

test("acepta texto en español dentro del máximo de caracteres", async () => {
  const { app, requests } = fixture();
  const description = "á".repeat(4000);
  assert.equal((await request(app).post("/api/contact").type("form").send({ ...input, descripcion: description })).status, 201);
  assert.equal(requests[0].descripcion, description);
});