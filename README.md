# API Miniventa

Backend Node.js 20+, Express y MongoDB. Las cuentas y suscripciones se gestionan manualmente: no hay registro público, credenciales predeterminadas ni integración de pagos.

## Configuración

1. Instala dependencias con `npm install` y configura `.env`.
2. Configura `MONGODB_URI` con acceso restringido y `SESSION_SECRET` con un valor aleatorio y exclusivo de al menos 32 bytes. Por ejemplo, genera uno con `openssl rand -hex 32` y colócalo en `.env` sin compartirlo.
3. Genera un par RSA en una carpeta local protegida, fuera de cualquier distribución de la aplicación:

   ```sh
   mkdir -p secrets
   chmod 700 secrets
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/offline-private.pem
   chmod 600 secrets/offline-private.pem
   openssl pkey -in secrets/offline-private.pem -pubout -out secrets/offline-public.pem
   ```

4. Ajusta `OFFLINE_PRIVATE_KEY_PATH` y `OFFLINE_PUBLIC_KEY_PATH` en `.env`. Se interpretan respecto al directorio desde el que se inicia Node. La API comprueba que las claves formen un par RSA de al menos 2048 bits y falla al arrancar si falta la configuración. `.env`, `secrets/` y los archivos `*.pem` y `*.key` están excluidos por `.gitignore`; comprueba también tus propias rutas y nunca subas claves privadas o secretos a control de versiones.
5. Inicia con `npm start` o `npm run dev`. MongoDB debe estar disponible. La API crea un índice único por nombre de usuario normalizado al arrancar.

Para obtener la clave pública PEM que debe distribuirse con el cliente, ejecuta `npm run --silent key:export`. Distribuye únicamente esa clave por un canal confiable. No se expone la clave privada por HTTP. Al rotar la clave privada, los tokens offline anteriores dejan de ser verificables con la nueva clave pública; coordina la actualización del cliente y el inicio de sesión/renovación. La rotación de `SESSION_SECRET` invalida todas las sesiones.

## Gestión manual

Ejecuta desde la carpeta de la API, con MongoDB configurado:

```sh
npm run user:manage -- --username usuario --name "Nombre Apellido" --status active --ends-at 2027-12-31T23:59:59Z
```

El comando solicita la contraseña sin mostrarla en una terminal. Debe tener entre 12 y 72 bytes, sin saltos de línea. No pases contraseñas como argumentos ni las incluyas literalmente en comandos, historial o archivos. Para automatización, se admite una sola contraseña por stdin desde un gestor de secretos confiable. El usuario no requiere formato de correo: se normaliza con Unicode NFKC, se recortan espacios externos y se convierte a minúsculas; es obligatorio, único, tiene un máximo de 254 caracteres y no admite caracteres de control. El nombre y la fecha con zona horaria son obligatorios. Usa `--status inactive` para desactivar, o `active` y una fecha futura para activar o renovar manualmente. El mismo comando crea o actualiza el usuario e **invalida todas sus sesiones anteriores**, y solicita una contraseña nueva en cada actualización. Las contraseñas se almacenan con bcrypt (coste 12). No almacena ni procesa pagos: un operador debe confirmar el pago por sus propios medios antes de modificar la suscripción.

Cada usuario tiene como máximo un dispositivo activo. El primer inicio de sesión válido registra el primer dispositivo; cualquier otra identidad de clave necesita aprobación administrativa. Para atender solicitudes, lista únicamente metadatos no secretos con `npm run device:requests` y aprueba una solicitud con `npm run device:approve -- --username usuario --request-id <id>`. La aprobación activa ese dispositivo, revoca el anterior e incrementa `sessionVersion`, invalidando todas las sesiones online previas. Una clave revocada, incluso si reaparece tras reinstalar la aplicación, vuelve a requerir aprobación.

## Panel administrativo remoto

El panel `admin-miniventa` usa rutas protegidas por `X-Admin-Key`. Genera una clave aleatoria de al menos 32 bytes (`openssl rand -hex 32`) y configúrala como `ADMIN_API_KEY` en el entorno del servidor. Si no está configurada, las rutas administrativas responden `503 admin_not_configured`; un valor de menos de 32 bytes impide arrancar el API. No incluyas esta clave en el frontend compilado ni en el repositorio. Publica el panel y el API únicamente por HTTPS y limita CORS al origen del panel en producción.

- `GET /api/admin/users?search=<texto>`: lista hasta 500 cuentas y metadatos de sus dispositivos, sin hashes ni claves públicas.
- `GET /api/admin/products`: lista el catálogo global completo.
- `GET /api/admin/contact-requests`: lista hasta 500 solicitudes de contacto recientes, incluidos los datos personales y la fecha de recepción.
- `DELETE /api/admin/contact-requests/:id`: elimina una solicitud de contacto por su identificador MongoDB.
- `POST /api/admin/products`: registra `number`, `name` y `priceCents` (entero no negativo). El número es texto único de hasta 40 caracteres, por lo que `001` y `1` son distintos; el nombre admite hasta 150 caracteres. Un número duplicado responde `409 product_number_exists`.
- `PUT /api/admin/products/:id`: reemplaza número, nombre y precio de un producto; usa el identificador de MongoDB devuelto por el API.
- `DELETE /api/admin/products/:id`: elimina el producto de la nube, sin eliminar los datos guardados previamente en dispositivos.
- `POST /api/admin/users`: registra una cuenta bloqueada. Recibe `username`, `name`, `password` y `priceCents` (precio en centavos de MXN, entero no negativo). La contraseña debe tener entre 12 y 72 bytes y se guarda con bcrypt; los usuarios duplicados responden `409 username_exists`.
- `PATCH /api/admin/users/:id/access`: recibe opcionalmente `priceCents` y/o `status: "inactive"`. Puede actualizar el precio sin cambiar el acceso o bloquear la cuenta; no permite activar una licencia ni alterar fechas de pago.
- `POST /api/admin/users/:id/confirm-payment`: cuerpo `{"requestId":"<UUID v4>","amountCents":30000,"paidAt":"<fecha ISO UTC>","endsAt":"<fecha ISO UTC futura>"}`. Confirma manualmente el monto recibido, registra un movimiento financiero, actualiza el último pago y vencimiento, activa la licencia e incrementa `sessionVersion`. El vencimiento debe ser posterior al actual, o responde `409 renewal_not_extended`. Reintentar con el mismo `requestId` y datos no duplica el pago; reutilizarlo con datos distintos responde `409 payment_request_conflict`. No existe renovación automática.
- `GET /api/admin/payments`: devuelve el total histórico `totalCents`, el número `count` y hasta 500 movimientos recientes, con nombre/usuario de referencia, monto, fecha de pago, registro y vencimiento. El historial reside en una colección independiente y sobrevive a la eliminación de la cuenta.
- `DELETE /api/admin/users/:id`: elimina permanentemente la cuenta y sus dispositivos. Los pagos confirmados permanecen en el historial financiero.
- `POST /api/admin/users/:id/revoke-sessions`: incrementa `sessionVersion` para cerrar las sesiones online actuales.
- `GET /api/admin/device-requests`: lista solicitudes de dispositivo pendientes sin exponer claves públicas.
- `POST /api/admin/device-requests/:requestId/approve`: aprueba el dispositivo, revoca el anterior e invalida sesiones.
- `POST /api/admin/device-requests/:requestId/reject`: revoca únicamente la solicitud pendiente; no desconecta el dispositivo que ya estaba activo.

Todas las rutas responden `401 invalid_admin_key` ante una clave inválida, `404` para cuentas/solicitudes inexistentes y `400 invalid_request` ante datos inválidos. Las respuestas llevan `Cache-Control: no-store`. El vencimiento se aplica automáticamente al autenticar o comprobar el acceso: una suscripción activa con `endsAt` pasado ya no permite entrar. No hay registro público ni cobros automáticos; usa `confirm-payment` para que una renovación quede reflejada en el historial. Los usuarios existentes sin `priceCents` reciben el valor predeterminado de cero y pueden configurarse desde el panel.

La confirmación de pagos requiere un replica set o clúster MongoDB compatible con transacciones: el cobro y la renovación se confirman juntos. Una instancia MongoDB independiente sin replica set no permite registrar pagos. Los pagos anteriores a este historial no se incorporan automáticamente a los ingresos. El comando `user:manage` modifica el acceso directamente y no registra pagos en el historial.

## Contrato HTTP

Usa HTTPS en producción. JSON UTF-8; respuestas de autenticación con `Cache-Control: no-store`. En los ejemplos, `<...>` representa un valor real.

- `POST /api/contact`: recibe el formulario de HIA Solutions como `application/x-www-form-urlencoded`, con `nombre`, `empresa`, `correo`, `telefono`, `tipo`, `descripcion` y `consentimiento=on`. Nombre, correo, descripción y consentimiento son obligatorios; el cuerpo del formulario tiene un máximo de 64 KiB. Guarda la solicitud en MongoDB y responde con una página de confirmación únicamente después de guardarla. Responde `400` ante datos inválidos, `413` si el cuerpo excede el límite y `429` después de 5 intentos por IP en 15 minutos. El límite es en memoria por proceso; ajusta la protección y los proxies confiables al despliegue. No envía notificaciones por correo: consulta las solicitudes mediante la ruta administrativa. Los datos no caducan automáticamente; define y aplica una política de retención, acceso y privacidad antes de habilitar el formulario.

- `GET /api/health`: `200 {"ok":true,"message":"API Miniventa running"}`.
- `GET /api/products`: catálogo global completo, protegido por sesión activa y las mismas cabeceras de prueba de dispositivo que `/api/auth/access`. Devuelve `{"products":[{"id":"<id>","number":"001","name":"Pan","priceCents":2000}]}` y `Cache-Control: no-store`.
- `POST /api/auth/device-challenge`: devuelve `200 {"challenge":"<JWT firmado por servidor>"}`. El reto lleva emisor/audiencia, identificador aleatorio de un solo uso y vence a los 2 minutos. Tiene límite de 30 solicitudes por IP cada 15 minutos.
- `POST /api/auth/login`: cuerpo `{"username":"usuario","password":"<contraseña>","devicePublicKey":"<SPKI PEM EC P-256>","deviceChallenge":"<reto>","deviceProof":"<firma ECDSA base64url>"}`. La aplicación genera y conserva una clave privada P-256 por instalación en almacenamiento seguro del sistema, exporta la clave pública SPKI y firma los bytes UTF-8 exactos del JWT de reto usando ECDSA/SHA-256 (firma DER codificada base64url). El servidor verifica el algoritmo, firma, expiración, emisor, audiencia, consumo único del reto y huella SHA-256 del SPKI antes de validar credenciales. Cada reto solo puede usarse una vez, también en login. Un primer dispositivo o uno ya activo recibe `200 {"sessionToken":"<JWT ligado a deviceKey>","offlineToken":"<JWT ligado a deviceKey>","user":{"id":"<id>","name":"<nombre>"},"subscription":{"status":"active","endsAt":"<fecha ISO UTC>"}}`. Un dispositivo nuevo recibe `202 {"error":"device_change_pending","requestId":"<id>"}` sin tokens. Reintentar una solicitud aún pendiente devuelve el mismo `requestId`.
- `GET /api/auth/access`: cabecera `Authorization: Bearer <sessionToken>` más `X-Device-Challenge: <reto>` y `X-Device-Proof: <firma ECDSA base64url>`. Para cada llamada protegida, solicita un reto nuevo y fírmalo con la clave privada P-256 asociada al dispositivo activo. El servidor valida sesión, estado y fingerprint, carga la clave pública guardada y verifica la firma sobre los bytes UTF-8 exactos del JWT del reto. El reto se consume una sola vez (incluido entre llamadas concurrentes) y debe usarse dentro de sus 120 segundos. Devuelve `200 {"user":{"id":"<id>","name":"<nombre>"},"subscription":{"status":"active","endsAt":"<fecha ISO UTC>"}}`.
- `POST /api/auth/renew`: mismas tres cabeceras que `/access`, sin cuerpo obligatorio y con un reto distinto y reciente por petición. Consulta el estado actual y devuelve `200 {"offlineToken":"<JWT nuevo>","user":{"id":"<id>","name":"<nombre>"},"subscription":{"status":"active","endsAt":"<fecha ISO UTC>"}}`. No renueva la suscripción ni extiende la sesión; emite una nueva autorización offline.

Errores JSON: `400 {"error":"invalid_request"}` para cuerpo/tipos inválidos, `413` con el mismo error para cuerpos superiores a 8 KiB; `401 {"error":"invalid_credentials"}` en login o `401 {"error":"invalid_session"}` para sesión, prueba de dispositivo ausente/inválida/reutilizada, sesión vencida o revocada; `403 {"error":"subscription_inactive"}` para credenciales/sesión válidas con suscripción inactiva o vencida; `429 {"error":"too_many_attempts"}` tras 10 intentos de login o 30 retos por IP en 15 minutos; y `500 {"error":"internal_error"}` ante errores internos. CORS admite `Authorization`, `Content-Type`, `X-Device-Challenge` y `X-Device-Proof`. No se aceptan tokens offline como sesiones. Los límites de intentos están en memoria por proceso: en despliegues con varios procesos o proxy se necesita un almacén compartido y configurar explícitamente los proxies confiables en Express antes de confiar en IP reenviadas.

## Verificación offline en el cliente

La sesión online es un JWT HS256 de 30 días para llamadas online; incluye `deviceKey` y su secreto nunca se distribuye. Cada petición protegida comprueba en MongoDB que esa huella siga activa, que `sessionVersion` coincida y que quien llama posea la clave privada del dispositivo activo mediante un reto firmado y de un solo uso. El token offline es un JWT RS256 firmado por el servidor, con `iss: "miniventa-api"`, `aud: "miniventa-offline"`, `token_use: "offline"`, `sub` (id del usuario), `deviceKey`, `name`, `subscriptionEndsAt` (ISO UTC), `iat` y `exp` (segundos Unix). `exp` es el menor entre `iat + 7 días` y el fin de suscripción, redondeado hacia abajo al segundo. El cliente debe verificar estrictamente firma RS256, emisor, audiencia, tipo, `exp` y fin de suscripción con la clave pública confiable antes de autorizar el acceso; rechazar algoritmos alternativos y tokens sin esos campos. Guardar clave privada y tokens en almacenamiento seguro del dispositivo y evitar registrar claves, tokens o contraseñas.

Sin conexión no es posible conocer una revocación, cambio de nombre o cambio de suscripción hasta la siguiente verificación online o el vencimiento del token previamente emitido. Por ello, un token offline entregado antes de una revocación puede seguir autorizando localmente durante el tiempo restante, como máximo 7 días y nunca más allá de la suscripción. Al reconectar, el token de sesión viejo recibe `401` y debe borrarse; el dispositivo anterior no obtiene nuevos tokens. El reloj manipulable del dispositivo también limita la garantía offline: usar protecciones de reloj/almacenamiento del sistema y reconocer que un dispositivo comprometido no puede garantizar el plazo.

## Pruebas

`npm test` ejecuta pruebas HTTP con repositorio simulado y del cálculo de expiración. Para ejecutar además la prueba del CLI y persistencia contra un `mongod` local temporal aislado: `RUN_MONGO_INTEGRATION=1 npm test`. Esta última requiere `mongod` disponible en `PATH` y no utiliza la base configurada en `.env`.
