import express from 'express';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import { swaggerDocs } from './swagger.js';

// NOTA: Ajusta estas importaciones si tus módulos de DB/Auth tienen otros nombres
import { securityGuard } from './securityGuard.js'; // O tu middleware de API Key
// import { pool } from './db.js'; 

const app = express();
app.use(cors());
app.use(express.json());

// -------------------------------------------------------------
// DOCUMENTACIÓN DE SWAGGER UI EN /docs
// -------------------------------------------------------------
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @openapi
 * /v1/auth/keys:
 *   post:
 *     summary: Registrar credenciales de prueba
 *     description: Genera un nuevo tenantId y apiKey para comenzar a consumir la API Criptográfica.
 *     tags:
 *       - Autenticación
 *     responses:
 *       200:
 *         description: Credenciales generadas con éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tenantId:
 *                   type: string
 *                   example: "tenant-q5j1hm0"
 *                 apiKey:
 *                   type: string
 *                   example: "bk_live_9c18eea59eec8f32ff3a18387f76a5ec"
 */
app.post('/v1/auth/keys', async (req, res) => {
  // Aquí la lógica existente de generación de llaves
  const tenantId = `tenant-${Math.random().toString(36).substring(2, 9)}`;
  const apiKey = `bk_live_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;
  res.json({ tenantId, apiKey });
});

/**
 * @openapi
 * /v1/encrypt:
 *   post:
 *     summary: Cifrar payload de un Tenant (Zero-Trust)
 *     description: Cifra los datos usando AES-256-GCM y los resguarda con aislamiento RLS.
 *     tags:
 *       - Cifrado
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - tenantId
 *               - payload
 *             properties:
 *               tenantId:
 *                 type: string
 *                 example: "tenant-q5j1hm0"
 *               payload:
 *                 type: object
 *                 example: {"usuario": "Carlos", "saldo": 1500}
 *     responses:
 *       200:
 *         description: Objeto cifrado y resguardado correctamente
 *       401:
 *         description: Acceso denegado (x-api-key ausente o inválida)
 */
app.post('/v1/encrypt', async (req, res) => {
  // Tu lógica actual de cifrado AES-256-GCM
  const { tenantId, payload } = req.body;
  if (!tenantId || !payload) {
    return res.status(400).json({ error: 'tenantId y payload son requeridos' });
  }
  res.json({
    status: 'SECURED_AND_SAVED',
    tenantId,
    fingerprint: '74656e616e742d71',
    data: '3bff10d1d7c5dd9990cafcd8:94460b3487d3a52dbc3110d37530e6ff...'
  });
});

/**
 * @openapi
 * /v1/decrypt:
 *   post:
 *     summary: Descifrar payload de un Tenant
 *     description: Recupera y descifra los datos resguardados pertenecientes únicamente al tenant solicitante.
 *     tags:
 *       - Cifrado
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - tenantId
 *             properties:
 *               tenantId:
 *                 type: string
 *                 example: "tenant-q5j1hm0"
 *     responses:
 *       200:
 *         description: Objeto descifrado con éxito
 *       401:
 *         description: Acceso denegado
 */
app.post('/v1/decrypt', async (req, res) => {
  // Tu lógica actual de descifrado
  const { tenantId } = req.body;
  res.json({
    status: 'SUCCESS',
    tenantId,
    data: { usuario: 'Carlos', saldo: 1500 }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en el puerto ${PORT}`);
  console.log(`📚 Documentación OpenAPI/Swagger disponible en http://localhost:${PORT}/docs`);
});
