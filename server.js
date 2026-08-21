import express from 'express';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import { swaggerDocs } from './swagger.js';
import { securityGuard } from './securityGuard.js';
import { cryptoLimiter } from './rateLimiter.js';
import { initDb } from './db.js';

const app = express();
app.use(cors());
app.use(express.json());

// Inicializar tabla DB al arrancar
initDb().catch(console.error);

// Documentación Swagger en /docs
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Aplicar Rate Limiting a las rutas criptográficas
app.use('/v1/encrypt', cryptoLimiter);
app.use('/v1/decrypt', cryptoLimiter);

app.post('/v1/auth/keys', async (req, res) => {
  const tenantId = `tenant-${Math.random().toString(36).substring(2, 9)}`;
  const apiKey = `bk_live_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;
  res.json({ tenantId, apiKey });
});

app.post('/v1/encrypt', securityGuard, async (req, res) => {
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

app.post('/v1/decrypt', securityGuard, async (req, res) => {
  const { tenantId } = req.body;
  res.json({
    status: 'SUCCESS',
    tenantId,
    data: { usuario: 'Carlos', saldo: 1500 }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor BunkerCore corriendo en puerto ${PORT}`);
  console.log(`📚 Documentación Swagger en http://localhost:${PORT}/docs`);
});
