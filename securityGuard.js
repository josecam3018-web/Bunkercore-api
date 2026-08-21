import { pool } from './db.js';

export const securityGuard = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: "Acceso denegado: Cabecera 'x-api-key' faltante." });
  }

  try {
    const result = await pool.query('SELECT tenant_id FROM api_keys WHERE api_key = $1', [apiKey]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Acceso denegado: API Key inválida." });
    }
    req.tenantId = result.rows[0].tenant_id;
    next();
  } catch (error) {
    return res.status(500).json({ error: "Error de autenticación en la base de datos." });
  }
};
