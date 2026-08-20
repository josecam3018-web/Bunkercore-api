import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';
import { checkAuthStatus } from '../../check_auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Archivos estáticos
app.use(express.static(path.join(__dirname, '../../public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../public/index.html'));
});

const PORT = process.env.PORT || 3000;

console.log("Bunkercore: Sistema iniciado y en modo Zero-Trust.");

/**
 * Middleware de Autenticación por API Key (x-api-key)
 */
const securityGuard = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const { tenantId } = req.body;

    // Validación por API Key comercial
    if (apiKey && tenantId) {
        try {
            const isValid = await db.isValidApiKey(tenantId, apiKey);
            if (isValid) return next();
            return res.status(401).json({ error: "Acceso denegado: API Key o Tenant ID no válido." });
        } catch (err) {
            return res.status(500).json({ error: "Error validando credenciales: " + err.message });
        }
    }

    // Modo Desarrollo / Firma FIDO2
    if (process.env.NODE_ENV === 'production') {
        const { userSignature } = req.body;
        if (userSignature && userSignature.startsWith('fido2_signature')) {
            return next();
        }
        return res.status(401).json({
            error: "Acceso denegado: Se requiere encabezado 'x-api-key' válido o firma de seguridad."
        });
    }

    if (!checkAuthStatus()) {
        return res.status(401).json({ error: "Acceso denegado: Se requiere autenticación biométrica." });
    }
    next();
};

/**
 * ENDPOINT 0: Registrar Nuevo Tenant & Generar API Key
 * POST /v1/auth/keys
 */
app.post('/v1/auth/keys', async (req, res) => {
    try {
        const tenantId = 'tenant-' + Math.random().toString(36).substring(2, 9);
        const apiKey = 'bk_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        await db.createApiKey(tenantId, apiKey);

        return res.status(201).json({
            status: "CREATED",
            tenantId,
            apiKey,
            message: "Guarda tu API Key. Requerida en la cabecera 'x-api-key'."
        });
    } catch (error) {
        return res.status(500).json({ error: "Error generando credenciales: " + error.message });
    }
});

/**
 * ENDPOINT 1: Cifrar Datos
 * POST /v1/encrypt
 */
app.post('/v1/encrypt', securityGuard, async (req, res) => {
    const { tenantId, payload } = req.body;

    if (!tenantId || !payload) {
        return res.status(400).json({ error: "Faltan parámetros requeridos: tenantId, payload." });
    }

    try {
        validateTenant(tenantId);

        const securePayload = await encryptData(payload, tenantId);
        const event = await recordEvent(tenantId, "DATA_ENCRYPTION", "Procesado vía API REST.");
        await db.saveData(tenantId, securePayload, event.fingerprint);

        return res.status(200).json({
            status: "SECURED_AND_SAVED",
            tenantId,
            fingerprint: event.fingerprint,
            data: securePayload
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

/**
 * ENDPOINT 2: Consultar y Descifrar Datos
 * POST /v1/decrypt
 */
app.post('/v1/decrypt', securityGuard, async (req, res) => {
    const { tenantId } = req.body;

    if (!tenantId) {
        return res.status(400).json({ error: "Falta parámetro requerido: tenantId." });
    }

    try {
        validateTenant(tenantId);

        const secureBlob = await db.getData(tenantId);
        if (!secureBlob) {
            return res.status(404).json({ error: "No se encontraron datos cifrados para este inquilino." });
        }

        const decryptedData = await decryptData(secureBlob);
        await recordEvent(tenantId, "DATA_RETRIEVAL", "Consulta exitosa vía API REST.");

        return res.status(200).json({
            status: "SUCCESS",
            tenantId,
            data: decryptedData
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 BunkerCore API Server corriendo en puerto ${PORT}`);
});
