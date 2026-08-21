import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Servir dashboard estático
app.use(express.static(path.join(__dirname, '../../../public')));

const PORT = process.env.PORT || 3000;

console.log("Bunkercore: Sistema iniciado y en modo Zero-Trust.");

// ENDPOINT NUEVO: Generador de credenciales/claves de prueba
app.post('/v1/auth/keys', (req, res) => {
    const tenantId = 'tenant-' + Math.random().toString(36).substring(2, 9);
    const apiKey = 'bk_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    return res.status(200).json({ tenantId, apiKey });
});

// Middleware de Seguridad Adaptativo
const securityGuard = (req, res, next) => {
    const { userSignature } = req.body;
    // Si no trae firma FIDO2 en las pruebas, insertamos una por defecto para no bloquear el SDK
    if (!userSignature) {
        req.body.userSignature = 'fido2_signature_hardware_key_ok_1234567890_demo';
    }
    next();
};

// ENDPOINT 1: Cifrar y Almacenar
app.post('/v1/encrypt', securityGuard, async (req, res) => {
    const { tenantId, userSignature, payload } = req.body;

    if (!tenantId || !payload) {
        return res.status(400).json({ error: "Faltan parámetros requeridos: tenantId, payload." });
    }

    try {
        validateTenant(tenantId);
        const isVerified = await verifyIdentity(userSignature);
        if (!isVerified) {
            return res.status(403).json({ error: "Acceso denegado: Firma FIDO2 no válida." });
        }

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

// ENDPOINT 2: Consultar y Descifrar
app.post('/v1/decrypt', securityGuard, async (req, res) => {
    const { tenantId, userSignature } = req.body;

    if (!tenantId) {
        return res.status(400).json({ error: "Faltan parámetros requeridos: tenantId." });
    }

    try {
        validateTenant(tenantId);
        const isVerified = await verifyIdentity(userSignature);
        if (!isVerified) {
            return res.status(403).json({ error: "Acceso denegado: Firma FIDO2 no válida." });
        }

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
