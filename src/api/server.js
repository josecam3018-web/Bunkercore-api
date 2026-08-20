import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';
import { checkAuthStatus } from '../../check_auth.js';

// Configuración de rutas estáticas para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Servir la interfaz web desde la carpeta public/
app.use(express.static(path.join(__dirname, '../../../public')));

const PORT = process.env.PORT || 3000;

console.log("Bunkercore: Sistema iniciado y en modo Zero-Trust.");

// Middleware de Seguridad Adaptativo (Termux / Render)
const securityGuard = (req, res, next) => {
    // Si la aplicación corre en producción (Render), valida la firma de la petición
    if (process.env.NODE_ENV === 'production') {
        const { userSignature } = req.body;
        if (!userSignature || !userSignature.startsWith('fido2_signature')) {
            return res.status(401).json({
                error: "Acceso denegado: Firma FIDO2 o ticket de seguridad inválido."
            });
        }
        return next();
    }

    // En entorno local (Termux)
    if (!checkAuthStatus()) {
        return res.status(401).json({
            error: "Acceso denegado: Se requiere autenticación biométrica o ticket válido."
        });
    }
    next();
};

/**
 * ENDPOINT 1: Cifrar y Almacenar Datos
 * POST /v1/encrypt
 */
app.post('/v1/encrypt', securityGuard, async (req, res) => {
    const { tenantId, userSignature, payload } = req.body;

    if (!tenantId || !userSignature || !payload) {
        return res.status(400).json({ error: "Faltan parámetros requeridos: tenantId, userSignature, payload." });
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

/**
 * ENDPOINT 2: Consultar y Descifrar Datos
 * POST /v1/decrypt
 */
app.post('/v1/decrypt', securityGuard, async (req, res) => {
    const { tenantId, userSignature } = req.body;

    if (!tenantId || !userSignature) {
        return res.status(400).json({ error: "Faltan parámetros requeridos: tenantId, userSignature." });
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
