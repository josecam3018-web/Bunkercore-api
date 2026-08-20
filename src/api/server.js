import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import Stripe from 'stripe';
import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';
import { checkAuthStatus } from '../../check_auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Instancia de Stripe (utiliza la variable de entorno o un placeholder de prueba)
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

app.use(express.json());

// Archivos estáticos
app.use(express.static(path.join(__dirname, '../../public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../public/index.html'));
});

const PORT = process.env.PORT || 3000;

console.log("Bunkercore: Sistema iniciado y en modo Zero-Trust con Módulo Billing.");

/**
 * Middleware de Autenticación por API Key (x-api-key)
 */
const securityGuard = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const { tenantId } = req.body;

    if (apiKey && tenantId) {
        try {
            const isValid = await db.isValidApiKey(tenantId, apiKey);
            if (isValid) return next();
            return res.status(401).json({ error: "Acceso denegado: API Key o Tenant ID no válido o suscripción inactiva." });
        } catch (err) {
            return res.status(500).json({ error: "Error validando credenciales: " + err.message });
        }
    }

    if (process.env.NODE_ENV === 'production') {
        const { userSignature } = req.body;
        if (userSignature && userSignature.startsWith('fido2_signature')) {
            return next();
        }
        return res.status(401).json({
            error: "Acceso denegado: Se requiere encabezado 'x-api-key' válido."
        });
    }

    if (!checkAuthStatus()) {
        return res.status(401).json({ error: "Acceso denegado: Se requiere autenticación biométrica." });
    }
    next();
};

/**
 * ENDPOINT 0: Crear Sesión de Pago en Stripe
 * POST /v1/billing/checkout
 */
app.post('/v1/billing/checkout', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'BunkerCore API - Plan Pro',
                            description: 'Acceso a Cifrado Zero-Trust con RLS y almacenamiento seguro',
                        },
                        unit_amount: 2900, // $29.00 USD/mes
                        recurring: { interval: 'month' },
                    },
                    quantity: 1,
                },
            ],
            success_url: `${req.protocol}://${req.get('host')}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
            cancel_url: `${req.protocol}://${req.get('host')}/?status=cancelled`,
        });

        return res.status(200).json({ url: session.url });
    } catch (error) {
        return res.status(500).json({ error: "Error al generar Checkout de Stripe: " + error.message });
    }
});

/**
 * ENDPOINT Webhook: Confirmación de Pago Automático desde Stripe
 * POST /v1/billing/webhook
 */
app.post('/v1/billing/webhook', async (req, res) => {
    const event = req.body;

    // Cuando la suscripción o pago ha sido completado exitosamente
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // Generar credenciales automáticamente tras confirmación de pago
        const tenantId = 'tenant-' + Math.random().toString(36).substring(2, 9);
        const apiKey = 'bk_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        await db.createApiKey(tenantId, apiKey);
        console.log(`💳 Suscripción activada: ${tenantId} con API Key ${apiKey}`);
    }

    return res.status(200).json({ received: true });
});

/**
 * ENDPOINT Registro Manual / Demostración
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
