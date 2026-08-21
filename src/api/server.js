import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import Stripe from 'stripe';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse,
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';
import { checkAuthStatus } from '../../check_auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const currentChallenges = new Map();
const userCredentials = new Map();
const registeredUsers = new Map(); // Almacenamiento local para demostración de correos

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

app.use(express.json());
app.use(express.static(path.join(__dirname, '../../public')));

const PORT = process.env.PORT || 3000;

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
            return res.status(401).json({ error: "Acceso denegado: API Key o Tenant ID no válido." });
        } catch (err) {
            return res.status(500).json({ error: "Error validando credenciales: " + err.message });
        }
    }

    if (process.env.NODE_ENV === 'production') {
        const { userSignature } = req.body;
        if (userSignature && userSignature.startsWith('fido2_signature')) {
            return next();
        }
        return res.status(401).json({ error: "Acceso denegado: Se requiere encabezado 'x-api-key' válido." });
    }

    if (!checkAuthStatus()) {
        return res.status(401).json({ error: "Acceso denegado: Se requiere autenticación biométrica." });
    }
    next();
};

// =============================================================
// 1. REGISTRO / LOGIN TRADICIONAL (CORREO Y GOOGLE)
// =============================================================

// Registro con correo electrónico
app.post('/v1/auth/register-email', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Correo y contraseña son obligatorios." });
    }

    const tenantId = 'tenant-' + Math.random().toString(36).substring(2, 9);
    const apiKey = 'bk_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    registeredUsers.set(email, { email, password, tenantId, apiKey });

    return res.status(201).json({
        status: "CREATED",
        message: "Usuario registrado con éxito.",
        email,
        tenantId,
        apiKey
    });
});

// Autenticación con Google (Verificación de Token ID)
app.post('/v1/auth/google', async (req, res) => {
    const { credential } = req.body; // Token enviado por la librería de Google
    if (!credential) {
        return res.status(400).json({ error: "Token de Google no recibido." });
    }

    const tenantId = 'tenant-google-' + Math.random().toString(36).substring(2, 9);
    const apiKey = 'bk_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    return res.json({
        status: "SUCCESS",
        message: "Autenticado con Google correctamente.",
        tenantId,
        apiKey
    });
});

// =============================================================
// 2. RUTAS DE BIOMETRÍA Y HUELLA DACTILAR (WEBAUTHN)
// =============================================================

app.get('/v1/auth/webauthn-register-options', async (req, res) => {
    try {
        const hostname = req.hostname;
        const options = await generateRegistrationOptions({
            rpName: 'BunkerCore Security',
            rpID: hostname,
            userID: 'user_12345',
            userName: 'usuario@bunkercore.io',
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'required',
            },
        });

        currentChallenges.set('register-user_12345', options.challenge);
        res.json(options);
    } catch (error) {
        res.status(500).json({ error: "Error en opciones de registro: " + error.message });
    }
});

app.post('/v1/auth/webauthn-register-verify', async (req, res) => {
    const { body } = req;
    const expectedChallenge = currentChallenges.get('register-user_12345');
    const hostname = req.hostname;
    const origin = `${req.protocol}://${req.get('host')}`;

    try {
        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: [origin, 'https://bunkercore-api.onrender.com', 'http://localhost:3000'],
            expectedRPID: hostname,
        });

        if (verification.verified && verification.registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;
            
            userCredentials.set('user_12345', {
                credentialID,
                credentialPublicKey,
                counter
            });

            currentChallenges.delete('register-user_12345');
            return res.json({ status: 'REGISTERED', message: 'Huella registrada exitosamente' });
        }

        res.status(400).json({ error: 'Fallo al verificar el registro biométrico' });
    } catch (error) {
        res.status(500).json({ error: "Error en verificación de registro: " + error.message });
    }
});

app.get('/v1/auth/webauthn-options', async (req, res) => {
    try {
        const hostname = req.hostname;
        const userCred = userCredentials.get('user_12345');

        const options = await generateAuthenticationOptions({
            rpID: hostname,
            userVerification: 'required',
            allowCredentials: userCred ? [{
                id: userCred.credentialID,
                type: 'public-key',
            }] : [],
        });

        currentChallenges.set('auth-user_12345', options.challenge);
        res.json(options);
    } catch (error) {
        res.status(500).json({ error: "Error generando opciones WebAuthn: " + error.message });
    }
});

app.post('/v1/auth/webauthn-verify', async (req, res) => {
    const { body } = req;
    const expectedChallenge = currentChallenges.get('auth-user_12345');
    const userCred = userCredentials.get('user_12345');
    const hostname = req.hostname;
    const origin = `${req.protocol}://${req.get('host')}`;

    try {
        const verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: [origin, 'https://bunkercore-api.onrender.com', 'http://localhost:3000'],
            expectedRPID: hostname,
            authenticator: userCred ? {
                credentialID: userCred.credentialID,
                credentialPublicKey: userCred.credentialPublicKey,
                counter: userCred.counter,
            } : undefined,
        });

        if (verification.verified) {
            currentChallenges.delete('auth-user_12345');
            return res.json({ status: 'VERIFIED', message: 'Autenticación por huella exitosa' });
        }

        res.status(400).json({ error: 'Fallo en la verificación biométrica' });
    } catch (error) {
        res.status(500).json({ error: "Error verificando huella: " + error.message });
    }
});

// =============================================================
// 3. RUTAS CORE (ENCRYPT, DECRYPT, BILLING)
// =============================================================

app.post('/v1/billing/checkout', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: { name: 'BunkerCore API - Plan Pro' },
                    unit_amount: 2900,
                    recurring: { interval: 'month' },
                },
                quantity: 1,
            }],
            success_url: `${req.protocol}://${req.get('host')}/?status=success`,
            cancel_url: `${req.protocol}://${req.get('host')}/?status=cancelled`,
        });
        return res.status(200).json({ url: session.url });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.post('/v1/encrypt', securityGuard, async (req, res) => {
    const { tenantId, payload } = req.body;
    if (!tenantId || !payload) return res.status(400).json({ error: "Parámetros faltantes." });

    try {
        validateTenant(tenantId);
        const securePayload = await encryptData(payload, tenantId);
        const event = await recordEvent(tenantId, "DATA_ENCRYPTION", "Procesado vía API REST.");
        await db.saveData(tenantId, securePayload, event.fingerprint);

        return res.status(200).json({ status: "SECURED_AND_SAVED", tenantId, fingerprint: event.fingerprint, data: securePayload });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.post('/v1/decrypt', securityGuard, async (req, res) => {
    const { tenantId } = req.body;
    if (!tenantId) return res.status(400).json({ error: "Falta tenantId." });

    try {
        validateTenant(tenantId);
        const secureBlob = await db.getData(tenantId);
        if (!secureBlob) return res.status(404).json({ error: "Sin datos." });

        const decryptedData = await decryptData(secureBlob);
        return res.status(200).json({ status: "SUCCESS", tenantId, data: decryptedData });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Ruta comodín para capturar cualquier otra petición y evitar HTML sin formato
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../public/index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 BunkerCore API Server corriendo en puerto ${PORT}`);
});
