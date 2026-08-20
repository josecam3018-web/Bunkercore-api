import { bunkercore } from './src/api/server.js';

async function main() {
    console.log("=== MOTOR BUNKERCORE: LECTURA Y ESCRITURA ===");
    
    bunkercore.init();
    const mockFidoSignature = "fido2_signature_hardware_key_ok_1234567890_demo";
    const tenantId = "tenant-demo-01";

    try {
        console.log("\n1. Guardando datos cifrados...");
        await bunkercore.processData(
            { secreto: "Clave de acceso a servidores principales", timestamp: Date.now() },
            tenantId,
            mockFidoSignature
        );

        console.log("\n2. Consultando y descifrando datos desde PostgreSQL (Neon)...");
        const decryptedData = await bunkercore.retrieveData(tenantId, mockFidoSignature);
        
        console.log("\n✅ [DATO DESCIFRADO DE LA BD]:", decryptedData);
        process.exit(0);
    } catch (error) {
        console.error("\n[ERROR/BLOQUEO DE SEGURIDAD]:", error.message);
        process.exit(1);
    }
}

main();
