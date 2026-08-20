import postgres from 'postgres';
import 'dotenv/config';

const sql = postgres(process.env.DATABASE_URL, { ssl: 'require' });

async function initDatabase() {
    console.log("Iniciando migración y aislamiento RLS en Neon...");

    try {
        // 1. Crear extensión para UUIDs si no existe
        await sql`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`;

        // 2. Crear tabla de Tenants
        await sql`
            CREATE TABLE IF NOT EXISTS tenants (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                domain TEXT UNIQUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `;

        // 3. Crear tabla principal inventory_records
        await sql`
            CREATE TABLE IF NOT EXISTS inventory_records (
                id SERIAL PRIMARY KEY,
                tenant_id VARCHAR(255) NOT NULL,
                secure_data TEXT NOT NULL,
                fingerprint VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `;

        // 4. Habilitar RLS
        await sql`ALTER TABLE inventory_records ENABLE ROW LEVEL SECURITY;`;

        // 5. Crear la política de seguridad RLS
        await sql`
            DO $$ 
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_policy'
                ) THEN
                    CREATE POLICY tenant_isolation_policy ON inventory_records
                        USING (tenant_id = current_setting('app.current_tenant_id', true));
                END IF;
            END $$;
        `;

        console.log("✅ Estructura de base de datos y RLS configurados con éxito.");
        process.exit(0);
    } catch (err) {
        console.error("❌ Error en la migración:", err.message);
        process.exit(1);
    }
}

initDatabase();
