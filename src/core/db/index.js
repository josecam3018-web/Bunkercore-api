import postgres from 'postgres';
import 'dotenv/config';

const sql = postgres(process.env.DATABASE_URL, { ssl: 'require' });

/**
 * DB Module con aislamiento Multitenant (RLS ready)
 */
export const db = {
    /**
     * Guarda datos asegurando que el contexto del Tenant esté configurado.
     */
    saveData: async (tenantId, payload, fingerprint) => {
        return await sql.begin(async sql => {
            // Establecemos el tenant_id para esta transacción (RLS lo usará)
            await sql`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;

            await sql`
                INSERT INTO inventory_records (tenant_id, secure_data, fingerprint)
                VALUES (${tenantId}, ${payload}, ${fingerprint})
            `;
        });
    },

    /**
     * Recupera datos filtrados automáticamente por RLS.
     */
    getData: async (tenantId) => {
        return await sql.begin(async sql => {
            // Establecemos el tenant_id (Si intentamos ver otro, RLS devolverá vacío)
            await sql`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;

            const result = await sql`
                SELECT secure_data FROM inventory_records
                ORDER BY created_at DESC LIMIT 1
            `;
            return result[0]?.secure_data;
        });
    },

    /**
     * Guarda una nueva API Key para un Tenant en PostgreSQL.
     */
    createApiKey: async (tenantId, apiKey) => {
        await sql`
            INSERT INTO api_keys (tenant_id, api_key)
            VALUES (${tenantId}, ${apiKey})
        `;
    },

    /**
     * Valida si la combinación de tenant_id y api_key es correcta y está activa.
     */
    isValidApiKey: async (tenantId, apiKey) => {
        const result = await sql`
            SELECT active FROM api_keys 
            WHERE tenant_id = ${tenantId} AND api_key = ${apiKey} AND active = TRUE
            LIMIT 1
        `;
        return result.length > 0;
    }
};
