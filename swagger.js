import swaggerJSDoc from 'swagger-jsdoc';

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'BunkerCore API - Zero-Trust Encryption SaaS',
      version: '1.0.0',
      description: 'API Criptográfica Zero-Trust con soporte para Múltiples Inquilinos (Multi-Tenant), aislamiento RLS en PostgreSQL y facturación automatizada mediante Stripe.',
      contact: {
        name: 'Soporte BunkerCore',
        url: 'https://github.com/josecam3018-web/bunkercore-sdk',
      },
    },
    servers: [
      {
        url: 'https://bunkercore-api.onrender.com',
        description: 'Servidor de Producción (Render)',
      },
      {
        url: 'http://localhost:3000',
        description: 'Servidor Local de Desarrollo',
      },
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-api-key',
          description: 'Clave de API para autenticación de peticiones Zero-Trust',
        },
      },
    },
  },
  apis: ['./server.js'], // Escanea las anotaciones dentro de server.js
};

export const swaggerDocs = swaggerJSDoc(swaggerOptions);
