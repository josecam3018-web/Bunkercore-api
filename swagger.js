import swaggerJSDoc from 'swagger-jsdoc';

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'BunkerCore API - Zero-Trust Encryption SaaS',
      version: '1.0.0',
      description: 'API Criptográfica Zero-Trust con soporte Multi-Tenant.',
    },
    servers: [
      { url: 'https://bunkercore-api.onrender.com', description: 'Producción' },
      { url: 'http://localhost:3000', description: 'Desarrollo Local' }
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-api-key',
          description: 'Clave de API de BunkerCore'
        }
      }
    }
  },
  apis: ['./server.js'],
};

export const swaggerDocs = swaggerJSDoc(swaggerOptions);
