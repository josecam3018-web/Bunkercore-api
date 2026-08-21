import rateLimit from 'express-rate-limit';

export const cryptoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Límite de 100 peticiones por ventana por IP
  message: {
    error: "Demasiadas peticiones desde esta IP, intente de nuevo en 15 minutos."
  },
  standardHeaders: true,
  legacyHeaders: false,
});
