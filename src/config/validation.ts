import * as Joi from 'joi';

// проверка переменных в валидации env
export const validationSchema = Joi.object({
  JWT_SECRET: Joi.string().required(),
  JWT_EXPIRES_IN: Joi.string().default('1h'),
  HMAC_SECRET: Joi.string().required(),
  REFRESH_TOKEN_TTL_DAYS: Joi.number().integer().min(1).default(7),
  REFRESH_COOKIE_NAME: Joi.string().default('refresh_token'),
});
