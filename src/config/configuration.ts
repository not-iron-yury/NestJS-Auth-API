export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '1h',
  },
  refreshToken: {
    ttlDays: parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '7', 10),
    cookieName: process.env.REFRESH_COOKIE_NAME || 'refresh_token',
  },
  hmac: {
    secret: process.env.HMAC_SECRET || 'default_secret',
  },
});
