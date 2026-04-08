const rateLimit = require('express-rate-limit');

function intFromEnv(name, fallback) {
  const parsed = parseInt(process.env[name] || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const OTP_REQUEST_WINDOW_MIN = intFromEnv('OTP_REQUEST_WINDOW_MINUTES', 2);
const OTP_REQUEST_MAX = intFromEnv('OTP_REQUEST_MAX', 4);
const OTP_VERIFY_WINDOW_MIN = intFromEnv('OTP_VERIFY_WINDOW_MINUTES', 5);
const OTP_VERIFY_MAX = intFromEnv('OTP_VERIFY_MAX', 12);

const otpRequestLimiter = rateLimit({
  windowMs: OTP_REQUEST_WINDOW_MIN * 60 * 1000,
  max: OTP_REQUEST_MAX,
  message: {
    error: `Too many OTP requests. Please wait ${OTP_REQUEST_WINDOW_MIN} minute(s) and try again.`,
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const otpVerifyLimiter = rateLimit({
  windowMs: OTP_VERIFY_WINDOW_MIN * 60 * 1000,
  max: OTP_VERIFY_MAX,
  skipSuccessfulRequests: true,
  message: {
    error: `Too many failed code attempts. Please wait ${OTP_VERIFY_WINDOW_MIN} minute(s) and request a fresh OTP.`,
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { otpRequestLimiter, otpVerifyLimiter, apiLimiter };
