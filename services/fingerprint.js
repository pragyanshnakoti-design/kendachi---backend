const crypto = require('crypto');

// Build a device fingerprint from request headers.
// Not biometric — just enough to detect session hijack
// (different machine, different browser, or cookie theft).
function buildFingerprint(req) {
  const ua      = req.headers['user-agent'] || '';
  const lang    = req.headers['accept-language'] || '';
  const enc     = req.headers['accept-encoding'] || '';
  const raw     = `${ua}|${lang}|${enc}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32);
}

// Verify that the current request matches the fingerprint
// that was recorded at login time.
function verifyFingerprint(req, storedFingerprint) {
  const current = buildFingerprint(req);
  return current === storedFingerprint;
}

// Verify that the current IP matches the session IP.
// Allow /24 subnet match for corporate NAT environments.
function verifyIP(req, storedIP) {
  const currentIP = getClientIP(req);
  if (currentIP === storedIP) return true;

  // Subnet tolerance — same /24 (e.g. 192.168.1.x)
  const currentParts = currentIP.split('.').slice(0, 3).join('.');
  const storedParts  = storedIP.split('.').slice(0, 3).join('.');
  return currentParts === storedParts;
}

function getClientIP(req) {
  const raw =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown';

  if (raw === '::1') return '127.0.0.1';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw;
}

module.exports = { buildFingerprint, verifyFingerprint, verifyIP, getClientIP };
