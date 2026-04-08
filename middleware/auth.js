const jwt = require('jsonwebtoken');
const { query } = require('../db');
const { verifyFingerprint, verifyIP, getClientIP } = require('../services/fingerprint');

// ─── Verify JWT and bind to session ────────────────────────
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = header.split(' ')[1];
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Token invalid or expired' });
    }

    // Look up active session record
    const { rows } = await query(
      `SELECT s.*, e.id as emp_id, e.name, e.email, e.role, e.emp_code,
              e.department, e.is_active
       FROM active_sessions s
       JOIN employees e ON e.id = s.employee_id
       WHERE s.session_token = $1 AND s.expires_at > NOW()`,
      [payload.sessionToken]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Session expired or revoked' });
    }

    const session = rows[0];

    if (!session.is_active) {
      return res.status(403).json({ error: 'Account deactivated' });
    }

    // ── Session binding checks ──────────────────────────────
    const currentIP = getClientIP(req);
    if (!verifyIP(req, session.ip_address)) {
      await logAudit({
        actor_id: session.emp_id,
        action: 'session_ip_mismatch',
        detail: { stored: session.ip_address, current: currentIP },
        ip: currentIP,
        success: false,
        threat: 'high',
      });
      return res.status(401).json({
        error: 'Session IP mismatch — possible hijack detected',
        code: 'IP_MISMATCH',
      });
    }

    if (!verifyFingerprint(req, session.device_fingerprint)) {
      await logAudit({
        actor_id: session.emp_id,
        action: 'session_fingerprint_mismatch',
        detail: { sessionId: session.id },
        ip: currentIP,
        success: false,
        threat: 'high',
      });
      return res.status(401).json({
        error: 'Device mismatch — session blocked',
        code: 'DEVICE_MISMATCH',
      });
    }

    // Update last ping
    await query(
      'UPDATE active_sessions SET last_ping = NOW() WHERE session_token = $1',
      [session.session_token]
    );

    // Attach to request
    req.user = {
      id:          session.emp_id,
      name:        session.name,
      email:       session.email,
      role:        session.role,
      empCode:     session.emp_code,
      department:  session.department,
      sessionToken: session.session_token,
    };

    next();
  } catch (err) {
    next(err);
  }
}

// ─── Role guard factory ─────────────────────────────────────
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied — requires role: ${roles.join(' or ')}`,
        code: 'INSUFFICIENT_ROLE',
      });
    }
    next();
  };
}

// ─── Audit log helper ───────────────────────────────────────
async function logAudit({ actor_id, actor_role, action, table, target_id, detail, ip, fp, success = true, threat = 'none' }) {
  try {
    await query(
      `INSERT INTO audit_log
         (actor_id, actor_role, action, target_table, target_id, detail,
          ip_address, device_fingerprint, success, threat_level)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        actor_id || null,
        actor_role || null,
        action,
        table || null,
        target_id || null,
        JSON.stringify(detail || {}),
        ip || null,
        fp || null,
        success,
        threat,
      ]
    );
  } catch (e) {
    console.error('[AUDIT] log failed:', e.message);
  }
}

module.exports = { requireAuth, requireRole, logAudit };
