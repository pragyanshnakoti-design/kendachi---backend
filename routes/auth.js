const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const { query } = require('../db');
const { sendOTP } = require('../services/email');
const { buildFingerprint, getClientIP } = require('../services/fingerprint');
const { checkLoginAnomaly } = require('../services/anomaly');
const { requireAuth, requireRole, logAudit } = require('../middleware/auth');
const { otpRequestLimiter, otpVerifyLimiter } = require('../middleware/rateLimit');

const router = express.Router();

function positiveInt(value, fallback) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const OTP_EXPIRE_MIN = positiveInt(process.env.OTP_EXPIRES_MINUTES, 2);
const OTP_VERIFY_ATTEMPTS = positiveInt(process.env.OTP_VERIFY_ATTEMPTS, 4);
const MAX_ACTIVE_LOGIN_SESSIONS = positiveInt(process.env.MAX_ACTIVE_LOGIN_SESSIONS, 4);
const hasRealResendConfig =
  Boolean(process.env.RESEND_API_KEY) &&
  !process.env.RESEND_API_KEY.includes('REPLACE_WITH') &&
  Boolean(process.env.EMAIL_FROM) &&
  !process.env.EMAIL_FROM.includes('yourdomain.com');
const exposeDevOtpOverride = String(process.env.EXPOSE_DEV_OTP || '').toLowerCase();
const shouldExposeDevOtp =
  exposeDevOtpOverride === 'true'
    ? true
    : exposeDevOtpOverride === 'false'
    ? false
    : process.env.NODE_ENV !== 'production' && !hasRealResendConfig;

router.post('/request-otp', otpRequestLimiter, async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const normalizedEmail = email.toLowerCase().trim();
    const { rows } = await query(
      'SELECT id, name, email, role, is_active FROM employees WHERE email = $1',
      [normalizedEmail]
    );

    if (!rows.length || !rows[0].is_active) {
      await logAudit({
        action: 'otp_request_unknown_email',
        ip: getClientIP(req),
        success: false,
        threat: 'low',
        detail: { email: normalizedEmail },
      });
      return res.json({ message: 'If that email exists, a code has been sent.' });
    }

    const employee = rows[0];

    await query(
      `UPDATE otp_codes
       SET used = true
       WHERE employee_id = $1 AND used = false`,
      [employee.id]
    );

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + OTP_EXPIRE_MIN * 60 * 1000);
    const clientIp = getClientIP(req);

    await query(
      `INSERT INTO otp_codes (employee_id, code, expires_at, ip_address, max_attempts)
       VALUES ($1, $2, $3, $4, $5)`,
      [employee.id, code, expiresAt, clientIp, OTP_VERIFY_ATTEMPTS]
    );

    await sendOTP(employee.email, employee.name, code, OTP_EXPIRE_MIN);

    await logAudit({
      actor_id: employee.id,
      actor_role: employee.role,
      action: 'otp_requested',
      ip: clientIp,
      detail: {
        otp_expires_minutes: OTP_EXPIRE_MIN,
        verify_attempts_allowed: OTP_VERIFY_ATTEMPTS,
      },
    });

    return res.json({
      message: 'If that email exists, a code has been sent.',
      otp_expires_minutes: OTP_EXPIRE_MIN,
      verify_attempts_allowed: OTP_VERIFY_ATTEMPTS,
      active_login_slots: MAX_ACTIVE_LOGIN_SESSIONS,
      ...(shouldExposeDevOtp ? { dev_otp: code } : {}),
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/verify-otp', otpVerifyLimiter, async (req, res, next) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const normalizedCode = code.trim();
    const ip = getClientIP(req);
    const fp = buildFingerprint(req);

    const { rows: empRows } = await query(
      'SELECT * FROM employees WHERE email = $1 AND is_active = true',
      [normalizedEmail]
    );

    if (!empRows.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const employee = empRows[0];

    const { rows: otpRows } = await query(
      `SELECT *
       FROM otp_codes
       WHERE employee_id = $1
         AND used = false
         AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [employee.id]
    );

    if (!otpRows.length) {
      await logAudit({
        actor_id: employee.id,
        actor_role: employee.role,
        action: 'otp_verify_fail',
        ip,
        success: false,
        threat: 'medium',
        detail: { code_provided: normalizedCode, reason: 'expired_or_missing' },
      });
      return res.status(401).json({ error: 'Invalid or expired code' });
    }

    const latestOtp = otpRows[0];
    const attemptBudget = positiveInt(latestOtp.max_attempts, OTP_VERIFY_ATTEMPTS);

    if (latestOtp.code !== normalizedCode) {
      const attemptsUsed = positiveInt(latestOtp.attempt_count, 0) + 1;
      const attemptsLeft = Math.max(0, attemptBudget - attemptsUsed);

      await query(
        `UPDATE otp_codes
         SET attempt_count = $1,
             used = $2
         WHERE id = $3`,
        [attemptsUsed, attemptsLeft === 0, latestOtp.id]
      );

      await logAudit({
        actor_id: employee.id,
        actor_role: employee.role,
        action: 'otp_verify_fail',
        ip,
        success: false,
        threat: 'medium',
        detail: {
          code_provided: normalizedCode,
          attempts_used: attemptsUsed,
          attempts_left: attemptsLeft,
        },
      });

      return res.status(401).json({
        error: attemptsLeft > 0
          ? `Invalid code. ${attemptsLeft} attempt(s) left before you need a new OTP.`
          : 'This OTP is locked now. Please request a new code.',
        attempts_left: attemptsLeft,
      });
    }

    await query(
      `UPDATE otp_codes
       SET used = true,
           attempt_count = attempt_count + 1
       WHERE id = $1`,
      [latestOtp.id]
    );

    const sessionToken = uuidv4().replace(/-/g, '') + crypto.randomBytes(8).toString('hex');
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

    await query(
      `INSERT INTO active_sessions
         (session_token, employee_id, ip_address, device_fingerprint, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionToken, employee.id, ip, fp, req.headers['user-agent'], expiresAt]
    );

    const { rows: sessionRows } = await query(
      `SELECT id
       FROM active_sessions
       WHERE employee_id = $1 AND expires_at > NOW()
       ORDER BY issued_at DESC`,
      [employee.id]
    );

    for (const staleSession of sessionRows.slice(MAX_ACTIVE_LOGIN_SESSIONS)) {
      await query('DELETE FROM active_sessions WHERE id = $1', [staleSession.id]);
    }

    const token = jwt.sign(
      { sessionToken, empId: employee.id, role: employee.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    checkLoginAnomaly(employee, ip).catch(console.error);

    await logAudit({
      actor_id: employee.id,
      actor_role: employee.role,
      action: 'login_success',
      ip,
      fp,
      detail: {
        sessionToken: `${sessionToken.slice(0, 8)}...`,
        active_login_slots: MAX_ACTIVE_LOGIN_SESSIONS,
      },
    });

    return res.json({
      token,
      login_policy: {
        active_login_slots: MAX_ACTIVE_LOGIN_SESSIONS,
        otp_attempts_per_code: attemptBudget,
      },
      employee: {
        id: employee.id,
        empCode: employee.emp_code,
        name: employee.name,
        email: employee.email,
        role: employee.role,
        department: employee.department,
      },
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    await query('DELETE FROM active_sessions WHERE session_token = $1', [req.user.sessionToken]);

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'logout',
      ip: getClientIP(req),
    });

    return res.json({ message: 'Logged out successfully' });
  } catch (err) {
    return next(err);
  }
});

router.post('/register', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { name, email, department, role } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email required' });

    const allowedRoles = ['employee', 'manager', 'admin'];
    const empRole = allowedRoles.includes(role) ? role : 'employee';

    const { rows: countRows } = await query('SELECT COUNT(*) FROM employees');
    const empCode = `EMP-${String(parseInt(countRows[0].count, 10) + 1001).padStart(4, '0')}`;

    const { rows } = await query(
      `INSERT INTO employees (emp_code, name, email, department, role, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, emp_code, name, email, department, role`,
      [empCode, name, email.toLowerCase().trim(), department, empRole, req.user.id]
    );

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'employee_registered',
      table: 'employees',
      target_id: rows[0].id,
      ip: getClientIP(req),
      detail: { empCode, email, role: empRole },
    });

    return res.status(201).json({ employee: rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    return next(err);
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ employee: req.user });
});

module.exports = router;
