const { query } = require('../db');
const { sendAnomalyAlert } = require('./email');

const WORK_START_HOUR = 6;   // 6 AM earliest normal login
const WORK_END_HOUR   = 22;  // 10 PM latest normal logout
const MAX_DAILY_HOURS = 16;  // flag if session > 16h
const IMPOSSIBLE_TRAVEL_KM = 500; // not used (no geo), but reserved

// ─── Check login time ───────────────────────────────────────
async function checkLoginAnomaly(employee, ipAddress) {
  const hour = new Date().getHours();
  const flags = [];

  // Odd-hours check
  if (hour < WORK_START_HOUR || hour >= WORK_END_HOUR) {
    flags.push({
      type: 'odd_hours_login',
      description: `Login at ${hour}:00 — outside normal working hours (${WORK_START_HOUR}:00–${WORK_END_HOUR}:00)`,
      severity: 'medium',
    });
  }

  // Weekend check (0 = Sunday, 6 = Saturday)
  const day = new Date().getDay();
  if (day === 0 || day === 6) {
    flags.push({
      type: 'weekend_login',
      description: `Login on ${day === 0 ? 'Sunday' : 'Saturday'} — flagged for admin awareness`,
      severity: 'low',
    });
  }

  // Multiple failed OTP attempts in last 10 minutes
  const { rows: failedOTPs } = await query(
    `SELECT COUNT(*) as cnt FROM audit_log
     WHERE actor_id = $1
       AND action = 'otp_verify_fail'
       AND recorded_at > NOW() - INTERVAL '10 minutes'`,
    [employee.id]
  );
  if (parseInt(failedOTPs[0].cnt) >= 3) {
    flags.push({
      type: 'brute_force_otp',
      description: `${failedOTPs[0].cnt} failed OTP attempts in last 10 minutes`,
      severity: 'high',
    });
  }

  await persistFlags(employee, flags, ipAddress);
  return flags;
}

// ─── Check session length ───────────────────────────────────
async function checkSessionAnomaly(employee, workSessionId, totalSeconds) {
  const totalHours = totalSeconds / 3600;
  const flags = [];

  if (totalHours > MAX_DAILY_HOURS) {
    flags.push({
      type: 'excessive_hours',
      description: `Session duration ${totalHours.toFixed(1)}h exceeds ${MAX_DAILY_HOURS}h daily limit`,
      severity: 'high',
    });
  } else if (totalHours > 12) {
    flags.push({
      type: 'long_session',
      description: `Session duration ${totalHours.toFixed(1)}h — extended work day`,
      severity: 'medium',
    });
  }

  await persistFlags(employee, flags, null, workSessionId);
  return flags;
}

// ─── Persist flags and notify admins ───────────────────────
async function persistFlags(employee, flags, ipAddress, workSessionId = null) {
  if (!flags.length) return;

  for (const flag of flags) {
    await query(
      `INSERT INTO anomaly_flags
         (employee_id, flag_type, description, severity, metadata)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        employee.id,
        flag.type,
        flag.description,
        flag.severity,
        JSON.stringify({ ip: ipAddress, work_session_id: workSessionId }),
      ]
    );

    // Alert admins for high/critical
    if (flag.severity === 'high' || flag.severity === 'critical') {
      const { rows: admins } = await query(
        `SELECT email FROM employees WHERE role = 'admin' AND is_active = true`
      );
      for (const admin of admins) {
        try {
          await sendAnomalyAlert(admin.email, employee.name, flag.type, flag.description);
        } catch (e) {
          console.error('[ANOMALY] Email send failed:', e.message);
        }
      }
    }
  }
}

module.exports = { checkLoginAnomaly, checkSessionAnomaly };
