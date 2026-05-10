const { query } = require('../db');
const { createSessionAnchor } = require('./proof');

const CORRECTABLE_FIELDS = ['logout_time', 'login_time', 'notes'];
const REASON_CODES = [
  'employee_forgot_clock_out',
  'system_error',
  'approved_schedule_change',
  'network_sync_issue',
  'duplicate_session_cleanup',
  'manager_dispute',
  'employee_dispute',
  'other',
];
const REGULAR_LIMIT_SEC = Math.round((parseFloat(process.env.REGULAR_HOURS_LIMIT) || 0.0167) * 3600);

function normalizeReasonCode(code) {
  return REASON_CODES.includes(code) ? code : 'other';
}

async function notifyEmployee(employeeId, type, title, message, detail = {}) {
  await query(
    `INSERT INTO employee_notifications (employee_id, type, title, message, detail)
     VALUES ($1, $2, $3, $4, $5)`,
    [employeeId, type, title, message, JSON.stringify(detail)]
  );
}

async function getWorkSession(workSessionId) {
  const { rows } = await query(
    `SELECT ws.*, e.name, e.email, e.emp_code
     FROM work_sessions ws
     JOIN employees e ON e.id = ws.employee_id
     WHERE ws.id = $1`,
    [workSessionId]
  );
  return rows[0] || null;
}

async function proposeCorrection({ workSessionId, fieldChanged, newValue, reasonCode, reason, proposer }) {
  if (!workSessionId || !fieldChanged || !newValue || !reason) {
    const err = new Error('work_session_id, field_changed, new_value, and reason are required');
    err.status = 400;
    throw err;
  }

  if (!CORRECTABLE_FIELDS.includes(fieldChanged)) {
    const err = new Error(`Field '${fieldChanged}' cannot be corrected. Allowed: ${CORRECTABLE_FIELDS.join(', ')}`);
    err.status = 400;
    throw err;
  }

  const workSession = await getWorkSession(workSessionId);
  if (!workSession) {
    const err = new Error('Work session not found');
    err.status = 404;
    throw err;
  }

  const oldValue = String(workSession[fieldChanged] ?? '');
  const cleanReasonCode = normalizeReasonCode(reasonCode);

  const { rows } = await query(
    `INSERT INTO corrections
       (work_session_id, corrected_by, field_changed, old_value, new_value,
        reason_code, reason, requires_second_admin, applied, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, true, false, 'pending')
     RETURNING *`,
    [workSessionId, proposer.id, fieldChanged, oldValue, newValue, cleanReasonCode, reason]
  );

  const correction = rows[0];
  await notifyEmployee(
    workSession.employee_id,
    'correction_proposed',
    'Time record correction proposed',
    `A correction was proposed for ${fieldChanged}. Reason code: ${cleanReasonCode}.`,
    { correction_id: correction.id, work_session_id: workSessionId, field_changed: fieldChanged, old_value: oldValue, new_value: newValue }
  );

  await runCorrectionPatternDetection(workSession.employee_id, proposer.id);
  return { correction, workSession, oldValue, reasonCode: cleanReasonCode };
}

async function reviewCorrection({ correctionId, reviewer, decision, comment }) {
  if (!['approved', 'rejected'].includes(decision)) {
    const err = new Error('decision must be approved or rejected');
    err.status = 400;
    throw err;
  }

  const { rows } = await query(
    `SELECT c.*, ws.employee_id
     FROM corrections c
     JOIN work_sessions ws ON ws.id = c.work_session_id
     WHERE c.id = $1`,
    [correctionId]
  );

  if (!rows.length) {
    const err = new Error('Correction not found');
    err.status = 404;
    throw err;
  }

  const correction = rows[0];
  if (correction.status !== 'pending') {
    const err = new Error(`Correction already ${correction.status}`);
    err.status = 409;
    throw err;
  }

  if (parseInt(correction.corrected_by, 10) === parseInt(reviewer.id, 10)) {
    const err = new Error('Second approval must come from a different person');
    err.status = 403;
    throw err;
  }

  const { rows: updated } = await query(
    `UPDATE corrections
     SET status = $1,
         applied = $2,
         second_admin_id = $3,
         reviewed_at = NOW()
     WHERE id = $4
     RETURNING *`,
    [decision, decision === 'approved', reviewer.id, correctionId]
  );

  if (decision === 'approved' && correction.field_changed === 'notes') {
    await query(
      'UPDATE work_sessions SET notes = $1 WHERE id = $2',
      [correction.new_value, correction.work_session_id]
    );
  }

  if (decision === 'approved' && ['login_time', 'logout_time'].includes(correction.field_changed)) {
    await query(
      `UPDATE work_sessions
       SET ${correction.field_changed} = $1
       WHERE id = $2`,
      [correction.new_value, correction.work_session_id]
    );

    const { rows: wsRows } = await query(
      `SELECT login_time, logout_time
       FROM work_sessions
       WHERE id = $1`,
      [correction.work_session_id]
    );

    const ws = wsRows[0];
    if (ws?.login_time && ws?.logout_time) {
      const totalSeconds = Math.max(0, Math.floor((new Date(ws.logout_time) - new Date(ws.login_time)) / 1000));
      const regularSeconds = Math.min(totalSeconds, REGULAR_LIMIT_SEC);
      const overtimeSeconds = Math.max(0, totalSeconds - REGULAR_LIMIT_SEC);
      await query(
        `UPDATE work_sessions
         SET total_seconds = $1,
             regular_seconds = $2,
             overtime_seconds = $3,
             is_overtime = $4
         WHERE id = $5`,
        [totalSeconds, regularSeconds, overtimeSeconds, overtimeSeconds > 0, correction.work_session_id]
      );
    }
  }

  if (decision === 'approved') {
    await createSessionAnchor(correction.work_session_id, 'correction_approved').catch((err) => {
      console.error('[PROOF] Correction anchor failed:', err.message);
    });
  }

  await notifyEmployee(
    correction.employee_id,
    `correction_${decision}`,
    `Time record correction ${decision}`,
    `A correction for ${correction.field_changed} was ${decision}. Original record remains preserved.`,
    { correction_id: correction.id, work_session_id: correction.work_session_id, decision, comment: comment || null }
  );

  return updated[0];
}

async function runCorrectionPatternDetection(employeeId, actorId) {
  const { rows: repeatRows } = await query(
    `SELECT COUNT(*) AS cnt
     FROM corrections c
     JOIN work_sessions ws ON ws.id = c.work_session_id
     WHERE ws.employee_id = $1
       AND c.corrected_by = $2
       AND c.created_at > NOW() - INTERVAL '30 days'`,
    [employeeId, actorId]
  );

  if (parseInt(repeatRows[0].cnt, 10) >= 4) {
    await insertPatternFlag(
      employeeId,
      'repeated_corrections_by_same_actor',
      'high',
      `Same reviewer proposed ${repeatRows[0].cnt} corrections for this employee in the last 30 days.`,
      { actor_id: actorId, count: parseInt(repeatRows[0].cnt, 10) }
    );
  }

  const { rows: correctionDates } = await query(
    `SELECT created_at
     FROM corrections
     WHERE created_at > NOW() - INTERVAL '30 days'`
  );
  const fridayCount = correctionDates.filter(row => new Date(row.created_at).getDay() === 5).length;

  if (fridayCount >= 5) {
    await insertPatternFlag(
      employeeId,
      'friday_correction_spike',
      'medium',
      `${fridayCount} corrections were proposed on Fridays in the last 30 days.`,
      { count: fridayCount, window_days: 30 }
    );
  }
}

async function insertPatternFlag(employeeId, flagType, severity, description, metadata) {
  const { rows } = await query(
    `SELECT id
     FROM anomaly_flags
     WHERE employee_id = $1
       AND flag_type = $2
       AND resolved = false
     LIMIT 1`,
    [employeeId, flagType]
  );
  if (rows.length) return;

  await query(
    `INSERT INTO anomaly_flags (employee_id, flag_type, description, severity, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [employeeId, flagType, description, severity, JSON.stringify(metadata || {})]
  );
}

async function getPatternAlerts() {
  const { rows: repeated } = await query(
    `SELECT c.corrected_by, actor.name AS actor_name, ws.employee_id, e.name AS employee_name,
            COUNT(*) AS correction_count
     FROM corrections c
     JOIN work_sessions ws ON ws.id = c.work_session_id
     JOIN employees e ON e.id = ws.employee_id
     JOIN employees actor ON actor.id = c.corrected_by
     WHERE c.created_at > NOW() - INTERVAL '30 days'
     GROUP BY c.corrected_by, actor.name, ws.employee_id, e.name
     HAVING COUNT(*) >= 3
     ORDER BY correction_count DESC
     LIMIT 20`
  );

  const { rows: pending } = await query(
    `SELECT c.id, c.field_changed, c.reason_code, c.created_at,
            e.name AS employee_name, actor.name AS proposer_name
     FROM corrections c
     JOIN work_sessions ws ON ws.id = c.work_session_id
     JOIN employees e ON e.id = ws.employee_id
     JOIN employees actor ON actor.id = c.corrected_by
     WHERE c.status = 'pending'
     ORDER BY c.created_at DESC
     LIMIT 50`
  );

  return { repeated_corrections: repeated, pending_corrections: pending };
}

module.exports = {
  CORRECTABLE_FIELDS,
  REASON_CODES,
  notifyEmployee,
  proposeCorrection,
  reviewCorrection,
  runCorrectionPatternDetection,
  getPatternAlerts,
};
