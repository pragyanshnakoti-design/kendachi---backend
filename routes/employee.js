const crypto = require('crypto');
const express = require('express');

const router = express.Router();
const { query } = require('../db');
const { requireAuth, logAudit } = require('../middleware/auth');
const { getClientIP } = require('../services/fingerprint');

router.get('/records', requireAuth, async (req, res, next) => {
  try {
    const { from, to, page = 1, limit = 30 } = req.query;
    const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    let dateFilter = '';
    const params = [req.user.id, parseInt(limit, 10), offset];

    if (from && to) {
      dateFilter = ' AND login_time BETWEEN $4 AND $5';
      params.push(from, to);
    }

    const { rows } = await query(
      `SELECT id, login_time, logout_time, total_seconds, regular_seconds,
              overtime_seconds, is_overtime, auto_closed, auto_close_reason,
              notes, closed, activity_events, idle_seconds, hidden_seconds,
              focus_loss_count, presence_passes, presence_failures, monitoring_score
       FROM work_sessions
       WHERE employee_id = $1 ${dateFilter}
       ORDER BY login_time DESC
       LIMIT $2 OFFSET $3`,
      params
    );

    const { rows: stats } = await query(
      `SELECT
         COUNT(*) as total_sessions,
         SUM(total_seconds) as total_seconds_all,
         SUM(overtime_seconds) as total_overtime_seconds,
         SUM(CASE WHEN is_overtime THEN 1 ELSE 0 END) as overtime_days
       FROM work_sessions
       WHERE employee_id = $1 AND closed = true`,
      [req.user.id]
    );

    res.json({
      sessions: rows,
      summary: stats[0],
      pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10) },
    });
  } catch (err) {
    next(err);
  }
});

router.get('/records/:id', requireAuth, async (req, res, next) => {
  try {
    const sessionId = parseInt(req.params.id, 10);

    const { rows: wsRows } = await query(
      `SELECT ws.*, e.name, e.emp_code, e.department
       FROM work_sessions ws
       JOIN employees e ON e.id = ws.employee_id
       WHERE ws.id = $1 AND ws.employee_id = $2`,
      [sessionId, req.user.id]
    );

    if (!wsRows.length) {
      return res.status(404).json({ error: 'Record not found or access denied' });
    }

    const { rows: otRows } = await query(
      `SELECT status, reason, estimated_hours, manager_note, admin_decision, requested_at, reviewed_at
       FROM overtime_requests WHERE work_session_id = $1`,
      [sessionId]
    );

    const { rows: correctionRows } = await query(
      `SELECT c.id, c.field_changed, c.old_value, c.new_value, c.reason_code,
              c.reason, c.status, c.applied, c.created_at, c.reviewed_at,
              proposer.name AS proposer_name, reviewer.name AS reviewer_name
       FROM corrections c
       JOIN employees proposer ON proposer.id = c.corrected_by
       LEFT JOIN employees reviewer ON reviewer.id = c.second_admin_id
       WHERE c.work_session_id = $1
       ORDER BY c.created_at DESC`,
      [sessionId]
    );

    const { rows: proofRows } = await query(
      `SELECT anchor_type, record_hash, merkle_root, provider, provider_ref,
              status, requested_at, anchored_at
       FROM proof_anchors
       WHERE work_session_id = $1
       ORDER BY requested_at DESC`,
      [sessionId]
    );

    res.json({
      session: wsRows[0],
      overtime_requests: otRows,
      correction_trail: correctionRows,
      proof_anchors: proofRows,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/export', requireAuth, async (req, res, next) => {
  try {
    const { from, to } = req.query;
    const ip = getClientIP(req);

    const params = [req.user.id];
    let dateFilter = '';
    if (from && to) {
      dateFilter = ' AND ws.login_time BETWEEN $2 AND $3';
      params.push(from, to);
    }

    const { rows } = await query(
      `SELECT ws.id, ws.login_time, ws.logout_time, ws.total_seconds,
              ws.regular_seconds, ws.overtime_seconds, ws.is_overtime,
              ws.auto_closed, ws.auto_close_reason, ws.notes, ws.activity_events,
              ws.idle_seconds, ws.hidden_seconds, ws.focus_loss_count,
              ws.presence_passes, ws.presence_failures, ws.monitoring_score,
              e.emp_code, e.name, e.department, e.email
       FROM work_sessions ws
       JOIN employees e ON e.id = ws.employee_id
       WHERE ws.employee_id = $1 AND ws.closed = true ${dateFilter}
       ORDER BY ws.login_time DESC`,
      params
    );

    const { rows: correctionRows } = await query(
      `SELECT c.work_session_id, c.field_changed, c.old_value, c.new_value,
              c.reason_code, c.reason, c.status, c.applied, c.created_at,
              c.reviewed_at, proposer.name AS proposer_name, reviewer.name AS reviewer_name
       FROM corrections c
       JOIN work_sessions ws ON ws.id = c.work_session_id
       JOIN employees proposer ON proposer.id = c.corrected_by
       LEFT JOIN employees reviewer ON reviewer.id = c.second_admin_id
       WHERE ws.employee_id = $1
       ORDER BY c.created_at DESC`,
      [req.user.id]
    );

    const { rows: proofRows } = await query(
      `SELECT pa.work_session_id, pa.anchor_type, pa.record_hash, pa.merkle_root,
              pa.provider, pa.provider_ref, pa.status, pa.requested_at, pa.anchored_at
       FROM proof_anchors pa
       JOIN work_sessions ws ON ws.id = pa.work_session_id
       WHERE ws.employee_id = $1
       ORDER BY pa.requested_at DESC`,
      [req.user.id]
    );

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'employee_export',
      ip,
      detail: { session_count: rows.length, correction_count: correctionRows.length, from, to },
    });

    const payload = {
      generated_at: new Date().toISOString(),
      generated_by: `${req.user.empCode} - ${req.user.name}`,
      watermark: req.user.empCode,
      promise: 'Every hour is accounted for, and every correction leaves a permanent trail.',
      record_count: rows.length,
      sessions: rows,
      correction_trail: correctionRows,
      proof_anchors: proofRows,
    };

    payload.integrity_hash = crypto
      .createHash('sha256')
      .update(JSON.stringify({
        sessions: payload.sessions,
        correction_trail: payload.correction_trail,
        proof_anchors: payload.proof_anchors,
      }))
      .digest('hex');
    payload.note = 'Export includes session totals, correction trail, and proof-anchor status for verifiable dispute review.';

    res.json(payload);
  } catch (err) {
    next(err);
  }
});

router.get('/today', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, login_time, logout_time, total_seconds, regular_seconds,
              overtime_seconds, is_overtime, closed, auto_closed, auto_close_reason,
              activity_events, idle_seconds, hidden_seconds, focus_loss_count,
              presence_passes, presence_failures, monitoring_score
       FROM work_sessions
       WHERE employee_id = $1
         AND login_time::date = CURRENT_DATE
       ORDER BY login_time DESC
       LIMIT 1`,
      [req.user.id]
    );

    res.json({ today: rows[0] || null });
  } catch (err) {
    next(err);
  }
});

router.get('/notifications', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, type, title, message, detail, read, created_at
       FROM employee_notifications
       WHERE employee_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    res.json({ notifications: rows });
  } catch (err) {
    next(err);
  }
});

router.post('/disputes', requireAuth, async (req, res, next) => {
  try {
    const { work_session_id, dispute_type = 'hours_dispute', employee_statement } = req.body;
    if (!work_session_id || !employee_statement) {
      return res.status(400).json({ error: 'work_session_id and employee_statement required' });
    }

    const { rows: sessionRows } = await query(
      `SELECT id
       FROM work_sessions
       WHERE id = $1 AND employee_id = $2`,
      [work_session_id, req.user.id]
    );
    if (!sessionRows.length) return res.status(404).json({ error: 'Work session not found' });

    const { rows } = await query(
      `INSERT INTO dispute_tickets
         (work_session_id, employee_id, opened_by, dispute_type, employee_statement)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [work_session_id, req.user.id, req.user.id, dispute_type, employee_statement]
    );

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'dispute_ticket_created',
      table: 'dispute_tickets',
      target_id: rows[0].id,
      ip: getClientIP(req),
      detail: { work_session_id, dispute_type },
    });

    res.status(201).json({ dispute: rows[0] });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
