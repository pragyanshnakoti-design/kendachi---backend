const express = require('express');
const router  = express.Router();
const { query } = require('../db');
const { requireAuth, requireRole, logAudit } = require('../middleware/auth');
const { getClientIP } = require('../services/fingerprint');
const { REASON_CODES, proposeCorrection } = require('../services/governance');

// All manager routes require manager OR admin role.
router.use(requireAuth, requireRole('manager', 'admin'));

// ─── GET /api/manager/employees ─────────────────────────────
// See all active employees — no salary, no personal data beyond name/dept.
router.get('/employees', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, emp_code, name, department, role, is_active
       FROM employees
       ORDER BY name ASC`
    );
    res.json({ employees: rows });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/manager/hours ──────────────────────────────────
// View all employees' hours for a given date range. READ ONLY.
router.get('/hours', async (req, res, next) => {
  try {
    const { from, to, employee_id } = req.query;

    let filter = '';
    const params = [];
    if (from && to) {
      params.push(from, to);
      filter += ` AND ws.login_time BETWEEN $${params.length - 1} AND $${params.length}`;
    }
    if (employee_id) {
      params.push(employee_id);
      filter += ` AND ws.employee_id = $${params.length}`;
    }

    const { rows } = await query(
      `SELECT ws.id, ws.login_time, ws.logout_time, ws.total_seconds,
              ws.regular_seconds, ws.overtime_seconds, ws.is_overtime,
              ws.auto_closed, ws.auto_close_reason, ws.closed,
              ws.hidden_seconds, ws.focus_loss_count, ws.presence_failures,
              ws.monitoring_score,
              e.emp_code, e.name, e.department
       FROM work_sessions ws
       JOIN employees e ON e.id = ws.employee_id
       WHERE 1=1 ${filter}
       ORDER BY ws.login_time DESC
       LIMIT 200`,
      params
    );

    // Log the access — managers can view, but viewing is tracked
    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'manager_view_hours',
      ip: getClientIP(req),
      detail: { from, to, employee_id: employee_id || 'all', result_count: rows.length },
    });

    res.json({ sessions: rows });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/manager/overtime-queue ────────────────────────
// Manager can see pending OT requests and add a comment.
// Cannot approve — admin only.
router.get('/overtime-queue', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT r.id, r.reason, r.estimated_hours, r.status, r.manager_note,
              r.requested_at, e.name, e.emp_code, e.department,
              ws.login_time, ws.total_seconds
       FROM overtime_requests r
       JOIN employees e  ON e.id  = r.employee_id
       JOIN work_sessions ws ON ws.id = r.work_session_id
       ORDER BY r.requested_at DESC
       LIMIT 100`
    );

    res.json({ requests: rows });
  } catch (err) {
    next(err);
  }
});

// ─── BLOCK: no edit routes exist for manager ─────────────────
// Any attempt to POST/PATCH/DELETE work_sessions data returns 403.
// This is enforced via missing routes + requireRole on admin routes.

router.post('/corrections/propose', async (req, res, next) => {
  try {
    const { work_session_id, field_changed, new_value, reason_code, reason } = req.body;
    const result = await proposeCorrection({
      workSessionId: work_session_id,
      fieldChanged: field_changed,
      newValue: new_value,
      reasonCode: reason_code,
      reason,
      proposer: req.user,
    });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'manager_correction_proposed',
      table: 'work_sessions',
      target_id: work_session_id,
      ip: getClientIP(req),
      detail: {
        correction_id: result.correction.id,
        field_changed,
        old_value: result.oldValue,
        new_value,
        reason_code: result.reasonCode,
        governance: 'admin_review_required',
      },
    });

    res.status(201).json({
      correction: result.correction,
      message: 'Correction proposed. Admin/HR approval is required before it is accepted.',
      reason_codes: REASON_CODES,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

module.exports = router;
