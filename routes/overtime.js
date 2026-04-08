const express = require('express');
const router  = express.Router();
const { query } = require('../db');
const { requireAuth, requireRole, logAudit } = require('../middleware/auth');
const { sendOTNotification } = require('../services/email');
const { getClientIP } = require('../services/fingerprint');

// ─── POST /api/overtime/request ─────────────────────────────
// Employee submits OT request for current/recent session.
router.post('/request', requireAuth, async (req, res, next) => {
  try {
    const { work_session_id, reason, estimated_hours } = req.body;

    if (!work_session_id || !reason) {
      return res.status(400).json({ error: 'work_session_id and reason required' });
    }

    // Verify session belongs to this employee
    const { rows: sessionRows } = await query(
      `SELECT id FROM work_sessions
       WHERE id = $1 AND employee_id = $2`,
      [work_session_id, req.user.id]
    );

    if (!sessionRows.length) {
      return res.status(404).json({ error: 'Work session not found' });
    }

    // Prevent duplicate requests for same session
    const { rows: existing } = await query(
      `SELECT id FROM overtime_requests
       WHERE work_session_id = $1 AND status = 'pending'`,
      [work_session_id]
    );

    if (existing.length) {
      return res.status(409).json({ error: 'Overtime request already pending for this session' });
    }

    const { rows } = await query(
      `INSERT INTO overtime_requests
         (work_session_id, employee_id, reason, estimated_hours)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [work_session_id, req.user.id, reason, estimated_hours || null]
    );

    // Notify all admins (not managers — manager sees it in dashboard but cannot approve)
    const { rows: admins } = await query(
      `SELECT email FROM employees WHERE role = 'admin' AND is_active = true`
    );

    for (const admin of admins) {
      try {
        await sendOTNotification(admin.email, req.user.name, reason, estimated_hours || 'unspecified');
      } catch (e) {
        console.error('[OT] Email notify failed:', e.message);
      }
    }

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'overtime_requested',
      table: 'overtime_requests',
      target_id: rows[0].id,
      ip: getClientIP(req),
      detail: { reason, estimated_hours },
    });

    res.status(201).json({
      message: 'Overtime request submitted — admin will review',
      request: rows[0],
    });
  } catch (err) {
    next(err);
  }
});

// ─── POST /api/overtime/:id/comment ─────────────────────────
// Manager adds a note — cannot approve or reject, view+comment only.
router.post('/:id/comment', requireAuth, requireRole('manager', 'admin'), async (req, res, next) => {
  try {
    const { note } = req.body;
    const otId = parseInt(req.params.id);

    if (!note) return res.status(400).json({ error: 'Note required' });

    // Managers can add a note but cannot change status
    await query(
      `UPDATE overtime_requests SET manager_note = $1 WHERE id = $2`,
      [note, otId]
    );

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'overtime_manager_comment',
      table: 'overtime_requests',
      target_id: otId,
      ip: getClientIP(req),
      detail: { note },
    });

    res.json({ message: 'Comment saved' });
  } catch (err) {
    next(err);
  }
});

// ─── POST /api/overtime/:id/decide ──────────────────────────
// Admin only — approve or reject OT request.
router.post('/:id/decide', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { decision, admin_note } = req.body;
    const otId = parseInt(req.params.id);

    if (!['approved', 'rejected'].includes(decision)) {
      return res.status(400).json({ error: 'decision must be approved or rejected' });
    }

    const { rows } = await query(
      `UPDATE overtime_requests SET
         status        = $1,
         admin_decision = $2,
         reviewed_by   = $3,
         reviewed_at   = NOW()
       WHERE id = $4
       RETURNING *`,
      [decision, admin_note || null, req.user.id, otId]
    );

    if (!rows.length) return res.status(404).json({ error: 'Request not found' });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: `overtime_${decision}`,
      table: 'overtime_requests',
      target_id: otId,
      ip: getClientIP(req),
      detail: { decision, admin_note },
    });

    res.json({ message: `Overtime ${decision}`, request: rows[0] });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/overtime/my ───────────────────────────────────
// Employee views their own OT requests.
router.get('/my', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT r.*, ws.login_time, ws.logout_time
       FROM overtime_requests r
       JOIN work_sessions ws ON ws.id = r.work_session_id
       WHERE r.employee_id = $1
       ORDER BY r.requested_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json({ requests: rows });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/overtime/pending ──────────────────────────────
// Admin sees all pending OT requests.
router.get('/pending', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT r.*, e.name as employee_name, e.emp_code,
              e.department, ws.login_time, ws.total_seconds
       FROM overtime_requests r
       JOIN employees e  ON e.id  = r.employee_id
       JOIN work_sessions ws ON ws.id = r.work_session_id
       WHERE r.status = 'pending'
       ORDER BY r.requested_at ASC`
    );
    res.json({ requests: rows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
