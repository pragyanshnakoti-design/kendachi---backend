const express = require('express');
const router  = express.Router();
const { query, transaction } = require('../db');
const { requireAuth, requireRole, logAudit } = require('../middleware/auth');
const { getClientIP } = require('../services/fingerprint');

// All admin routes require admin role — no exceptions.
router.use(requireAuth, requireRole('admin'));

// ─── GET /api/admin/dashboard ───────────────────────────────
// High-level stats for today.
router.get('/dashboard', async (req, res, next) => {
  try {
    const { rows: stats } = await query(`
      SELECT
        (SELECT COUNT(*) FROM employees WHERE is_active = true)              AS total_employees,
        (SELECT COUNT(*) FROM work_sessions WHERE login_time::date = CURRENT_DATE) AS sessions_today,
        (SELECT COUNT(*) FROM work_sessions WHERE closed = false)            AS currently_active,
        (SELECT COUNT(*) FROM overtime_requests WHERE status = 'pending')   AS pending_ot,
        (SELECT COUNT(*) FROM anomaly_flags WHERE resolved = false)         AS unresolved_flags,
        (SELECT COUNT(*) FROM work_sessions WHERE monitoring_score < 70 AND login_time::date = CURRENT_DATE) AS monitoring_alerts
    `);

    res.json({ stats: stats[0] });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/admin/records ─────────────────────────────────
// All work sessions — full access.
router.get('/records', async (req, res, next) => {
  try {
    const { from, to, employee_id, page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const params = [parseInt(limit), offset];

    let filter = '';
    if (from && to) {
      params.push(from, to);
      filter += ` AND ws.login_time BETWEEN $${params.length - 1} AND $${params.length}`;
    }
    if (employee_id) {
      params.push(employee_id);
      filter += ` AND ws.employee_id = $${params.length}`;
    }

    const { rows } = await query(
      `SELECT ws.*, e.emp_code, e.name, e.department, e.role
       FROM work_sessions ws
       JOIN employees e ON e.id = ws.employee_id
       WHERE 1=1 ${filter}
       ORDER BY ws.login_time DESC
       LIMIT $1 OFFSET $2`,
      params
    );

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'admin_view_records',
      ip: getClientIP(req),
      detail: { from, to, employee_id: employee_id || 'all' },
    });

    res.json({ sessions: rows });
  } catch (err) {
    next(err);
  }
});

// ─── POST /api/admin/correct ────────────────────────────────
// Admin submits a correction. Original row NEVER changes.
// Correction is appended as a new row with reason + before/after values.
router.post('/correct', async (req, res, next) => {
  try {
    const { work_session_id, field_changed, new_value, reason } = req.body;

    if (!work_session_id || !field_changed || !new_value || !reason) {
      return res.status(400).json({ error: 'work_session_id, field_changed, new_value, reason all required' });
    }

    // Only these fields are correctable — prevents abuse
    const CORRECTABLE = ['logout_time', 'login_time', 'notes'];
    if (!CORRECTABLE.includes(field_changed)) {
      return res.status(400).json({
        error: `Field '${field_changed}' cannot be corrected. Allowed: ${CORRECTABLE.join(', ')}`,
      });
    }

    // Get current value before correction
    const { rows: wsRows } = await query(
      `SELECT * FROM work_sessions WHERE id = $1`,
      [work_session_id]
    );
    if (!wsRows.length) return res.status(404).json({ error: 'Work session not found' });

    const oldValue = String(wsRows[0][field_changed] ?? '');

    // Log correction (immutable — never update work_sessions rows for time fields)
    const { rows: corrRows } = await query(
      `INSERT INTO corrections
         (work_session_id, corrected_by, field_changed, old_value, new_value, reason, applied)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING *`,
      [work_session_id, req.user.id, field_changed, oldValue, new_value, reason]
    );

    // Only 'notes' is directly updated on the row — time fields are kept as correction records
    if (field_changed === 'notes') {
      await query(
        'UPDATE work_sessions SET notes = $1 WHERE id = $2',
        [new_value, work_session_id]
      );
    }

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'admin_correction',
      table: 'work_sessions',
      target_id: work_session_id,
      ip: getClientIP(req),
      detail: { field_changed, old_value: oldValue, new_value, reason },
    });

    res.status(201).json({ correction: corrRows[0] });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/admin/audit-log ───────────────────────────────
// Full audit trail — every action ever taken in the system.
router.get('/audit-log', async (req, res, next) => {
  try {
    const { from, to, actor_id, action, page = 1 } = req.query;
    const limit  = 100;
    const offset = (parseInt(page) - 1) * limit;
    const params = [limit, offset];
    let filter = '';

    if (from && to) {
      params.push(from, to);
      filter += ` AND al.recorded_at BETWEEN $${params.length - 1} AND $${params.length}`;
    }
    if (actor_id) {
      params.push(actor_id);
      filter += ` AND al.actor_id = $${params.length}`;
    }
    if (action) {
      params.push(`%${action}%`);
      filter += ` AND al.action ILIKE $${params.length}`;
    }

    const { rows } = await query(
      `SELECT al.*, e.name as actor_name, e.emp_code
       FROM audit_log al
       LEFT JOIN employees e ON e.id = al.actor_id
       WHERE 1=1 ${filter}
       ORDER BY al.recorded_at DESC
       LIMIT $1 OFFSET $2`,
      params
    );

    res.json({ logs: rows });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/admin/anomalies ───────────────────────────────
router.get('/anomalies', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT af.*, e.name, e.emp_code, e.department
       FROM anomaly_flags af
       JOIN employees e ON e.id = af.employee_id
       ORDER BY af.flagged_at DESC
       LIMIT 200`
    );
    res.json({ anomalies: rows });
  } catch (err) {
    next(err);
  }
});

// ─── POST /api/admin/anomalies/:id/resolve ──────────────────
router.post('/anomalies/:id/resolve', async (req, res, next) => {
  try {
    const { rows } = await query(
      `UPDATE anomaly_flags
       SET resolved = true, resolved_by = $1, resolved_at = NOW()
       WHERE id = $2 RETURNING *`,
      [req.user.id, parseInt(req.params.id)]
    );

    if (!rows.length) return res.status(404).json({ error: 'Flag not found' });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'anomaly_resolved',
      table: 'anomaly_flags',
      target_id: parseInt(req.params.id),
      ip: getClientIP(req),
    });

    res.json({ resolved: rows[0] });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/admin/export-full ─────────────────────────────
// Full org export — admin only, every action logged with admin watermark.
router.get('/export-full', async (req, res, next) => {
  try {
    const { from, to } = req.query;
    const crypto = require('crypto');
    const params = [];
    let filter = '';
    if (from && to) {
      params.push(from, to);
      filter = 'WHERE ws.login_time BETWEEN $1 AND $2';
    }

    const { rows } = await query(
      `SELECT ws.*, e.emp_code, e.name, e.department
       FROM work_sessions ws
       JOIN employees e ON e.id = ws.employee_id
       ${filter}
       ORDER BY ws.employee_id, ws.login_time`,
      params
    );

    const payload = {
      generated_at:  new Date().toISOString(),
      generated_by:  `${req.user.empCode} — ${req.user.name} [ADMIN]`,
      watermark:     `ADMIN:${req.user.empCode}`,
      record_count:  rows.length,
      sessions:      rows,
      integrity_hash: crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex'),
    };

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'admin_full_export',
      ip: getClientIP(req),
      detail: { record_count: rows.length, from, to },
    });

    res.json(payload);
  } catch (err) {
    next(err);
  }
});

// ─── DELETE /api/admin/employees/:id/deactivate ─────────────
// Soft delete — never hard-delete, records must stay.
router.post('/employees/:id/deactivate', async (req, res, next) => {
  try {
    const empId = parseInt(req.params.id);
    if (empId === req.user.id) {
      return res.status(400).json({ error: 'Cannot deactivate yourself' });
    }

    await query(
      'UPDATE employees SET is_active = false WHERE id = $1',
      [empId]
    );

    // Kill active sessions
    await query('DELETE FROM active_sessions WHERE employee_id = $1', [empId]);

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'employee_deactivated',
      table: 'employees',
      target_id: empId,
      ip: getClientIP(req),
    });

    res.json({ message: 'Employee deactivated. Records preserved.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
