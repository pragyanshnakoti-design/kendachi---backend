const express = require('express');

const router = express.Router();
const { query } = require('../db');
const { requireAuth, requireRole, logAudit } = require('../middleware/auth');
const { getClientIP } = require('../services/fingerprint');
const {
  REASON_CODES,
  getPatternAlerts,
  proposeCorrection,
  reviewCorrection,
} = require('../services/governance');

router.use(requireAuth, requireRole('admin'));

router.get('/dashboard', async (req, res, next) => {
  try {
    const { rows: stats } = await query(`
      SELECT
        (SELECT COUNT(*) FROM employees WHERE is_active = true) AS total_employees,
        (SELECT COUNT(*) FROM work_sessions WHERE login_time::date = CURRENT_DATE) AS sessions_today,
        (SELECT COUNT(*) FROM work_sessions WHERE closed = false) AS currently_active,
        (SELECT COUNT(*) FROM overtime_requests WHERE status = 'pending') AS pending_ot,
        (SELECT COUNT(*) FROM anomaly_flags WHERE resolved = false) AS unresolved_flags,
        (SELECT COUNT(*) FROM work_sessions WHERE monitoring_score < 70 AND login_time::date = CURRENT_DATE) AS monitoring_alerts,
        (SELECT COUNT(*) FROM corrections WHERE status = 'pending') AS pending_corrections
    `);

    res.json({ stats: stats[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/records', async (req, res, next) => {
  try {
    const { from, to, employee_id, page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    const params = [parseInt(limit, 10), offset];

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

router.post('/correct', async (req, res, next) => {
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
      action: 'correction_proposed',
      table: 'work_sessions',
      target_id: work_session_id,
      ip: getClientIP(req),
      detail: {
        correction_id: result.correction.id,
        field_changed,
        old_value: result.oldValue,
        new_value,
        reason_code: result.reasonCode,
        reason,
        governance: 'second_approval_required',
      },
    });

    res.status(201).json({
      correction: result.correction,
      message: 'Correction proposed. A different approver must review it before it is applied.',
      reason_codes: REASON_CODES,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

router.get('/corrections', async (req, res, next) => {
  try {
    const { status = 'pending' } = req.query;
    const params = [];
    let filter = '';
    if (status !== 'all') {
      params.push(status);
      filter = 'WHERE c.status = $1';
    }

    const { rows } = await query(
      `SELECT c.*, ws.employee_id, e.name AS employee_name, e.emp_code,
              proposer.name AS proposer_name, reviewer.name AS reviewer_name
       FROM corrections c
       JOIN work_sessions ws ON ws.id = c.work_session_id
       JOIN employees e ON e.id = ws.employee_id
       JOIN employees proposer ON proposer.id = c.corrected_by
       LEFT JOIN employees reviewer ON reviewer.id = c.second_admin_id
       ${filter}
       ORDER BY c.created_at DESC
       LIMIT 100`,
      params
    );

    res.json({ corrections: rows, reason_codes: REASON_CODES });
  } catch (err) {
    next(err);
  }
});

router.post('/corrections/:id/review', async (req, res, next) => {
  try {
    const correction = await reviewCorrection({
      correctionId: parseInt(req.params.id, 10),
      reviewer: req.user,
      decision: req.body.decision,
      comment: req.body.comment,
    });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: `correction_${req.body.decision}`,
      table: 'corrections',
      target_id: correction.id,
      ip: getClientIP(req),
      detail: { correction_id: correction.id, comment: req.body.comment || null },
    });

    res.json({ correction });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

router.get('/patterns', async (req, res, next) => {
  try {
    res.json(await getPatternAlerts());
  } catch (err) {
    next(err);
  }
});

router.get('/audit-log', async (req, res, next) => {
  try {
    const { from, to, actor_id, action, page = 1 } = req.query;
    const limit = 100;
    const offset = (parseInt(page, 10) - 1) * limit;
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

router.post('/anomalies/:id/resolve', async (req, res, next) => {
  try {
    const { rows } = await query(
      `UPDATE anomaly_flags
       SET resolved = true, resolved_by = $1, resolved_at = NOW()
       WHERE id = $2 RETURNING *`,
      [req.user.id, parseInt(req.params.id, 10)]
    );

    if (!rows.length) return res.status(404).json({ error: 'Flag not found' });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'anomaly_resolved',
      table: 'anomaly_flags',
      target_id: parseInt(req.params.id, 10),
      ip: getClientIP(req),
    });

    res.json({ resolved: rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/export-full', async (req, res, next) => {
  try {
    const crypto = require('crypto');
    const { from, to } = req.query;
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
      generated_at: new Date().toISOString(),
      generated_by: `${req.user.empCode} - ${req.user.name} [ADMIN]`,
      watermark: `ADMIN:${req.user.empCode}`,
      promise: 'Every hour is accounted for, and every correction leaves a permanent trail.',
      record_count: rows.length,
      sessions: rows,
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

router.post('/employees/:id/deactivate', async (req, res, next) => {
  try {
    const empId = parseInt(req.params.id, 10);
    if (empId === req.user.id) {
      return res.status(400).json({ error: 'Cannot deactivate yourself' });
    }

    await query('UPDATE employees SET is_active = false WHERE id = $1', [empId]);
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
