const express = require('express');

const { query } = require('../db');
const { requireAuth, logAudit } = require('../middleware/auth');
const { getClientIP, buildFingerprint } = require('../services/fingerprint');
const { checkSessionAnomaly } = require('../services/anomaly');
const { createSessionAnchor } = require('../services/proof');

const router = express.Router();

const REGULAR_LIMIT_SEC = Math.round((parseFloat(process.env.REGULAR_HOURS_LIMIT) || 0.0167) * 3600);
const COMPANY_SESSION_SEC = Math.round((parseFloat(process.env.COMPANY_SESSION_MINUTES) || 5) * 60);
const IDLE_TIMEOUT_SEC = Math.round((parseFloat(process.env.IDLE_TIMEOUT_MINUTES) || 1) * 60);
const HEARTBEAT_INTERVAL_SEC = parseInt(process.env.HEARTBEAT_INTERVAL_SECONDS || '5', 10);
const IDLE_THRESHOLD_SEC = parseInt(process.env.IDLE_THRESHOLD_SECONDS || '10', 10);
const PRESENCE_INTERVAL_SEC = parseInt(process.env.PRESENCE_INTERVAL_SECONDS || '60', 10);
const PRESENCE_RESPONSE_SEC = parseInt(process.env.PRESENCE_RESPONSE_SECONDS || '15', 10);
const HIDDEN_ALERT_SEC = parseInt(process.env.HIDDEN_ALERT_SECONDS || '30', 10);

function clampInt(value, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(0, Math.round(parsed));
}

function buildMonitoringConfig() {
  return {
    regular_limit_seconds: REGULAR_LIMIT_SEC,
    company_session_seconds: COMPANY_SESSION_SEC,
    heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SEC,
    idle_threshold_seconds: IDLE_THRESHOLD_SEC,
    idle_timeout_seconds: IDLE_TIMEOUT_SEC,
    presence_interval_seconds: PRESENCE_INTERVAL_SEC,
    presence_response_seconds: PRESENCE_RESPONSE_SEC,
    hidden_alert_seconds: HIDDEN_ALERT_SEC,
  };
}

function computeMonitoringScore(metrics) {
  const idlePenalty = Math.min(30, Math.floor(metrics.idle_seconds / 10) * 6);
  const hiddenPenalty = Math.min(25, Math.floor(metrics.hidden_seconds / 10) * 5);
  const focusPenalty = Math.min(20, metrics.focus_loss_count * 4);
  const presencePenalty = Math.min(50, metrics.presence_failures * 35);
  const activityBoost = Math.min(10, Math.floor(metrics.activity_events / 10));
  const presenceBoost = Math.min(6, metrics.presence_passes * 2);
  return Math.max(0, Math.min(100, 100 - idlePenalty - hiddenPenalty - focusPenalty - presencePenalty + activityBoost + presenceBoost));
}

function buildMonitoringMetrics(sessionRow, body = {}) {
  return {
    activity_events: clampInt(body.activity_events, sessionRow?.activity_events || 0),
    idle_seconds: clampInt(body.idle_seconds, sessionRow?.idle_seconds || 0),
    hidden_seconds: clampInt(body.hidden_seconds, sessionRow?.hidden_seconds || 0),
    focus_loss_count: clampInt(body.focus_loss_count, sessionRow?.focus_loss_count || 0),
    presence_passes: clampInt(body.presence_passes, sessionRow?.presence_passes || 0),
    presence_failures: clampInt(body.presence_failures, sessionRow?.presence_failures || 0),
  };
}

async function createMonitoringFlag(employeeId, type, severity, description, metadata = {}) {
  await query(
    `INSERT INTO anomaly_flags
       (employee_id, flag_type, description, severity, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [employeeId, type, description, severity, JSON.stringify(metadata)]
  );
}

async function updateWorkSessionSnapshot(workSessionId, elapsedSeconds, metrics, monitoringScore) {
  const regularSeconds = Math.min(elapsedSeconds, REGULAR_LIMIT_SEC);
  const overtimeSeconds = Math.max(0, elapsedSeconds - REGULAR_LIMIT_SEC);
  const isOvertime = elapsedSeconds > REGULAR_LIMIT_SEC;

  await query(
    `UPDATE work_sessions SET
       last_heartbeat    = NOW(),
       total_seconds     = $1,
       regular_seconds   = $2,
       overtime_seconds  = $3,
       is_overtime       = $4,
       activity_events   = $5,
       idle_seconds      = $6,
       hidden_seconds    = $7,
       focus_loss_count  = $8,
       presence_passes   = $9,
       presence_failures = $10,
       monitoring_score  = $11
     WHERE id = $12`,
    [
      elapsedSeconds,
      regularSeconds,
      overtimeSeconds,
      isOvertime,
      metrics.activity_events,
      metrics.idle_seconds,
      metrics.hidden_seconds,
      metrics.focus_loss_count,
      metrics.presence_passes,
      metrics.presence_failures,
      monitoringScore,
      workSessionId,
    ]
  );

  return {
    regular_seconds: regularSeconds,
    overtime_seconds: overtimeSeconds,
    is_overtime: isOvertime,
  };
}

async function autoCloseSession(workSessionId, user, totalSeconds, metrics, reason) {
  const logoutTime = new Date();
  const regularSeconds = Math.min(totalSeconds, REGULAR_LIMIT_SEC);
  const overtimeSeconds = Math.max(0, totalSeconds - REGULAR_LIMIT_SEC);
  const monitoringScore = computeMonitoringScore(metrics);

  await query(
    `UPDATE work_sessions SET
       logout_time       = $1,
       total_seconds     = $2,
       regular_seconds   = $3,
       overtime_seconds  = $4,
       is_overtime       = $5,
       closed            = true,
       auto_closed       = true,
       auto_close_reason = $6,
       activity_events   = $7,
       idle_seconds      = $8,
       hidden_seconds    = $9,
       focus_loss_count  = $10,
       presence_passes   = $11,
       presence_failures = $12,
       monitoring_score  = $13,
       last_heartbeat    = NOW()
     WHERE id = $14`,
    [
      logoutTime,
      totalSeconds,
      regularSeconds,
      overtimeSeconds,
      overtimeSeconds > 0,
      reason,
      metrics.activity_events,
      metrics.idle_seconds,
      metrics.hidden_seconds,
      metrics.focus_loss_count,
      metrics.presence_passes,
      metrics.presence_failures,
      monitoringScore,
      workSessionId,
    ]
  );

  await logAudit({
    actor_id: user.id,
    actor_role: user.role,
    action: 'work_session_auto_closed',
    table: 'work_sessions',
    target_id: workSessionId,
    ip: getClientIP({ headers: {}, socket: {} }),
    detail: {
      reason,
      total_seconds: totalSeconds,
      monitoring_score: monitoringScore,
      idle_seconds: metrics.idle_seconds,
      hidden_seconds: metrics.hidden_seconds,
      presence_failures: metrics.presence_failures,
    },
    success: false,
    threat: metrics.presence_failures > 0 ? 'high' : 'medium',
  });

  const proofAnchor = await createSessionAnchor(workSessionId, 'session_auto_close').catch((err) => {
    console.error('[PROOF] Anchor creation failed:', err.message);
    return null;
  });

  return {
    work_session_id: workSessionId,
    logout_time: logoutTime,
    total_seconds: totalSeconds,
    regular_seconds: regularSeconds,
    overtime_seconds: overtimeSeconds,
    is_overtime: overtimeSeconds > 0,
    monitoring_score: monitoringScore,
    auto_close_reason: reason,
    proof_anchor: proofAnchor,
  };
}

router.post('/start', requireAuth, async (req, res, next) => {
  try {
    const ip = getClientIP(req);
    const fp = buildFingerprint(req);

    const { rows: existing } = await query(
      `SELECT id
       FROM work_sessions
       WHERE employee_id = $1 AND closed = false`,
      [req.user.id]
    );

    if (existing.length) {
      return res.status(409).json({
        error: 'You already have an active work session',
        work_session_id: existing[0].id,
      });
    }

    const { rows } = await query(
      `INSERT INTO work_sessions
         (employee_id, session_token, ip_address, device_fingerprint, monitoring_score)
       VALUES ($1, $2, $3, $4, 100)
       RETURNING id, login_time, monitoring_score`,
      [req.user.id, req.user.sessionToken, ip, fp]
    );

    const workSession = rows[0];

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'work_session_start',
      table: 'work_sessions',
      target_id: workSession.id,
      ip,
      fp,
      detail: { monitoring_mode: 'live_presence_audit', config: buildMonitoringConfig() },
    });

    return res.status(201).json({
      work_session_id: workSession.id,
      login_time: workSession.login_time,
      monitoring_score: workSession.monitoring_score,
      config: buildMonitoringConfig(),
      message: 'Work session started',
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/heartbeat', requireAuth, async (req, res, next) => {
  try {
    const { work_session_id, elapsed_seconds, is_idle = false } = req.body;
    if (!work_session_id) {
      return res.status(400).json({ error: 'work_session_id required' });
    }

    const { rows } = await query(
      `SELECT *
       FROM work_sessions
       WHERE id = $1 AND employee_id = $2 AND closed = false`,
      [work_session_id, req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Active work session not found' });
    }

    const ws = rows[0];
    const elapsedSeconds = clampInt(elapsed_seconds, ws.total_seconds);
    const metrics = buildMonitoringMetrics(ws, req.body);
    const monitoringScore = computeMonitoringScore(metrics);
    const totals = await updateWorkSessionSnapshot(work_session_id, elapsedSeconds, metrics, monitoringScore);

    await query(
      `INSERT INTO heartbeats
         (work_session_id, employee_id, elapsed_seconds, ip_address, is_idle)
       VALUES ($1, $2, $3, $4, $5)`,
      [work_session_id, req.user.id, elapsedSeconds, getClientIP(req), is_idle]
    );

    if (metrics.hidden_seconds >= HIDDEN_ALERT_SEC && ws.hidden_seconds < HIDDEN_ALERT_SEC) {
      await createMonitoringFlag(
        req.user.id,
        'hidden_tab_monitor',
        'medium',
        `Session spent ${metrics.hidden_seconds}s with the dashboard hidden.`,
        { work_session_id, hidden_seconds: metrics.hidden_seconds }
      );
    }

    if (is_idle && metrics.idle_seconds >= IDLE_TIMEOUT_SEC) {
      const summary = await autoCloseSession(
        work_session_id,
        req.user,
        elapsedSeconds,
        metrics,
        `No verified activity for ${IDLE_TIMEOUT_SEC} seconds`
      );

      return res.json({
        saved: true,
        auto_closed: true,
        reason: summary.auto_close_reason,
        monitoring_score: summary.monitoring_score,
        summary,
      });
    }

    if (elapsedSeconds >= COMPANY_SESSION_SEC) {
      const summary = await autoCloseSession(
        work_session_id,
        req.user,
        elapsedSeconds,
        metrics,
        `Company demo session reached ${Math.round(COMPANY_SESSION_SEC / 60)} minutes`
      );

      return res.json({
        saved: true,
        auto_closed: true,
        reason: summary.auto_close_reason,
        monitoring_score: summary.monitoring_score,
        summary,
      });
    }

    return res.json({
      saved: true,
      elapsed_seconds: elapsedSeconds,
      is_overtime: totals.is_overtime,
      monitoring_score: monitoringScore,
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/signal', requireAuth, async (req, res, next) => {
  try {
    const { work_session_id, type, elapsed_seconds } = req.body;
    if (!work_session_id || !type) {
      return res.status(400).json({ error: 'work_session_id and type required' });
    }

    const { rows } = await query(
      `SELECT *
       FROM work_sessions
       WHERE id = $1 AND employee_id = $2 AND closed = false`,
      [work_session_id, req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Active work session not found' });
    }

    const ws = rows[0];
    const elapsedSeconds = clampInt(elapsed_seconds, ws.total_seconds);
    const metrics = buildMonitoringMetrics(ws, req.body);
    const monitoringScore = computeMonitoringScore(metrics);

    if (type === 'presence_failed') {
      await createMonitoringFlag(
        req.user.id,
        'presence_challenge_failed',
        'high',
        'Live presence challenge was missed. Session was automatically closed.',
        { work_session_id, elapsed_seconds: elapsedSeconds }
      );

      const summary = await autoCloseSession(
        work_session_id,
        req.user,
        elapsedSeconds,
        metrics,
        'Missed live presence challenge'
      );

      return res.json({
        accepted: true,
        auto_closed: true,
        reason: summary.auto_close_reason,
        monitoring_score: summary.monitoring_score,
        summary,
      });
    }

    await updateWorkSessionSnapshot(work_session_id, elapsedSeconds, metrics, monitoringScore);

    const detail = {
      work_session_id,
      monitoring_score: monitoringScore,
      idle_seconds: metrics.idle_seconds,
      hidden_seconds: metrics.hidden_seconds,
      focus_loss_count: metrics.focus_loss_count,
      presence_passes: metrics.presence_passes,
      presence_failures: metrics.presence_failures,
      activity_events: metrics.activity_events,
    };

    const actionMap = {
      visibility_hidden: 'session_visibility_hidden',
      visibility_visible: 'session_visibility_restored',
      focus_lost: 'session_focus_lost',
      focus_restored: 'session_focus_restored',
      presence_passed: 'presence_check_passed',
    };

    const threatMap = {
      visibility_hidden: 'low',
      visibility_visible: 'none',
      focus_lost: 'low',
      focus_restored: 'none',
      presence_passed: 'none',
    };

    const action = actionMap[type];
    if (!action) {
      return res.status(400).json({ error: 'Unsupported monitoring signal' });
    }

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action,
      table: 'work_sessions',
      target_id: work_session_id,
      ip: getClientIP(req),
      detail,
      threat: threatMap[type],
    });

    return res.json({ accepted: true, monitoring_score: monitoringScore });
  } catch (err) {
    return next(err);
  }
});

router.post('/stop', requireAuth, async (req, res, next) => {
  try {
    const { work_session_id, notes } = req.body;

    const { rows } = await query(
      `SELECT *
       FROM work_sessions
       WHERE id = $1 AND employee_id = $2 AND closed = false`,
      [work_session_id, req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Active work session not found' });
    }

    const ws = rows[0];
    const logoutTime = new Date();
    const loginTime = new Date(ws.login_time);
    const totalSeconds = Math.floor((logoutTime - loginTime) / 1000);
    const metrics = buildMonitoringMetrics(ws, ws);
    const monitoringScore = computeMonitoringScore(metrics);
    const regularSeconds = Math.min(totalSeconds, REGULAR_LIMIT_SEC);
    const overtimeSeconds = Math.max(0, totalSeconds - REGULAR_LIMIT_SEC);

    await query(
      `UPDATE work_sessions SET
         logout_time       = $1,
         total_seconds     = $2,
         regular_seconds   = $3,
         overtime_seconds  = $4,
         is_overtime       = $5,
         closed            = true,
         notes             = $6,
         monitoring_score  = $7,
         last_heartbeat    = NOW()
       WHERE id = $8`,
      [logoutTime, totalSeconds, regularSeconds, overtimeSeconds, overtimeSeconds > 0, notes || null, monitoringScore, work_session_id]
    );

    checkSessionAnomaly(req.user, work_session_id, totalSeconds).catch(console.error);
    const proofAnchor = await createSessionAnchor(work_session_id, 'session_clockout').catch((err) => {
      console.error('[PROOF] Anchor creation failed:', err.message);
      return null;
    });

    await logAudit({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'work_session_stop',
      table: 'work_sessions',
      target_id: work_session_id,
      ip: getClientIP(req),
      detail: {
        total_seconds: totalSeconds,
        overtime: overtimeSeconds > 0,
        monitoring_score: monitoringScore,
        presence_failures: metrics.presence_failures,
        proof_anchor_status: proofAnchor?.status || 'not_created',
      },
    });

    return res.json({
      message: 'Work session closed',
      summary: {
        work_session_id,
        login_time: ws.login_time,
        logout_time: logoutTime,
        total_seconds: totalSeconds,
        regular_seconds: regularSeconds,
        overtime_seconds: overtimeSeconds,
        is_overtime: overtimeSeconds > 0,
        monitoring_score: monitoringScore,
        activity_events: metrics.activity_events,
        idle_seconds: metrics.idle_seconds,
        hidden_seconds: metrics.hidden_seconds,
        focus_loss_count: metrics.focus_loss_count,
        presence_passes: metrics.presence_passes,
        presence_failures: metrics.presence_failures,
        proof_anchor: proofAnchor,
      },
    });
  } catch (err) {
    return next(err);
  }
});

router.get('/active', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, login_time, last_heartbeat, total_seconds,
              regular_seconds, overtime_seconds, is_overtime,
              activity_events, idle_seconds, hidden_seconds, focus_loss_count,
              presence_passes, presence_failures, monitoring_score
       FROM work_sessions
       WHERE employee_id = $1 AND closed = false`,
      [req.user.id]
    );

    if (!rows.length) {
      return res.json({ active: false, config: buildMonitoringConfig() });
    }

    const ws = rows[0];
    const elapsed = Math.floor((Date.now() - new Date(ws.login_time).getTime()) / 1000);

    return res.json({
      active: true,
      config: buildMonitoringConfig(),
      work_session: {
        ...ws,
        live_elapsed: elapsed,
      },
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
