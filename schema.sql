-- ═══════════════════════════════════════════════════════════
-- KENDACHI - Database Schema
-- Correction governance design: every hour is accounted for, and every
-- correction leaves a permanent trail beside the original record.
-- ═══════════════════════════════════════════════════════════

-- ─── Employees ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS employees (
  id           SERIAL PRIMARY KEY,
  emp_code     VARCHAR(20)  UNIQUE NOT NULL,   -- e.g. EMP-2041
  name         VARCHAR(100) NOT NULL,
  email        VARCHAR(255) UNIQUE NOT NULL,   -- must be company email
  department   VARCHAR(100),
  role         VARCHAR(20)  NOT NULL DEFAULT 'employee'
                            CHECK (role IN ('employee','manager','admin')),
  is_active    BOOLEAN      NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  created_by   INTEGER      REFERENCES employees(id)   -- admin who registered
);

-- ─── OTP Codes ─────────────────────────────────────────────
-- Short-lived, single-use codes sent to company email.
CREATE TABLE IF NOT EXISTS otp_codes (
  id           SERIAL PRIMARY KEY,
  employee_id  INTEGER      NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  code         VARCHAR(8)   NOT NULL,
  expires_at   TIMESTAMPTZ  NOT NULL,
  used         BOOLEAN      NOT NULL DEFAULT false,
  attempt_count INTEGER     NOT NULL DEFAULT 0,
  max_attempts INTEGER      NOT NULL DEFAULT 4,
  ip_address   INET,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── Active Sessions ───────────────────────────────────────
-- One active session per employee enforced at application level.
CREATE TABLE IF NOT EXISTS active_sessions (
  id               SERIAL PRIMARY KEY,
  session_token    VARCHAR(64) UNIQUE NOT NULL,
  employee_id      INTEGER     NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  ip_address       INET        NOT NULL,
  device_fingerprint VARCHAR(128) NOT NULL,
  user_agent       TEXT,
  issued_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL,
  last_ping        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Work Sessions ─────────────────────────────────────────
-- Core table. Closed rows preserve the original session facts.
CREATE TABLE IF NOT EXISTS work_sessions (
  id               SERIAL PRIMARY KEY,
  employee_id      INTEGER     NOT NULL REFERENCES employees(id),
  session_token    VARCHAR(64),                -- links to active_sessions
  login_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  logout_time      TIMESTAMPTZ,                -- NULL = still active
  last_heartbeat   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  total_seconds    INTEGER     DEFAULT 0,
  regular_seconds  INTEGER     DEFAULT 0,
  overtime_seconds INTEGER     DEFAULT 0,
  ip_address       INET,
  device_fingerprint VARCHAR(128),
  is_overtime      BOOLEAN     NOT NULL DEFAULT false,
  closed           BOOLEAN     NOT NULL DEFAULT false,  -- true after logout
  auto_closed      BOOLEAN     NOT NULL DEFAULT false,  -- idle timeout
  notes            TEXT,                       -- employee can add a note
  activity_events  INTEGER     NOT NULL DEFAULT 0,
  idle_seconds     INTEGER     NOT NULL DEFAULT 0,
  hidden_seconds   INTEGER     NOT NULL DEFAULT 0,
  focus_loss_count INTEGER     NOT NULL DEFAULT 0,
  presence_passes  INTEGER     NOT NULL DEFAULT 0,
  presence_failures INTEGER    NOT NULL DEFAULT 0,
  monitoring_score INTEGER     NOT NULL DEFAULT 100,
  auto_close_reason TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Heartbeats ────────────────────────────────────────────
-- Written every N seconds by frontend ping. Proves activity.
CREATE TABLE IF NOT EXISTS heartbeats (
  id               SERIAL PRIMARY KEY,
  work_session_id  INTEGER     NOT NULL REFERENCES work_sessions(id),
  employee_id      INTEGER     NOT NULL REFERENCES employees(id),
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  elapsed_seconds  INTEGER     NOT NULL,
  ip_address       INET,
  is_idle          BOOLEAN     NOT NULL DEFAULT false
);

-- ─── Overtime Requests ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS overtime_requests (
  id               SERIAL PRIMARY KEY,
  work_session_id  INTEGER     NOT NULL REFERENCES work_sessions(id),
  employee_id      INTEGER     NOT NULL REFERENCES employees(id),
  reason           TEXT        NOT NULL,
  estimated_hours  NUMERIC(4,1),
  status           VARCHAR(20) NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending','approved','rejected')),
  manager_note     TEXT,                       -- manager view-only comment
  admin_decision   TEXT,                       -- admin final note
  reviewed_by      INTEGER     REFERENCES employees(id),   -- admin id
  requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at      TIMESTAMPTZ
);

-- ─── Corrections ───────────────────────────────────────────
-- Corrections are governed proposals. Original row always stays.
-- A second person must approve before a correction becomes accepted.
CREATE TABLE IF NOT EXISTS corrections (
  id               SERIAL PRIMARY KEY,
  work_session_id  INTEGER     NOT NULL REFERENCES work_sessions(id),
  corrected_by     INTEGER     NOT NULL REFERENCES employees(id),  -- proposer
  field_changed    VARCHAR(50) NOT NULL,        -- e.g. 'logout_time'
  old_value        TEXT        NOT NULL,
  new_value        TEXT        NOT NULL,
  reason_code      VARCHAR(80) NOT NULL DEFAULT 'other',
  reason           TEXT        NOT NULL,
  requires_second_admin BOOLEAN NOT NULL DEFAULT true,
  second_admin_id  INTEGER     REFERENCES employees(id),
  status           VARCHAR(20) NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending','approved','rejected')),
  applied          BOOLEAN     NOT NULL DEFAULT false,
  reviewed_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Employee notifications for governed corrections and disputes.
CREATE TABLE IF NOT EXISTS employee_notifications (
  id               SERIAL PRIMARY KEY,
  employee_id      INTEGER     NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  type             VARCHAR(60) NOT NULL,
  title            VARCHAR(160) NOT NULL,
  message          TEXT        NOT NULL,
  detail           JSONB,
  read             BOOLEAN     NOT NULL DEFAULT false,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- External proof anchor records. In production, record_hash can be sent to
-- RFC 3161 TSA or included in a daily public ledger anchor.
CREATE TABLE IF NOT EXISTS proof_anchors (
  id               SERIAL PRIMARY KEY,
  work_session_id  INTEGER     NOT NULL REFERENCES work_sessions(id),
  anchor_type      VARCHAR(40) NOT NULL DEFAULT 'session_clockout',
  record_hash      VARCHAR(64) NOT NULL,
  merkle_root      VARCHAR(64),
  provider         VARCHAR(80) NOT NULL,
  provider_ref     TEXT,
  status           VARCHAR(30) NOT NULL DEFAULT 'pending_external_anchor',
  requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  anchored_at      TIMESTAMPTZ,
  metadata         JSONB
);

-- Dispute tickets preserve both sides' evidence before final mediation.
CREATE TABLE IF NOT EXISTS dispute_tickets (
  id               SERIAL PRIMARY KEY,
  work_session_id  INTEGER     NOT NULL REFERENCES work_sessions(id),
  employee_id      INTEGER     NOT NULL REFERENCES employees(id),
  opened_by        INTEGER     REFERENCES employees(id),
  dispute_type     VARCHAR(80) NOT NULL DEFAULT 'hours_dispute',
  status           VARCHAR(20) NOT NULL DEFAULT 'open'
                             CHECK (status IN ('open','under_review','resolved','rejected')),
  employee_statement TEXT,
  manager_statement  TEXT,
  director_decision  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at       TIMESTAMPTZ
);

-- ─── Audit Log ─────────────────────────────────────────────
-- Every sensitive action is logged. APPEND-ONLY — no deletes ever.
CREATE TABLE IF NOT EXISTS audit_log (
  id               BIGSERIAL   PRIMARY KEY,
  actor_id         INTEGER     REFERENCES employees(id),
  actor_role       VARCHAR(20),
  action           VARCHAR(80) NOT NULL,
  target_table     VARCHAR(50),
  target_id        INTEGER,
  detail           JSONB,
  ip_address       INET,
  device_fingerprint VARCHAR(128),
  success          BOOLEAN     NOT NULL DEFAULT true,
  threat_level     VARCHAR(10) NOT NULL DEFAULT 'none'
                               CHECK (threat_level IN ('none','low','medium','high','critical')),
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Anomaly Flags ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS anomaly_flags (
  id               SERIAL PRIMARY KEY,
  employee_id      INTEGER     NOT NULL REFERENCES employees(id),
  flag_type        VARCHAR(50) NOT NULL,  -- 'odd_hours','impossible_travel','bulk_export'
  description      TEXT        NOT NULL,
  severity         VARCHAR(10) NOT NULL DEFAULT 'low'
                               CHECK (severity IN ('low','medium','high','critical')),
  resolved         BOOLEAN     NOT NULL DEFAULT false,
  resolved_by      INTEGER     REFERENCES employees(id),
  flagged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at      TIMESTAMPTZ,
  metadata         JSONB
);

-- ─── Indexes ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_work_sessions_employee ON work_sessions(employee_id);
CREATE INDEX IF NOT EXISTS idx_work_sessions_date ON work_sessions(login_time);
CREATE INDEX IF NOT EXISTS idx_work_sessions_closed ON work_sessions(closed);
CREATE INDEX IF NOT EXISTS idx_heartbeats_session ON heartbeats(work_session_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_recorded ON audit_log(recorded_at);
CREATE INDEX IF NOT EXISTS idx_otp_employee ON otp_codes(employee_id);
CREATE INDEX IF NOT EXISTS idx_active_sessions_token ON active_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_anomaly_employee ON anomaly_flags(employee_id);
CREATE INDEX IF NOT EXISTS idx_corrections_session ON corrections(work_session_id);
CREATE INDEX IF NOT EXISTS idx_corrections_status ON corrections(status);
CREATE INDEX IF NOT EXISTS idx_notifications_employee ON employee_notifications(employee_id);
CREATE INDEX IF NOT EXISTS idx_proof_anchors_session ON proof_anchors(work_session_id);
CREATE INDEX IF NOT EXISTS idx_dispute_employee ON dispute_tickets(employee_id);

-- ─── Seed: First Admin ─────────────────────────────────────
-- Replace email with real admin email before running.
-- Password is not stored — login is OTP-only.
INSERT INTO employees (emp_code, name, email, department, role)
VALUES ('ADMIN-001', 'System Admin', 'admin@company.org', 'IT', 'admin')
ON CONFLICT (email) DO NOTHING;
