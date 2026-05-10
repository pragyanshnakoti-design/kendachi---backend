const crypto = require('crypto');

const { query } = require('../db');

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function combineMerklePair(left, right) {
  return sha256(`${left}${right || left}`);
}

function buildMerkleRoot(hashes) {
  if (!hashes.length) return null;
  let level = hashes.slice().sort();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(combineMerklePair(level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0];
}

async function createSessionAnchor(workSessionId, anchorType = 'session_clockout') {
  const { rows } = await query(
    `SELECT ws.*, e.emp_code, e.email
     FROM work_sessions ws
     JOIN employees e ON e.id = ws.employee_id
     WHERE ws.id = $1`,
    [workSessionId]
  );

  if (!rows.length) return null;

  const record = rows[0];
  const recordHash = sha256(stableJson({
    id: record.id,
    employee_id: record.employee_id,
    emp_code: record.emp_code,
    email: record.email,
    login_time: record.login_time,
    logout_time: record.logout_time,
    total_seconds: record.total_seconds,
    regular_seconds: record.regular_seconds,
    overtime_seconds: record.overtime_seconds,
    auto_closed: record.auto_closed,
    auto_close_reason: record.auto_close_reason,
    monitoring_score: record.monitoring_score,
    presence_failures: record.presence_failures,
  }));

  const { rows: todayHashes } = await query(
    `SELECT record_hash
     FROM proof_anchors
     WHERE requested_at::date = CURRENT_DATE
     ORDER BY id ASC`
  );

  const merkleRoot = buildMerkleRoot([...todayHashes.map(row => row.record_hash), recordHash]);
  const provider = process.env.PROOF_ANCHOR_PROVIDER || 'external-anchor-ready';
  const mode = String(process.env.PROOF_ANCHOR_MODE || 'demo').toLowerCase();
  const status = mode === 'tsa' || mode === 'blockchain'
    ? 'pending_external_anchor'
    : 'demo_anchor_created';

  const providerRef = status === 'demo_anchor_created'
    ? `demo:${recordHash.slice(0, 12)}:${Date.now()}`
    : null;

  const { rows: anchors } = await query(
    `INSERT INTO proof_anchors
       (work_session_id, anchor_type, record_hash, merkle_root, provider, provider_ref, status, anchored_at, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING *`,
    [
      workSessionId,
      anchorType,
      recordHash,
      merkleRoot,
      provider,
      providerRef,
      status,
      status === 'demo_anchor_created' ? new Date() : null,
      JSON.stringify({
        production_options: ['RFC3161 timestamping authority', 'daily public blockchain Merkle root'],
      }),
    ]
  );

  return anchors[0];
}

module.exports = { createSessionAnchor, stableJson, sha256, buildMerkleRoot };
