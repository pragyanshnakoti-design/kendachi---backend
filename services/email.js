const { Resend } = require('resend');

const resendApiKey = process.env.RESEND_API_KEY || '';
const resend = resendApiKey && !resendApiKey.includes('REPLACE_WITH')
  ? new Resend(resendApiKey)
  : null;
const FROM = process.env.EMAIL_FROM || 'Kendachi <no-reply@yourdomain.com>';

async function sendEmail({ to, subject, html, fallbackLabel, fallbackDetail }) {
  if (!resend) {
    console.log(`[EMAIL:DEV-FALLBACK] ${fallbackLabel} -> ${to}`);
    console.log(`[EMAIL:DEV-FALLBACK] Subject: ${subject}`);
    if (fallbackDetail) {
      console.log(`[EMAIL:DEV-FALLBACK] ${fallbackDetail}`);
    }
    return { id: 'dev-fallback' };
  }

  return resend.emails.send({
    from: FROM,
    to,
    subject,
    html,
  });
}

async function sendOTP(toEmail, employeeName, code, expiresMinutes) {
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#f8fafc;color:#0f172a;padding:32px;border-radius:16px;border:1px solid #dbe2ea">
      <div style="color:#c8801a;font-size:18px;font-weight:700;letter-spacing:3px;margin-bottom:24px">KENDACHI</div>
      <p style="margin:0 0 8px">Hello, <strong>${employeeName}</strong></p>
      <p style="margin:0 0 24px;color:#64748b">Your one-time login code is ready.</p>
      <div style="background:#ffffff;border:1px solid #d7dee8;border-radius:12px;padding:20px;text-align:center;margin-bottom:24px;box-shadow:0 12px 30px rgba(15,23,42,0.06)">
        <span style="font-size:36px;letter-spacing:12px;color:#1f8a5b;font-weight:700">${code}</span>
      </div>
      <p style="color:#475569;font-size:12px;margin:0 0 4px">This code expires in <strong style="color:#0f172a">${expiresMinutes} minute(s)</strong>.</p>
      <p style="color:#475569;font-size:12px;margin:0 0 24px">If you did not request this, contact your IT administrator immediately.</p>
      <div style="border-top:1px solid #dbe2ea;padding-top:16px;font-size:11px;color:#64748b">
        Kendachi - Employee Justice & Audit Platform<br>
        This is an automated message. Do not reply.
      </div>
    </div>
  `;

  await sendEmail({
    to: toEmail,
    subject: `[${code}] Your Kendachi login code`,
    html,
    fallbackLabel: 'OTP',
    fallbackDetail: `Code for ${employeeName}: ${code} (expires in ${expiresMinutes} minute(s))`,
  });
}

async function sendOTNotification(adminEmail, employeeName, reason, hours) {
  await sendEmail({
    to: adminEmail,
    subject: `[Kendachi] Overtime Request - ${employeeName}`,
    html: `
      <div style="font-family:Arial,sans-serif;background:#ffffff;color:#0f172a;padding:24px;border-radius:14px;border:1px solid #dbe2ea">
        <p style="color:#c8801a;font-weight:700;letter-spacing:2px">OVERTIME REQUEST</p>
        <p><strong>${employeeName}</strong> has submitted an overtime request.</p>
        <p><strong>Reason:</strong> ${reason}</p>
        <p><strong>Estimated hours:</strong> ${hours}</p>
        <p style="color:#64748b;font-size:12px">Log in to Kendachi admin panel to approve or reject.</p>
      </div>
    `,
    fallbackLabel: 'OT-NOTICE',
    fallbackDetail: `${employeeName} requested overtime: ${reason} (${hours} hour(s))`,
  });
}

async function sendAnomalyAlert(adminEmail, employeeName, flagType, description) {
  await sendEmail({
    to: adminEmail,
    subject: `[Kendachi] SECURITY ALERT - ${flagType}`,
    html: `
      <div style="font-family:Arial,sans-serif;background:#ffffff;color:#0f172a;padding:24px;border-radius:14px;border:1px solid #dbe2ea">
        <p style="color:#dc2626;font-weight:700;letter-spacing:2px">ANOMALY DETECTED</p>
        <p><strong>Employee:</strong> ${employeeName}</p>
        <p><strong>Flag type:</strong> ${flagType}</p>
        <p><strong>Detail:</strong> ${description}</p>
        <p style="color:#64748b;font-size:12px">Review in the Kendachi admin panel immediately.</p>
      </div>
    `,
    fallbackLabel: 'ANOMALY',
    fallbackDetail: `${employeeName} -> ${flagType}: ${description}`,
  });
}

module.exports = { sendOTP, sendOTNotification, sendAnomalyAlert };
