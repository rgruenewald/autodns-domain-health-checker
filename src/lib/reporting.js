import fs from 'fs/promises';
import path from 'path';
import nodemailer from 'nodemailer';
import { config } from './config.js';
import { colors, getTimestamp,
  parseSummaryCounts } from '../utils/helpers.js';

/**
 * Save report to file with automatic cleanup
 * @param {string} content - Report content
 * @returns {Promise<string>} File path of saved report
 */
export async function saveReport(content) {
  const reportsDir = path.join(process.cwd(), 'reports');
  await fs.mkdir(reportsDir, { recursive: true });

  // Cleanup: keep only last 30 reports
  try {
    const files = await fs.readdir(reportsDir);
    const reports = files
      .filter(f => f.startsWith('domain-health-') && f.endsWith('.txt'))
      .sort()
      .reverse();

    if (reports.length > 30) {
      await Promise.all(
        reports.slice(30).map(f =>
          fs.unlink(path.join(reportsDir, f)).catch(() => {}),
        ),
      );
      console.log(
        `Cleaned up ${reports.length - 30} old report(s)\n`,
      );
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error('Cleanup error:', err.message);
    }
  }

  const filepath = path.join(
    reportsDir,
    `domain-health-${getTimestamp()}.txt`,
  );
  await fs.writeFile(filepath, content, 'utf8');
  console.log(`Report: ${path.relative(process.cwd(), filepath)}\n`);

  return filepath;
}

/**
 * Send report via email with summary
 * @param {string} reportContent - Report content to send
 */
export async function sendReportByEmail(reportContent) {
  if (!config.smtp.host || !config.email.from || !config.email.to) {
    console.log('Email not configured, skipping\n');
    return;
  }

  console.log('Sending report via email...');

  try {
    const transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user && config.smtp.password ? {
        user: config.smtp.user,
        pass: config.smtp.password,
      } : undefined,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000,
    });

    const counts = parseSummaryCounts(reportContent);
    const dryRunHeader = config.dryRun ? ' [DRY-RUN MODE]' : '';
    const dryRunBanner = config.dryRun
      ? '\n*** DRY-RUN MODE: No changes made to AutoDNS ***\n'
      : '';

    const emailBody = `AutoDNS Domain Health Report${dryRunHeader}
Generated: ${new Date().toISOString().replace('T', ' ').substring(0, 19)}

=======
SUMMARY
=======
- SPF   (TOTAL: ${counts.total} | OK: ${counts.spf.ok} | FAILED: ${counts.spf.fail} | ERRORS: ${counts.spf.error} | SKIPPED: ${counts.spf.skipped})
- DMARC (TOTAL: ${counts.total} | OK: ${counts.dmarc.ok} | FAILED: ${counts.dmarc.fail} | ERRORS: ${counts.dmarc.error} | SKIPPED: ${counts.dmarc.skipped})
- DKIM  (TOTAL: ${counts.total} | OK: ${counts.dkim.ok} | FAILED: ${counts.dkim.fail} | ERRORS: ${counts.dkim.error} | SKIPPED: ${counts.dkim.skipped})${dryRunBanner}

====================
DOMAIN CHECK RESULTS
====================

Expected SPF:   ${config.expectedSpf}
Expected DMARC: ${config.expectedDmarc}

${reportContent}
`;

    // Parse and normalize recipient email addresses (support comma-separated list)
    const recipients = config.email.to.split(',').map(e => e.trim()).join(', ');

    const info = await transporter.sendMail({
      from: config.email.from,
      to: recipients,
      subject: config.email.subject,
      text: emailBody,
    });

    console.log(
      `${colors.green}✓${colors.reset} Email sent: ${info.messageId}\n`,
    );
  } catch (error) {
    console.error(
      `${colors.red}✗${colors.reset} Email failed: ${error.message}`,
    );
    if (error.code) {console.error(`Error code: ${error.code}`);}
  }
}
