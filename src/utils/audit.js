/**
 * Audit logging for DNS record changes and critical operations.
 *
 * Provides a permanent record of all changes made to DNS records,
 * configuration updates, and security-relevant events for compliance
 * and troubleshooting.
 *
 * @module utils/audit
 */

import fs from 'fs/promises';
import path from 'path';
import { logger } from './logger.js';

/**
 * @typedef {Object} AuditEntry
 * @property {string} timestamp - ISO 8601 timestamp
 * @property {string} action - Action performed (e.g., 'DNS_UPDATE', 'CONFIG_CHANGE')
 * @property {string} domain - Domain affected (if applicable)
 * @property {string} [recordType] - DNS record type (SPF, DMARC, DKIM, etc.)
 * @property {Object} [before] - State before change
 * @property {Object} [after] - State after change
 * @property {boolean} success - Whether action succeeded
 * @property {string} [error] - Error message if failed
 * @property {Object} [metadata] - Additional context
 */

/**
 * Audit log directory and file configuration
 */
const AUDIT_CONFIG = {
  DIR: process.env.AUDIT_LOG_DIR || 'audit-logs',
  FILE_PREFIX: 'audit',
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  RETENTION_DAYS: parseInt(process.env.AUDIT_RETENTION_DAYS || '365', 10),
};

/**
 * Ensure audit log directory exists.
 *
 * @async
 * @returns {Promise<void>}
 */
async function ensureAuditDir() {
  try {
    await fs.mkdir(AUDIT_CONFIG.DIR, { recursive: true });
  } catch (error) {
    logger.error({ err: error }, 'Failed to create audit log directory');
    throw error;
  }
}

/**
 * Get current audit log file path based on date.
 *
 * @returns {string} Path to current audit log file
 */
function getAuditLogPath() {
  const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return path.join(
    AUDIT_CONFIG.DIR,
    `${AUDIT_CONFIG.FILE_PREFIX}-${date}.json`,
  );
}

/**
 * Append an audit entry to the log file.
 *
 * @async
 * @param {AuditEntry} entry - Audit entry to log
 * @returns {Promise<void>}
 */
async function appendAuditEntry(entry) {
  await ensureAuditDir();
  const logPath = getAuditLogPath();

  // Add newline-delimited JSON format (easier to parse large files)
  const line = `${JSON.stringify(entry)}\n`;

  try {
    await fs.appendFile(logPath, line, 'utf8');
  } catch (error) {
    logger.error(
      { err: error, logPath },
      'Failed to write audit log entry',
    );
    // Don't throw - audit logging should not break main flow
  }
}

/**
 * Log a DNS record update to the audit trail.
 *
 * @async
 * @param {Object} params - Audit parameters
 * @param {string} params.domain - Domain name
 * @param {string} params.recordType - Record type (SPF, DMARC, DKIM, etc.)
 * @param {string|Object} params.before - Previous record value/state
 * @param {string|Object} params.after - New record value/state
 * @param {boolean} params.success - Whether update succeeded
 * @param {string} [params.error] - Error message if failed
 * @param {Object} [params.metadata] - Additional context
 * @returns {Promise<void>}
 *
 * @example
 * await auditDNSUpdate({
 *   domain: 'example.com',
 *   recordType: 'SPF',
 *   before: 'v=spf1 a mx ~all',
 *   after: 'v=spf1 a mx include:_spf.example.com ~all',
 *   success: true,
 *   metadata: { reason: 'SPF flattening' }
 * });
 */
export async function auditDNSUpdate({
  domain,
  recordType,
  before,
  after,
  success,
  error,
  metadata = {},
}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action: 'DNS_UPDATE',
    domain,
    recordType,
    before,
    after,
    success,
    error,
    metadata,
  };

  logger.info(
    {
      domain,
      recordType,
      success,
    },
    'Audit: DNS update',
  );

  await appendAuditEntry(entry);
}

/**
 * Log a configuration change to the audit trail.
 *
 * @async
 * @param {Object} params - Audit parameters
 * @param {string} params.configKey - Configuration key changed
 * @param {*} params.before - Previous value
 * @param {*} params.after - New value
 * @param {boolean} params.success - Whether change succeeded
 * @param {string} [params.error] - Error message if failed
 * @returns {Promise<void>}
 *
 * @example
 * await auditConfigChange({
 *   configKey: 'DKIM_SELECTORS',
 *   before: ['s1', 's2'],
 *   after: ['s1', 's2', 's3'],
 *   success: true
 * });
 */
export async function auditConfigChange({
  configKey,
  before,
  after,
  success,
  error,
}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action: 'CONFIG_CHANGE',
    configKey,
    before,
    after,
    success,
    error,
  };

  logger.info({ configKey, success }, 'Audit: Configuration change');

  await appendAuditEntry(entry);
}

/**
 * Log a security event to the audit trail.
 *
 * @async
 * @param {Object} params - Audit parameters
 * @param {string} params.eventType - Type of security event
 * @param {string} params.description - Event description
 * @param {string} [params.severity] - Severity level (low, medium, high, critical)
 * @param {Object} [params.metadata] - Additional context
 * @returns {Promise<void>}
 *
 * @example
 * await auditSecurityEvent({
 *   eventType: 'INVALID_DOMAIN',
 *   description: 'Attempted to process invalid domain name',
 *   severity: 'medium',
 *   metadata: { input: '../../../etc/passwd' }
 * });
 */
export async function auditSecurityEvent({
  eventType,
  description,
  severity = 'medium',
  metadata = {},
}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action: 'SECURITY_EVENT',
    eventType,
    description,
    severity,
    metadata,
  };

  logger.warn({ eventType, severity }, 'Audit: Security event');

  await appendAuditEntry(entry);
}

/**
 * Log an application event to the audit trail.
 *
 * @async
 * @param {Object} params - Audit parameters
 * @param {string} params.action - Action identifier
 * @param {boolean} params.success - Whether action succeeded
 * @param {Object} [params.metadata] - Additional context
 * @param {string} [params.error] - Error message if failed
 * @returns {Promise<void>}
 *
 * @example
 * await auditApplicationEvent({
 *   action: 'REPORT_GENERATED',
 *   success: true,
 *   metadata: { domainCount: 50, reportSize: 12345 }
 * });
 */
export async function auditApplicationEvent({
  action,
  success,
  metadata = {},
  error,
}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    success,
    metadata,
    error,
  };

  logger.info({ action, success }, 'Audit: Application event');

  await appendAuditEntry(entry);
}

/**
 * Clean up old audit log files beyond retention period.
 *
 * @async
 * @returns {Promise<number>} Number of files deleted
 *
 * @example
 * const deleted = await cleanupOldAuditLogs();
 * console.log(`Deleted ${deleted} old audit log files`);
 */
export async function cleanupOldAuditLogs() {
  try {
    await ensureAuditDir();
    const files = await fs.readdir(AUDIT_CONFIG.DIR);
    const now = Date.now();
    const cutoffTime = now - (AUDIT_CONFIG.RETENTION_DAYS * 24 * 60 * 60 * 1000);

    let deletedCount = 0;

    for (const file of files) {
      if (!file.startsWith(AUDIT_CONFIG.FILE_PREFIX)) {
        continue;
      }

      const filePath = path.join(AUDIT_CONFIG.DIR, file);
      const stats = await fs.stat(filePath);

      if (stats.mtimeMs < cutoffTime) {
        await fs.unlink(filePath);
        deletedCount++;
        logger.info({ file }, 'Deleted old audit log');
      }
    }

    return deletedCount;
  } catch (error) {
    logger.error({ err: error }, 'Failed to cleanup old audit logs');
    return 0;
  }
}

/**
 * Read audit log entries for a specific date range.
 *
 * @async
 * @param {Date} startDate - Start date (inclusive)
 * @param {Date} endDate - End date (inclusive)
 * @returns {Promise<AuditEntry[]>} Array of audit entries
 *
 * @example
 * const entries = await readAuditLogs(
 *   new Date('2025-01-01'),
 *   new Date('2025-01-31')
 * );
 * console.log(`Found ${entries.length} audit entries`);
 */
export async function readAuditLogs(startDate, endDate) {
  const entries = [];

  try {
    await ensureAuditDir();
    const files = await fs.readdir(AUDIT_CONFIG.DIR);

    for (const file of files) {
      if (!file.startsWith(AUDIT_CONFIG.FILE_PREFIX)) {
        continue;
      }

      // Extract date from filename: audit-YYYY-MM-DD.json
      const dateMatch = file.match(/audit-(\d{4}-\d{2}-\d{2})\.json/);
      if (!dateMatch) {
        continue;
      }

      const fileDate = new Date(dateMatch[1]);
      if (fileDate >= startDate && fileDate <= endDate) {
        const filePath = path.join(AUDIT_CONFIG.DIR, file);
        const content = await fs.readFile(filePath, 'utf8');

        // Parse newline-delimited JSON
        const lines = content.trim().split('\n');
        for (const line of lines) {
          if (line) {
            try {
              entries.push(JSON.parse(line));
            } catch (_parseError) {
              logger.warn({ line }, 'Failed to parse audit log line');
            }
          }
        }
      }
    }
  } catch (error) {
    logger.error({ err: error }, 'Failed to read audit logs');
  }

  return entries;
}
