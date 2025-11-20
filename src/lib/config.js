import 'dotenv/config';
import {
  isValidEmail,
  isValidPort,
  parseBoolean,
  parseInteger,
  isSafeFilePath,
  isValidDomainName,
} from '../utils/validators.js';

/**
 * @typedef {Object} SMTPConfig
 * @property {string} host - SMTP server hostname
 * @property {number} port - SMTP server port
 * @property {boolean} secure - Whether to use TLS
 * @property {string} user - SMTP username
 * @property {string} password - SMTP password
 */

/**
 * @typedef {Object} EmailConfig
 * @property {string} from - Sender email address
 * @property {string} to - Recipient email address
 * @property {string} subject - Email subject line
 */

/**
 * @typedef {Object} AppConfig
 * @property {string} user - AutoDNS API username
 * @property {string} password - AutoDNS API password
 * @property {number} context - AutoDNS API context ID
 * @property {string} apiUrl - AutoDNS API base URL
 * @property {string} diebasisDeSpfRecordName - SPF record name for diebasis.de
 * @property {string} diebasisDeSpfRecordValue - SPF record value
 * @property {SMTPConfig} smtp - SMTP server configuration
 * @property {EmailConfig} email - Email configuration
 * @property {string} expectedSpf - Expected SPF record format
 * @property {string} expectedDmarc - Expected DMARC policy
 * @property {string} dmarcReportAuthDomain - Domain for DMARC report authorization
 * @property {string[]} dkimSelectors - DKIM selector names to check
 * @property {string} dkimConfigPath - Path to DKIM configuration file
 * @property {boolean} dryRun - Whether to run in dry-run mode (no changes)
 * @property {boolean} testDomainsEnabled - Whether to use test domains only
 * @property {string[]} testDomains - List of test domains to process
 */

/**
 * Configuration validation error
 */
export class ConfigurationError extends Error {
  /**
   * @param {string} message - Error message
   */
  constructor(message) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

/**
 * Parse and validate SMTP port from environment
 * @returns {number} Valid SMTP port number
 * @throws {ConfigurationError} If port is invalid
 */
function parseSMTPPort() {
  const port = parseInteger(process.env.SMTP_PORT, 587, 1, 65535);
  if (!isValidPort(port)) {
    throw new ConfigurationError(`Invalid SMTP port: ${port}`);
  }
  return port;
}

/**
 * Parse and validate AutoDNS context ID
 * @returns {number} Valid context ID
 * @throws {ConfigurationError} If context is invalid
 */
function parseContext() {
  const context = parseInteger(process.env.AUTODNS_CONTEXT, 4, 1, 999);
  if (isNaN(context)) {
    throw new ConfigurationError('Invalid AUTODNS_CONTEXT value');
  }
  return context;
}

/**
 * Validate email address with proper error message
 * @param {string|undefined} email - Email address to validate (or comma-separated list)
 * @param {string} fieldName - Field name for error message
 * @returns {string} Validated email address(es)
 * @throws {ConfigurationError} If email is invalid
 */
function validateEmailAddress(email, fieldName) {
  if (!email) {
    throw new ConfigurationError(`${fieldName} is required`);
  }
  // Support comma-separated email addresses
  const emails = email.split(',').map(e => e.trim());
  for (const addr of emails) {
    if (!isValidEmail(addr)) {
      throw new ConfigurationError(`Invalid ${fieldName}: ${addr}`);
    }
  }
  return email;
}

/**
 * Validate domain name with proper error message
 * @param {string|undefined} domain - Domain name to validate
 * @param {string} fieldName - Field name for error message
 * @returns {string} Validated domain name
 * @throws {ConfigurationError} If domain is invalid
 */
function validateDomain(domain, fieldName) {
  if (!domain) {
    throw new ConfigurationError(`${fieldName} is required`);
  }
  if (!isValidDomainName(domain)) {
    throw new ConfigurationError(`Invalid ${fieldName}: ${domain}`);
  }
  return domain;
}

/**
 * Application configuration loaded from environment variables with validation.
 *
 * @type {AppConfig}
 *
 * @example
 * import { config } from './config.js';
 * console.log(config.apiUrl); // 'https://api.autodns.com/v1'
 */
export const config = {
  user: process.env.AUTODNS_USER,
  password: process.env.AUTODNS_PASSWORD,
  context: parseContext(),
  apiUrl: process.env.AUTODNS_API_URL || 'https://api.autodns.com/v1',
  diebasisDeSpfRecordName: process.env.DIEBASIS_DE_SPF_RECORD_NAME,
  diebasisDeSpfRecordValue: process.env.DIEBASIS_DE_SPF_RECORD_VALUE,
  smtp: {
    host: process.env.SMTP_HOST,
    port: parseSMTPPort(),
    secure: parseBoolean(process.env.SMTP_SECURE, false),
    user: process.env.SMTP_USER,
    password: process.env.SMTP_PASSWORD,
  },
  email: {
    from: process.env.EMAIL_FROM,
    to: process.env.EMAIL_TO,
    subject: process.env.EMAIL_SUBJECT || 'AutoDNS Domain Health Report',
  },
  expectedSpf: 'v=spf1 a mx include:_spf.diebasis.de -all',
  expectedDmarc: process.env.EXPECTED_DMARC ||
    'v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s;' +
    'rua=mailto:dmarc-reports@diebasis.de;' +
    'ruf=mailto:dmarc-failures@diebasis.de;fo=d:s',
  dmarcReportAuthDomain: process.env.DMARC_REPORT_AUTH_DOMAIN ||
    'diebasis.de',
  dkimSelectors: process.env.DKIM_SELECTORS ?
    process.env.DKIM_SELECTORS.split(',').map((s) => s.trim()) :
    ['s1', 's2'],
  dkimConfigPath: process.env.DKIM_CONFIG_PATH || 'dkim.config.json',
  dryRun: parseBoolean(process.env.DRY_RUN, false) ||
    process.argv.includes('--dry-run'),
  testDomainsEnabled: parseBoolean(process.env.TEST_DOMAINS_ENABLED, false),
  testDomains: process.env.TEST_DOMAINS ?
    process.env.TEST_DOMAINS.split(',').map((s) => s.trim()) :
    [],
};

/**
 * Validate required configuration fields and throw error if missing.
 * This function should be called at application startup.
 *
 * @throws {ConfigurationError} If required configuration is missing or invalid
 *
 * @example
 * try {
 *   validateConfig();
 * } catch (error) {
 *   console.error('Configuration error:', error.message);
 *   process.exit(1);
 * }
 */
export function validateConfig() {
  const errors = [];

  // Validate AutoDNS credentials
  if (!config.user || !config.password) {
    errors.push('Missing AutoDNS credentials (AUTODNS_USER and AUTODNS_PASSWORD)');
  }

  // Validate SPF record configuration
  if (!config.diebasisDeSpfRecordName || !config.diebasisDeSpfRecordValue) {
    errors.push('Missing SPF record configuration ' +
      '(DIEBASIS_DE_SPF_RECORD_NAME and DIEBASIS_DE_SPF_RECORD_VALUE)');
  }

  // Validate email addresses if provided
  if (config.email.from) {
    try {
      validateEmailAddress(config.email.from, 'EMAIL_FROM');
    } catch (error) {
      errors.push(error.message);
    }
  }

  if (config.email.to) {
    try {
      validateEmailAddress(config.email.to, 'EMAIL_TO');
    } catch (error) {
      errors.push(error.message);
    }
  }

  // Validate DKIM config path is safe
  if (config.dkimConfigPath) {
    if (!isSafeFilePath(config.dkimConfigPath, process.cwd())) {
      errors.push(`Unsafe DKIM config path: ${config.dkimConfigPath}`);
    }
  }

  // Validate DMARC report auth domain
  if (config.dmarcReportAuthDomain) {
    try {
      validateDomain(config.dmarcReportAuthDomain, 'DMARC_REPORT_AUTH_DOMAIN');
    } catch (error) {
      errors.push(error.message);
    }
  }

  // Validate test domains if enabled
  if (config.testDomainsEnabled && config.testDomains.length === 0) {
    errors.push('TEST_DOMAINS_ENABLED is true but no TEST_DOMAINS provided');
  }

  if (config.testDomains.length > 0) {
    config.testDomains.forEach((domain) => {
      if (!isValidDomainName(domain)) {
        errors.push(`Invalid test domain: ${domain}`);
      }
    });
  }

  if (errors.length > 0) {
    throw new ConfigurationError(
      `Configuration validation failed:\n  - ${errors.join('\n  - ')}`,
    );
  }
}
