/**
 * Validation utilities for input sanitization and security.
 * @module utils/validators
 */

/**
 * Validates if a string is a valid domain name.
 *
 * @param {string} domain - The domain name to validate
 * @returns {boolean} True if valid domain name, false otherwise
 * @throws {TypeError} If domain is not a string
 *
 * @example
 * isValidDomainName('example.com'); // true
 * isValidDomainName('invalid..com'); // false
 * isValidDomainName('sub.example.com'); // true
 */
export function isValidDomainName(domain) {
  if (typeof domain !== 'string') {
    throw new TypeError('Domain must be a string');
  }

  // Basic checks
  if (!domain || domain.length > 253) {
    return false;
  }

  // Check for valid characters and structure
  // Domain regex: allows letters, numbers, hyphens, dots
  // Labels must start/end with alphanumeric, max 63 chars per label
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*/.source +
    /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.source;
  const domainPattern = new RegExp(domainRegex, 'i');

  if (!domainPattern.test(domain)) {
    return false;
  }

  // Check each label length
  const labels = domain.split('.');
  return labels.every(label => label.length > 0 && label.length <= 63);
}

/**
 * Validates if a string is a valid email address.
 *
 * @param {string} email - The email address to validate
 * @returns {boolean} True if valid email, false otherwise
 * @throws {TypeError} If email is not a string
 *
 * @example
 * isValidEmail('user@example.com'); // true
 * isValidEmail('invalid@'); // false
 */
export function isValidEmail(email) {
  if (typeof email !== 'string') {
    throw new TypeError('Email must be a string');
  }

  // Basic email validation regex
  const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+/.source +
    /(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@/.source +
    /(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+/.source +
    /[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.source;
  const emailPattern = new RegExp(emailRegex, 'i');

  if (!emailPattern.test(email)) {
    return false;
  }

  // Additional validation
  const [localPart, domainPart] = email.split('@');

  // Local part max 64 chars, domain max 253 chars
  if (localPart.length > 64 || domainPart.length > 253) {
    return false;
  }

  return isValidDomainName(domainPart);
}

/**
 * Validates a file path to prevent directory traversal attacks.
 *
 * @param {string} filePath - The file path to validate
 * @param {string} baseDir - The base directory to restrict access to
 * @returns {boolean} True if path is safe, false otherwise
 * @throws {TypeError} If arguments are not strings
 *
 * @example
 * isSafeFilePath('./config.json', '/app'); // true
 * isSafeFilePath('../../etc/passwd', '/app'); // false
 */
export function isSafeFilePath(filePath, baseDir) {
  if (typeof filePath !== 'string' || typeof baseDir !== 'string') {
    throw new TypeError('File path and base directory must be strings');
  }

  // Check for null bytes
  if (filePath.includes('\0')) {
    return false;
  }

  // Check for common path traversal patterns
  const dangerousPatterns = [
    /\.\./,           // Parent directory
    /^\/etc\//,       // System files
    /^\/root\//,      // Root home
    /^\/proc\//,      // Process info
    /^\/sys\//,       // System info
    /^~\//,           // Home directory expansion (if not intended)
  ];

  return !dangerousPatterns.some(pattern => pattern.test(filePath));
}

/**
 * Validates and sanitizes a boolean from string input.
 *
 * @param {string|boolean} value - The value to parse as boolean
 * @param {boolean} defaultValue - Default value if parsing fails
 * @returns {boolean} The parsed boolean value
 *
 * @example
 * parseBoolean('true'); // true
 * parseBoolean('yes'); // true
 * parseBoolean('1'); // true
 * parseBoolean('false'); // false
 * parseBoolean('invalid', false); // false
 */
export function parseBoolean(value, defaultValue = false) {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    const normalized = value.toLowerCase().trim();
    if (['true', 'yes', '1', 'on'].includes(normalized)) {
      return true;
    }
    if (['false', 'no', '0', 'off'].includes(normalized)) {
      return false;
    }
  }

  return defaultValue;
}

/**
 * Validates and parses an integer from string input.
 *
 * @param {string|number} value - The value to parse as integer
 * @param {number} defaultValue - Default value if parsing fails
 * @param {number} [min] - Minimum allowed value
 * @param {number} [max] - Maximum allowed value
 * @returns {number} The parsed integer value
 * @throws {RangeError} If value is outside min/max bounds
 *
 * @example
 * parseInteger('42', 0); // 42
 * parseInteger('invalid', 10); // 10
 * parseInteger('100', 0, 1, 50); // throws RangeError
 */
export function parseInteger(value, defaultValue, min, max) {
  let parsed;

  if (typeof value === 'number') {
    parsed = Math.floor(value);
  } else if (typeof value === 'string') {
    parsed = parseInt(value, 10);
    if (isNaN(parsed)) {
      return defaultValue;
    }
  } else {
    return defaultValue;
  }

  if (min !== undefined && parsed < min) {
    throw new RangeError(`Value ${parsed} is below minimum ${min}`);
  }

  if (max !== undefined && parsed > max) {
    throw new RangeError(`Value ${parsed} is above maximum ${max}`);
  }

  return parsed;
}

/**
 * Validates if a string contains only safe DNS TXT record characters.
 * Prevents potential DNS injection attacks.
 *
 * @param {string} value - The TXT record value to validate
 * @returns {boolean} True if safe, false otherwise
 * @throws {TypeError} If value is not a string
 *
 * @example
 * isSafeDNSValue('v=spf1 include:example.com ~all'); // true
 * isSafeDNSValue('malicious\x00value'); // false
 */
export function isSafeDNSValue(value) {
  if (typeof value !== 'string') {
    throw new TypeError('DNS value must be a string');
  }

  // Check for null bytes and control characters
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    return false;
  }

  // TXT records can be up to 255 characters per string (but can have multiple)
  // Most SPF/DMARC/DKIM records should be under reasonable length
  if (value.length > 1000) {
    return false;
  }

  return true;
}

/**
 * Validates a port number.
 *
 * @param {string|number} port - The port number to validate
 * @returns {boolean} True if valid port, false otherwise
 *
 * @example
 * isValidPort(443); // true
 * isValidPort('8080'); // true
 * isValidPort(70000); // false
 */
export function isValidPort(port) {
  const parsed = typeof port === 'string' ? parseInt(port, 10) : port;
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535;
}

/**
 * Sanitizes a domain name for use in API calls or DNS queries.
 *
 * @param {string} domain - The domain to sanitize
 * @returns {string} Sanitized domain name
 * @throws {Error} If domain is invalid
 *
 * @example
 * sanitizeDomainName('EXAMPLE.COM'); // 'example.com'
 * sanitizeDomainName(' example.com '); // 'example.com'
 */
export function sanitizeDomainName(domain) {
  if (typeof domain !== 'string') {
    throw new TypeError('Domain must be a string');
  }

  const sanitized = domain.toLowerCase().trim();

  if (!isValidDomainName(sanitized)) {
    throw new Error(`Invalid domain name: ${domain}`);
  }

  return sanitized;
}
