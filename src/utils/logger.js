/**
 * Structured logging utility using Pino.
 *
 * Provides centralized logging with structured JSON output, log levels,
 * and development-friendly pretty printing.
 *
 * @module utils/logger
 */

import pino from 'pino';

/**
 * @typedef {Object} LoggerConfig
 * @property {string} level - Log level (trace, debug, info, warn, error, fatal)
 * @property {boolean} prettify - Whether to use pretty printing (for development)
 */

/**
 * Determine if we're in production environment
 * @returns {boolean} True if in production
 */
function isProduction() {
  return process.env.NODE_ENV === 'production';
}

/**
 * Get the log level from environment or default
 * @returns {string} Log level
 */
function getLogLevel() {
  return process.env.LOG_LEVEL || (isProduction() ? 'info' : 'debug');
}

/**
 * Create logger transport configuration
 * @returns {Object} Pino transport configuration
 */
function getTransport() {
  // In development, use pretty printing
  if (!isProduction() && process.env.LOG_PRETTY !== 'false') {
    return {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname',
      },
    };
  }

  // In production, use JSON output
  return undefined;
}

/**
 * Create and configure the logger instance.
 *
 * The logger automatically adjusts its configuration based on environment:
 * - Development: Pretty-printed colored output with debug level
 * - Production: Structured JSON output with info level
 *
 * @returns {import('pino').Logger} Configured Pino logger instance
 *
 * @example
 * import { logger } from './utils/logger.js';
 *
 * logger.info('Processing domain', { domain: 'example.com' });
 * logger.error({ err: error }, 'Failed to update DNS');
 * logger.debug({ record: spfRecord }, 'SPF record validated');
 */
function createLogger() {
  const transport = getTransport();

  const config = {
    level: getLogLevel(),
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label) => {
        return { level: label };
      },
    },
  };

  if (transport) {
    config.transport = transport;
  }

  // Create logger with explicit stdout destination to avoid buffering issues
  // pino.destination(1) creates a synchronous write stream to stdout (fd 1)
  return pino(config, pino.destination({ dest: 1, sync: false }));
}

/**
 * Global logger instance.
 *
 * @type {import('pino').Logger}
 *
 * @example
 * import { logger } from './utils/logger.js';
 *
 * // Basic logging
 * logger.info('Application started');
 * logger.warn('Configuration missing, using defaults');
 *
 * // Structured logging with context
 * logger.info({ domain: 'example.com', records: 5 }, 'Domain processed');
 *
 * // Error logging with error object
 * logger.error({ err: error }, 'Failed to query AutoDNS API');
 *
 * // Child logger with persistent context
 * const domainLogger = logger.child({ domain: 'example.com' });
 * domainLogger.info('Starting health checks');
 * domainLogger.debug({ check: 'SPF' }, 'Check passed');
 */
export const logger = createLogger();

/**
 * Create a child logger with additional context.
 *
 * Child loggers inherit configuration from parent but add
 * persistent bindings that appear in all log messages.
 *
 * @param {Object} bindings - Context to bind to all log messages
 * @returns {import('pino').Logger} Child logger instance
 *
 * @example
 * const domainLogger = createChildLogger({ domain: 'example.com' });
 * domainLogger.info('Processing started'); // Includes domain in every log
 *
 * const requestLogger = createChildLogger({ requestId: '123-456' });
 * requestLogger.debug('API call initiated'); // Includes requestId
 */
export function createChildLogger(bindings) {
  return logger.child(bindings);
}

/**
 * Log levels available in the logger.
 *
 * @enum {string}
 * @readonly
 *
 * @example
 * import { logger, LOG_LEVELS } from './utils/logger.js';
 *
 * logger.level = LOG_LEVELS.DEBUG;
 */
export const LOG_LEVELS = {
  TRACE: 'trace',
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
  FATAL: 'fatal',
};

/**
 * Wrapper to safely log error objects with full context.
 *
 * @param {import('pino').Logger} loggerInstance - Logger instance to use
 * @param {Error} error - Error object to log
 * @param {string} message - Human-readable error message
 * @param {Object} [context={}] - Additional context to include
 *
 * @example
 * try {
 *   await riskyOperation();
 * } catch (error) {
 *   logError(logger, error, 'Failed to perform risky operation', {
 *     domain: 'example.com',
 *     attempt: 3
 *   });
 * }
 */
export function logError(loggerInstance, error, message, context = {}) {
  loggerInstance.error(
    {
      err: error,
      errorMessage: error.message,
      errorStack: error.stack,
      ...context,
    },
    message,
  );
}

export default logger;
