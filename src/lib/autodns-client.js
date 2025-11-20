import axios from 'axios';
import pRetry, { AbortError } from 'p-retry';
import { config } from './config.js';
import { logger, logError } from '../utils/logger.js';
import { sanitizeDomainName } from '../utils/validators.js';

/**
 * @typedef {Object} RateLimiter
 * @property {number} capacity - Maximum tokens available
 * @property {number} tokens - Current available tokens
 * @property {Function[]} queue - Queue of pending requests
 */

/**
 * @typedef {Object} AutoDNSResponse
 * @property {Object} status - Response status information
 * @property {string} status.type - Status type (SUCCESS, ERROR, etc.)
 * @property {string} [status.text] - Status description
 * @property {Object} [data] - Response data
 */

/**
 * Rate limiting constants for AutoDNS API
 */
const RATE_LIMIT = {
  CAPACITY: 3,
  REFILL_INTERVAL: 1000, // milliseconds
};

/**
 * Retry configuration for API calls
 */
const RETRY_CONFIG = {
  RETRIES: 3,
  MIN_TIMEOUT: 1000, // Initial retry delay in ms
  MAX_TIMEOUT: 5000, // Maximum retry delay in ms
  FACTOR: 2, // Exponential backoff factor
};

/**
 * Rate limiter for AutoDNS API: max 3 requests per second.
 *
 * @type {RateLimiter}
 */
const autodnsRate = {
  capacity: RATE_LIMIT.CAPACITY,
  tokens: RATE_LIMIT.CAPACITY,
  queue: [],
};

// Refill tokens every second
let refillTimer = setInterval(() => {
  autodnsRate.tokens = autodnsRate.capacity;
  const processed = [];
  while (autodnsRate.tokens > 0 && autodnsRate.queue.length > 0) {
    autodnsRate.tokens--;
    const resolve = autodnsRate.queue.shift();
    processed.push(resolve);
  }
  // Process resolves after updating state to avoid race conditions
  processed.forEach((resolve) => resolve());
}, RATE_LIMIT.REFILL_INTERVAL);

// Allow process to exit naturally even if the timer is active
if (typeof refillTimer.unref === 'function') {
  refillTimer.unref();
}

/**
 * Rate limit AutoDNS API calls to comply with API limits.
 *
 * Implements a token bucket algorithm with 3 tokens refilled per second.
 * If tokens are available, resolves immediately. Otherwise, queues the
 * request until tokens become available.
 *
 * @async
 * @returns {Promise<void>} Resolves when rate limit allows request
 *
 * @example
 * await rateLimitAutoDNS();
 * // Now safe to make API call
 * const response = await axios.get(...);
 */
export function rateLimitAutoDNS() {
  if (autodnsRate.tokens > 0) {
    autodnsRate.tokens--;
    logger.trace(
      { tokensRemaining: autodnsRate.tokens },
      'Rate limit token consumed',
    );
    return Promise.resolve();
  }

  logger.debug(
    { queueLength: autodnsRate.queue.length + 1 },
    'Rate limit reached, queueing request',
  );

  return new Promise((resolve) => autodnsRate.queue.push(resolve));
}

/**
 * Stop the AutoDNS rate limiter timer to allow clean shutdown.
 *
 * Should be called during application shutdown to ensure the process
 * exits cleanly.
 *
 * @example
 * process.on('SIGTERM', () => {
 *   shutdownAutoDNSRateLimiter();
 *   process.exit(0);
 * });
 */
export function shutdownAutoDNSRateLimiter() {
  if (refillTimer) {
    clearInterval(refillTimer);
    refillTimer = null;
    logger.debug('AutoDNS rate limiter shutdown');
  }
}

/**
 * Determine if an error is retryable.
 *
 * @param {Error} error - Error to check
 * @returns {boolean} True if error should trigger retry
 */
function isRetryableError(error) {
  // Network errors are retryable
  if (error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT' ||
      error.code === 'ENOTFOUND') {
    return true;
  }

  // HTTP 5xx errors are retryable
  if (error.response && error.response.status >= 500) {
    return true;
  }

  // HTTP 429 (Too Many Requests) is retryable
  if (error.response && error.response.status === 429) {
    return true;
  }

  return false;
}

/**
 * Query all domains from AutoDNS API with retry logic.
 *
 * Retrieves all domains from the AutoDNS account with automatic retry
 * on transient failures. Rate-limited to comply with API restrictions.
 *
 * @async
 * @returns {Promise<Object>} API response with domain data
 * @throws {Error} If all retry attempts fail or non-retryable error occurs
 *
 * @example
 * try {
 *   const response = await queryDomains();
 *   const domains = response.data;
 *   console.log(`Retrieved ${domains.length} domains`);
 * } catch (error) {
 *   console.error('Failed to query domains:', error.message);
 * }
 */
export async function queryDomains() {
  logger.info('Querying domains from AutoDNS API');

  return pRetry(
    async () => {
      await rateLimitAutoDNS();

      try {
        const response = await axios.post(
          `${config.apiUrl}/domain/_search`,
          {
            filters: [],
            view: {
              children: true,
              limit: 10000,
            },
          },
          {
            auth: {
              username: config.user,
              password: config.password,
            },
            headers: {
              'Content-Type': 'application/json',
              'X-Domainrobot-Context': config.context,
            },
          },
        );

        logger.info(
          { count: response.data?.data?.length || 0 },
          'Successfully retrieved domains',
        );

        return response.data;
      } catch (error) {
        if (error.response) {
          logger.error(
            {
              status: error.response.status,
              statusText: error.response.statusText,
              data: error.response.data,
            },
            'AutoDNS API error',
          );
        } else {
          logError(logger, error, 'Network error querying domains');
        }

        if (!isRetryableError(error)) {
          throw new AbortError(error);
        }

        throw error;
      }
    },
    {
      retries: RETRY_CONFIG.RETRIES,
      minTimeout: RETRY_CONFIG.MIN_TIMEOUT,
      maxTimeout: RETRY_CONFIG.MAX_TIMEOUT,
      factor: RETRY_CONFIG.FACTOR,
      onFailedAttempt: (error) => {
        logger.warn(
          {
            attempt: error.attemptNumber,
            retriesLeft: error.retriesLeft,
            error: error.message,
          },
          'Domain query attempt failed, retrying',
        );
      },
    },
  );
}

/**
 * Get zone information for a domain with retry logic.
 *
 * Retrieves DNS zone configuration including all records for the specified
 * domain. Validates domain name before making API call.
 *
 * @async
 * @param {string} zoneName - Domain name (will be sanitized)
 * @returns {Promise<Object>} Zone data from API
 * @throws {Error} If zone retrieval fails or domain name is invalid
 *
 * @example
 * const zone = await getZone('example.com');
 * console.log('Zone has', zone.data.records.length, 'DNS records');
 */
export async function getZone(zoneName) {
  const sanitizedZone = sanitizeDomainName(zoneName);
  logger.debug({ zone: sanitizedZone }, 'Getting zone information');

  return pRetry(
    async () => {
      await rateLimitAutoDNS();

      try {
        const response = await axios.get(
          `${config.apiUrl}/zone/${sanitizedZone}`,
          {
            auth: {
              username: config.user,
              password: config.password,
            },
            headers: {
              'Content-Type': 'application/json',
              'X-Domainrobot-Context': config.context,
            },
          },
        );

        logger.debug(
          {
            zone: sanitizedZone,
            recordCount: response.data?.data?.records?.length || 0,
          },
          'Zone retrieved successfully',
        );

        return response.data;
      } catch (error) {
        if (error.response) {
          logger.error(
            {
              zone: sanitizedZone,
              status: error.response.status,
              statusText: error.response.statusText,
            },
            'API error getting zone',
          );
        } else {
          logError(logger, error, 'Network error getting zone', {
            zone: sanitizedZone,
          });
        }

        if (!isRetryableError(error)) {
          throw new AbortError(error);
        }

        throw error;
      }
    },
    {
      retries: RETRY_CONFIG.RETRIES,
      minTimeout: RETRY_CONFIG.MIN_TIMEOUT,
      maxTimeout: RETRY_CONFIG.MAX_TIMEOUT,
      factor: RETRY_CONFIG.FACTOR,
      onFailedAttempt: (error) => {
        logger.warn(
          {
            zone: sanitizedZone,
            attempt: error.attemptNumber,
            retriesLeft: error.retriesLeft,
          },
          'Get zone attempt failed, retrying',
        );
      },
    },
  );
}

/**
 * Update zone with new/updated DNS record with retry logic.
 *
 * Updates DNS zone configuration. In dry-run mode, logs the intended
 * change without making actual API call. Automatically removes read-only
 * fields from the payload.
 *
 * @async
 * @param {string} zoneName - Domain name (will be sanitized)
 * @param {Object} zoneData - Complete zone data to update
 * @returns {Promise<AutoDNSResponse>} API response
 * @throws {Error} If zone update fails
 *
 * @example
 * const zone = await getZone('example.com');
 * zone.data.records.push({
 *   name: 'www',
 *   type: 'A',
 *   value: '192.0.2.1',
 *   ttl: 3600
 * });
 * await updateZone('example.com', zone.data);
 */
export async function updateZone(zoneName, zoneData) {
  const sanitizedZone = sanitizeDomainName(zoneName);

  if (config.dryRun) {
    logger.info(
      { zone: sanitizedZone },
      '[DRY-RUN] Would update zone',
    );
    console.log(`[DRY-RUN] Would update zone: ${sanitizedZone}`);
    return {
      status: {
        type: 'SUCCESS',
        text: 'Dry-run mode: no changes made',
      },
    };
  }

  logger.info({ zone: sanitizedZone }, 'Updating zone');

  return pRetry(
    async () => {
      await rateLimitAutoDNS();

      try {
        // Send complete zone object to preserve all settings
        // Remove read-only fields that shouldn't be sent in PUT requests
        const updatePayload = { ...zoneData };
        const readOnlyFields = [
          'created',
          'updated',
          'owner',
          'updater',
          'roid',
        ];
        readOnlyFields.forEach((field) => delete updatePayload[field]);

        const response = await axios.put(
          `${config.apiUrl}/zone/${sanitizedZone}`,
          updatePayload,
          {
            auth: {
              username: config.user,
              password: config.password,
            },
            headers: {
              'Content-Type': 'application/json',
              'X-Domainrobot-Context': config.context,
            },
          },
        );

        logger.info(
          { zone: sanitizedZone },
          'Zone updated successfully',
        );

        return response.data;
      } catch (error) {
        if (error.response) {
          logger.error(
            {
              zone: sanitizedZone,
              status: error.response.status,
              statusText: error.response.statusText,
              data: error.response.data,
            },
            'API error updating zone',
          );
        } else {
          logError(logger, error, 'Network error updating zone', {
            zone: sanitizedZone,
          });
        }

        if (!isRetryableError(error)) {
          throw new AbortError(error);
        }

        throw error;
      }
    },
    {
      retries: RETRY_CONFIG.RETRIES,
      minTimeout: RETRY_CONFIG.MIN_TIMEOUT,
      maxTimeout: RETRY_CONFIG.MAX_TIMEOUT,
      factor: RETRY_CONFIG.FACTOR,
      onFailedAttempt: (error) => {
        logger.warn(
          {
            zone: sanitizedZone,
            attempt: error.attemptNumber,
            retriesLeft: error.retriesLeft,
          },
          'Update zone attempt failed, retrying',
        );
      },
    },
  );
}
