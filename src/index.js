#!/usr/bin/env node

import {
  config,
  validateConfig,
  ConfigurationError,
} from './lib/config.js';
import {
  queryDomains,
  shutdownAutoDNSRateLimiter,
} from './lib/autodns-client.js';
import { buildFlattenedSpfRecord, updateMainSPFRecord }
  from './lib/spf.js';
import { processDomains } from './lib/domain-processor.js';
import { saveReport, sendReportByEmail } from './lib/reporting.js';
import { colors } from './utils/helpers.js';
import { logger, logError } from './utils/logger.js';

/**
 * Main execution function for AutoDNS domain health monitoring.
 *
 * This function orchestrates the entire domain health check workflow:
 * 1. Validates configuration
 * 2. Queries domains from AutoDNS API
 * 3. Builds flattened SPF record
 * 4. Processes domains and performs health checks
 * 5. Updates DNS records as needed
 * 6. Generates and sends report
 *
 * @async
 * @returns {Promise<void>}
 * @throws {ConfigurationError} If configuration is invalid
 * @throws {Error} If domain retrieval or processing fails
 */
async function main() {
  console.log('AutoDNS Domain Query Tool');
  console.log('========================\n');

  logger.info('Application starting');

  if (config.dryRun) {
    console.log(`${colors.bold}*** DRY-RUN MODE ENABLED ***${colors.reset}`);
    console.log('No changes will be made to AutoDNS records.\n');
    logger.info('Running in DRY-RUN mode');
  }

  try {
    validateConfig();
    logger.info('Configuration validated successfully');
  } catch (error) {
    if (error instanceof ConfigurationError) {
      console.error(`${colors.red}Configuration Error:${colors.reset}`);
      console.error(error.message);
      console.error('\nPlease check your .env file. ' +
        'See .env.example for reference');
      logError(logger, error, 'Configuration validation failed');
      process.exit(1);
    }
    throw error;
  }

  console.log(`Querying domains from ${config.apiUrl}...`);
  logger.info({ apiUrl: config.apiUrl }, 'Querying domains from AutoDNS');

  try {
    const data = await queryDomains();
    logger.info({ domainCount: data?.length || 0 }, 'Domains retrieved');

    // Resolve all SPF includes and build flattened record
    logger.debug('Building flattened SPF record');
    const flattenedSpf = await buildFlattenedSpfRecord(
      config.mainSpfRecordValue,
    );
    logger.info({ record: flattenedSpf }, 'Flattened SPF record built');

    // Generate the main report with flattening info included
    logger.info('Processing domains and performing health checks');
    const reportContent = await processDomains(
      data,
      config.mainSpfRecordValue,
      flattenedSpf,
    );

    logger.debug('Updating main SPF record');
    await updateMainSPFRecord(
      config.mainSpfRecordName,
      flattenedSpf,
    );

    // Save report to file
    logger.debug('Saving report to file');
    await saveReport(reportContent);
    logger.info('Report saved successfully');

    // Send the report by email if configured
    if (config.smtp.host && config.email.to) {
      logger.debug({ to: config.email.to }, 'Sending report via email');
      await sendReportByEmail(reportContent);
      logger.info('Report sent via email');
    } else {
      console.log('\nEmail sending is not configured. ' +
        'Skipping email notification.');
      logger.info('Email not configured, skipping notification');
    }

    logger.info('Domain health check completed successfully');
  } catch (error) {
    console.error(`\n${colors.red}Error:${colors.reset} ` +
      'Failed to process domains');
    console.error(error.message);
    if (error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    logError(logger, error, 'Domain processing failed');
    process.exit(1);
  } finally {
    // Ensure timers are cleared so the process can exit cleanly
    shutdownAutoDNSRateLimiter();
    logger.debug('AutoDNS rate limiter shutdown');
  }
}

main();