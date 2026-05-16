import { getZone } from './autodns-client.js';
import { getSPFRecord, updateDomainSPFRecord } from './spf.js';
import {
  getDMARCRecord,
  normalizeDMARC,
  updateDomainDMARCRecord,
  addDMARCReportAuthRecord,
} from './dmarc.js';
import {
  checkDKIMRecords,
  listZoneDKIMRecords,
  updateDomainDKIMRecord,
  loadDkimConfig,
  saveDkimConfig,
} from './dkim.js';
import { getARecords, getAAAARecords, getMXRecords } from './dns-operations.js';
import {
  checkNS,
  checkSOA,
  checkCAA,
  checkMtaSts,
  checkTlsRpt,
  checkPTRForOutbound,
  checkMXIntegrity,
  buildHealthSummary,
  usesAutoDNSNameservers,
} from './health-checks.js';
import { colors, formatTimestamp } from '../utils/helpers.js';
import { config } from './config.js';

/**
 * Process and check all domains
 * @param {object} data - API response with domain data
 * @param {string} originalSpf - Original SPF value
 * @param {object} spfData - SPF data object with mainRecord, chunkRecords, needsSplit
 * @returns {Promise<{reportContent: string, hasFailures: boolean}>} Report content and failure flag
 */
export async function processDomains(data, originalSpf, spfData) {
  // Check for errors
  if (!data || data.status?.type === 'ERROR') {
    console.log(
      'Error in API response:',
      data?.status?.text || 'Unknown error',
    );
    return { reportContent: '', hasFailures: true };
  }

  // The API returns data directly at the root level
  let domains = data.data || [];

  console.log(`\nFound ${domains.length} domain(s) total`);

  if (domains.length === 0) {
    console.log('No domains found in this account.');
    return { reportContent: '', hasFailures: false };
  }

  // Limit to specific domains for testing (if enabled)
  if (config.testDomainsEnabled && config.testDomains.length > 0) {
    domains = domains.filter((d) =>
      config.testDomains.includes(d.name || d.origin),
    );
  }

  // Sort domains alphabetically by name
  domains.sort((a, b) => {
    const nameA = (a.name || a.origin || '').toLowerCase();
    const nameB = (b.name || b.origin || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });

  if (config.testDomainsEnabled) {
    const testingList = domains.map((d) => d.name || d.origin).join(', ');
    console.log(`Testing with domain(s): ${testingList || 'none found'}\n`);
  }

  // Build output for both console and file
  let domainDetailsOutput = '';
  let hasFailures = false;

  // Track failures by type for summary
  // MTA, TLS, PTR are informational only and not tracked here
  const failuresByType = {
    SPF: [],
    DMARC: [],
    DKIM: [],
    A: [],
    AAAA: [],
    SOA: [],
    NS: [],
    CAA: [],
  };

  const counts = {
    total: domains.length,
    spf: { ok: 0, fail: 0, error: 0, skipped: 0 },
    dmarc: { ok: 0, fail: 0, error: 0, skipped: 0 },
    dkim: { ok: 0, fail: 0, error: 0, skipped: 0 },
    a: { ok: 0, fail: 0, error: 0, skipped: 0 },
    aaaa: { ok: 0, fail: 0, error: 0, skipped: 0 },
  };

  // Load desired DKIM config
  const dkimConfig = await loadDkimConfig();

  // Ensure all domains have an entry in dkimConfig with default selector
  let configUpdated = false;
  for (const domain of domains) {
    const domainName = domain.name || domain.origin;
    if (!dkimConfig[domainName]) {
      dkimConfig[domainName] = { default: '' };
      configUpdated = true;
    }
  }

  // Save updated config if new domains were added
  if (configUpdated) {
    try {
      await saveDkimConfig(dkimConfig);
      console.log('Updated dkim.config.json with new domains\n');
    } catch (e) {
      console.error('Failed to save dkim.config.json:', e.message);
    }
  }

  // Query SPF, DMARC, and DKIM records for all domains
  for (const domain of domains) {
    const domainName = domain.name || domain.origin;
    const timestamp = formatTimestamp();

    try {
      console.log(`Processing ${domainName}...`);
      const result = await checkDomain(domainName, dkimConfig);

      // Parse health summary
      const healthParts = {};
      result.healthSummary.split('; ').forEach((part) => {
        const [key, value] = part.split(':');
        healthParts[key] = value;
      });

      // Determine A/AAAA status
      const aStatus = result.aDisplay !== '-' ? 'ok' : 'fail';
      const aaaaStatus = result.aaaaDisplay !== '-' ? 'ok' : 'fail';

      // Collect failures by type and update counts
      countCheckResult(result.spfStatus, 'spf', counts, failuresByType, domainName);
      countCheckResult(result.dmarcStatus, 'dmarc', counts, failuresByType, domainName);
      countCheckResult(result.dkimStatus, 'dkim', counts, failuresByType, domainName);

      counts.a[aStatus === 'ok' ? 'ok' : 'fail']++;
      if (aStatus === 'fail') {failuresByType.A.push(domainName);}
      counts.aaaa[aaaaStatus === 'ok' ? 'ok' : 'fail']++;
      if (aaaaStatus === 'fail') {failuresByType.AAAA.push(domainName);}

      if (healthParts.SOA === 'fail') {
        failuresByType.SOA.push(domainName);
      }
      if (healthParts.NS === 'fail') {
        failuresByType.NS.push(domainName);
      }
      if (healthParts.CAA === 'fail') {
        failuresByType.CAA.push(domainName);
      }

      // Check for any failures or errors (SPF/DMARC/DKIM and A/AAAA;
      // MTA, TLS, PTR are informational only and don't trigger email)
      if (
        isFailureStatus(result.spfStatus) ||
        isFailureStatus(result.dmarcStatus) ||
        isFailureStatus(result.dkimStatus) ||
        aStatus === 'fail' ||
        aaaaStatus === 'fail'
      ) {
        hasFailures = true;
      }

      // Write output to both file and console
      const detailLines = formatDomainResultLines(
        timestamp, domainName, result, aStatus, aaaaStatus, healthParts);
      domainDetailsOutput += `${detailLines.join('\n')  }\n\n`;
      detailLines.forEach((line) => console.log(line));
      console.log('');
    } catch (err) {
      const msg = err?.message || String(err);
      console.error(`${timestamp} ${domainName}`);
      console.error(`    ERROR: processing failed: ${msg}`);
      console.log(''); // Empty line
      domainDetailsOutput += `${timestamp} ${domainName}\n`;
      domainDetailsOutput += `    ERROR: processing failed: ${msg}\n\n`;
      hasFailures = true; // Mark as failure due to processing error
      counts.spf.error++;
      counts.dmarc.error++;
      counts.dkim.error++;
      counts.a.error++;
      counts.aaaa.error++;
      failuresByType.SPF.push(domainName);
      failuresByType.DMARC.push(domainName);
      failuresByType.DKIM.push(domainName);
      failuresByType.A.push(domainName);
      failuresByType.AAAA.push(domainName);
      // continue with next domain
    }
  }

  console.log(`\nExpected SPF: ${config.expectedSpf}`);
  console.log(`Expected DMARC: ${config.expectedDmarc}\n`);

  // Build final report with 3 sections
  let reportContent = '';

  // Section 1: Summary
  reportContent += '=======\nSUMMARY\n=======\n';
  reportContent += `- SPF   (TOTAL: ${counts.total} | OK: ${counts.spf.ok} | FAILED: ${counts.spf.fail} | ERRORS: ${counts.spf.error} | SKIPPED: ${counts.spf.skipped})\n`;
  reportContent += `- DMARC (TOTAL: ${counts.total} | OK: ${counts.dmarc.ok} | FAILED: ${counts.dmarc.fail} | ERRORS: ${counts.dmarc.error} | SKIPPED: ${counts.dmarc.skipped})\n`;
  reportContent += `- DKIM  (TOTAL: ${counts.total} | OK: ${counts.dkim.ok} | FAILED: ${counts.dkim.fail} | ERRORS: ${counts.dkim.error} | SKIPPED: ${counts.dkim.skipped})\n`;
  reportContent += `- A     (TOTAL: ${counts.total} | OK: ${counts.a.ok} | FAILED: ${counts.a.fail} | ERRORS: ${counts.a.error} | SKIPPED: ${counts.a.skipped})\n`;
  reportContent += `- AAAA  (TOTAL: ${counts.total} | OK: ${counts.aaaa.ok} | FAILED: ${counts.aaaa.fail} | ERRORS: ${counts.aaaa.error} | SKIPPED: ${counts.aaaa.skipped})\n\n`;

  // Section 2: Failure Details by Type
  reportContent += '==================\nFailure Details by Type\n==================\n';
  for (const [type, domains] of Object.entries(failuresByType)) {
    reportContent += `${type} (${domains.length}):\n`;
    if (domains.length === 0) {
      reportContent += '  None\n';
    } else {
      for (const d of domains) {
        reportContent += `  - ${d}\n`;
      }
    }
    reportContent += '\n';
  }

  // Section 3: Domain Check Results
  reportContent += `Expected SPF:   ${config.expectedSpf}\n`;
  reportContent += `Expected DMARC: ${config.expectedDmarc}\n\n`;
  reportContent += '====================\nDOMAIN CHECK RESULTS\n====================\n\n';
  reportContent += domainDetailsOutput;

  // Append SPF flattening information to the report
  if (originalSpf && spfData) {
    reportContent += '\n==============\nSPF Flattening\n==============\n\n';
    reportContent += `Original:\n${originalSpf}\n\n`;

    if (spfData.needsSplit) {
      reportContent += `Split into ${spfData.chunkRecords.length} chunks (to avoid DNS UDP fragmentation):\n\n`;
      spfData.chunkRecords.forEach((chunk, index) => {
        reportContent += `Chunk ${index + 1} (_spf${index + 1}):\n${chunk}\n\n`;
      });
      reportContent += `Main Record (_spf):\n${spfData.mainRecord}\n`;
    } else {
      reportContent += `Flattened (single record):\n${spfData.mainRecord}\n`;
    }
  }

  return { reportContent, hasFailures };
}

/**
 * Evaluate whether a DNS record matches the expected value and populate result.
 *
 * Handles the three-way branch: correct match, mismatch (value present but wrong),
 * or missing (no record). Populates the result object's checkConsole, record, and
 * status fields for the given label.
 *
 * @param {string|null} current - Current parsed value (normalized for comparison)
 * @param {string} expected - Expected value (normalized)
 * @param {'spf'|'dmarc'} label - Lowercase protocol label
 * @param {Object} result - Check-domain result object (populated in place)
 * @param {string} [displayValue] - Original value for display (falls back to current)
 * @returns {{needsUpdate: boolean, currentValue: string}}
 */
function evaluateCheckResult(current, expected, label, result, displayValue) {
  const shown = displayValue !== undefined ? displayValue : current;
  const upper = label.toUpperCase();

  if (current === expected) {
    result[`${label}CheckConsole`] = `${colors.green}✓${colors.reset}`;
    result[`${label}Record`] = `${upper}: Correct`;
    result[`${label}Status`] = 'ok';
    return { needsUpdate: false, currentValue: '' };
  }

  result[`${label}CheckConsole`] = `${colors.red}✗${colors.reset}`;
  if (current) {
    result[`${label}Record`] = `${upper}: ${shown}`;
    result[`${label}Status`] = 'needs-update';
    return { needsUpdate: true, currentValue: shown };
  }
  result[`${label}Record`] = `${upper}: No record`;
  result[`${label}Status`] = 'needs-update';
  return { needsUpdate: true, currentValue: `No ${upper} record` };
}

/**
 * Return true if a status string represents a failure condition.
 *
 * Matches countCheckResult's classification: fail, error, and needs-update
 * are failure states; ok and skipped are not.
 *
 * @param {string} status - A status string (e.g., 'fail "No records"',
 *   'error "timeout"', 'needs-update')
 * @returns {boolean}
 */
function isFailureStatus(status) {
  return status.startsWith('fail') ||
         status.startsWith('error') ||
         status.startsWith('needs-update');
}

/**
 * Tally a single check result into running counts and failure tracking.
 *
 * @param {string} statusField - The status string from the result
 *   (ok / fail / error / skipped / needs-update)
 * @param {'spf'|'dmarc'|'dkim'} type - Protocol key for counts/failures
 * @param {Object} counts - Running counts object
 * @param {Object} failuresByType - Per-type failure domain lists
 * @param {string} domainName - Current domain name
 */
function countCheckResult(statusField, type, counts, failuresByType, domainName) {
  if (statusField.startsWith('ok')) {
    counts[type].ok++;
  } else if (statusField.startsWith('fail')) {
    counts[type].fail++;
    failuresByType[type.toUpperCase()].push(domainName);
  } else if (statusField.startsWith('error')) {
    counts[type].error++;
    failuresByType[type.toUpperCase()].push(domainName);
  } else if (statusField.startsWith('skipped')) {
    counts[type].skipped++;
  } else if (statusField.startsWith('needs-update')) {
    counts[type].fail++;
    failuresByType[type.toUpperCase()].push(domainName);
  }
}

/**
 * Attempt to apply a DNS record update and update status fields.
 *
 * @param {'spf'|'dmarc'} label - Lowercase protocol label
 * @param {boolean} needsUpdate - Whether an update is required
 * @param {Function} updateFn - Async function performing the update
 * @param {string} currentValue - Previous value for status message
 * @param {Object} result - Check-domain result object (populated in place)
 */
async function applyProtocolUpdate(label, needsUpdate, updateFn, currentValue, result) {
  if (!needsUpdate) {
    if (result[`${label}Status`] === 'error') {
      result[`${label}Status`] = `error "${currentValue}"`;
    }
    return;
  }

  try {
    await updateFn();
    result[`${label}CheckConsole`] = `${colors.green}✓${colors.reset}(updated)`;
    result[`${label}Record`] = `${label.toUpperCase()}: Correct (updated)`;
    result[`${label}Status`] = `ok - updated from "${currentValue}"`;
  } catch (error) {
    result[`${label}CheckConsole`] = `${colors.red}✗${colors.reset}(failed)`;
    result[`${label}Status`] = `error "Update failed: ${error.message}"`;
  }
}

/**
 * Build a consistent array of domain-check detail lines (for console and file output).
 *
 * @param {string} timestamp
 * @param {string} domainName
 * @param {Object} result
 * @param {string} aStatus
 * @param {string} aaaaStatus
 * @param {Object} healthParts
 * @returns {string[]}
 */
function formatDomainResultLines(timestamp, domainName, result, aStatus, aaaaStatus, healthParts) {
  return [
    `${timestamp} ${domainName}`,
    `    SPF:        ${result.spfStatus}`,
    `    DMARC:      ${result.dmarcStatus}`,
    `    DKIM:       ${result.dkimStatus}`,
    `    A:          ${aStatus}${result.aDisplay !== '-' ? ` - ${result.aDisplay}` : ''}`,
    `    AAAA:       ${aaaaStatus}${result.aaaaDisplay !== '-' ? ` - ${result.aaaaDisplay}` : ''}`,
    `    MX:         ${result.mxDisplay}`,
    `    Nameserver: ${healthParts.NS || 'unknown'}`,
    `    SOA:        ${healthParts.SOA || 'unknown'}`,
    `    CAA:        ${healthParts.CAA || 'unknown'}`,
    `    MTA:        ${healthParts.MTA || 'unknown'}`,
    `    TLS:        ${healthParts.TLS || 'unknown'}`,
    `    PTR:        ${healthParts.PTR || 'unknown'}`,
  ];
}

/**
 * Check a single domain for SPF, DMARC, DKIM, and DNS records
 * @param {string} domainName - Domain to check
 * @param {object} dkimConfig - DKIM configuration
 * @returns {Promise<object>} Check results
 */
async function checkDomain(domainName, dkimConfig) {
  const result = {
    spfCheckConsole: '',
    spfRecord: '',
    spfStatus: '',
    dmarcCheckConsole: '',
    dmarcRecord: '',
    dmarcStatus: '',
    dkimCheckConsole: '',
    dkimInfo: '',
    dkimStatus: '',
    aDisplay: '-',
    aaaaDisplay: '-',
    mxDisplay: '-',
    healthSummary: '',
  };

  try {
    // Check if domain uses AutoDNS nameservers
    const usesAutoDNS = await usesAutoDNSNameservers(domainName);

    if (!usesAutoDNS) {
      // Domain does not use AutoDNS - skip all DNS updates
      result.spfStatus = 'skipped - not using AutoDNS nameservers';
      result.dmarcStatus = 'skipped - not using AutoDNS nameservers';
      result.dkimStatus = 'skipped - not using AutoDNS nameservers';

      // Still get A/AAAA/MX records for display
      console.log(
        '  → Domain not using AutoDNS nameservers, skipping DNS updates',
      );
      console.log(`  → Checking A/AAAA/MX for ${domainName}`);
      await getRecordsForDomain(domainName, result);

      // Still run health checks
      console.log(`  → Running health checks for ${domainName}`);
      await addHealthChecks(domainName, result);

      return result;
    }

    // Query SPF record
    console.log(`  → Checking SPF for ${domainName}`);
    let spfNeedsUpdate = false,
      spfCurrentValue = '';
    try {
      const currentSpf = await Promise.race([
        getSPFRecord(domainName),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('SPF query timeout')), 5000),
        ),
      ]);
      const spfEval = evaluateCheckResult(
        currentSpf, config.expectedSpf, 'spf', result);
      spfNeedsUpdate = spfEval.needsUpdate;
      spfCurrentValue = spfEval.currentValue;
    } catch (error) {
      result.spfCheckConsole = `${colors.red}✗${colors.reset}`;
      result.spfRecord = `SPF Error: ${error.message}`;
      spfCurrentValue = error.message;
      result.spfStatus = 'error';
    }

    // Query DMARC record
    console.log(`  → Checking DMARC for ${domainName}`);
    let dmarcNeedsUpdate = false,
      dmarcCurrentValue = '';
    try {
      const currentDmarc = await getDMARCRecord(domainName);
      const normalizedCurrent = normalizeDMARC(currentDmarc);
      const normalizedExpected = normalizeDMARC(config.expectedDmarc);

      const dmarcEval = evaluateCheckResult(
        normalizedCurrent, normalizedExpected, 'dmarc', result, currentDmarc);
      dmarcNeedsUpdate = dmarcEval.needsUpdate;
      dmarcCurrentValue = dmarcEval.currentValue;
    } catch (error) {
      result.dmarcCheckConsole = `${colors.red}✗${colors.reset}`;
      result.dmarcRecord = `DMARC Error: ${error.message}`;
      dmarcCurrentValue = error.message;
      result.dmarcStatus = 'error';
    }

    // Query DKIM records
    console.log(`  → Checking DKIM for ${domainName}`);
    await checkDKIMForDomain(domainName, dkimConfig, result);

    // Update SPF record if needed
    await applyProtocolUpdate('spf', spfNeedsUpdate,
      () => updateDomainSPFRecord(domainName, config.expectedSpf),
      spfCurrentValue, result);

    // Update DMARC record if needed
    await applyProtocolUpdate('dmarc', dmarcNeedsUpdate,
      async () => {
        await addDMARCReportAuthRecord(domainName);
        await updateDomainDMARCRecord(domainName, config.expectedDmarc);
      },
      dmarcCurrentValue, result);

    // Get A/AAAA/MX records
    console.log(`  → Checking A/AAAA/MX for ${domainName}`);
    await getRecordsForDomain(domainName, result);

    // Extended DNS health checks (best-effort, no throw)
    console.log(`  → Running health checks for ${domainName}`);
    await addHealthChecks(domainName, result);

    return result;
  } catch (error) {
    // Top-level catch for any unhandled error in checkDomain
    console.error(
      `  ✗ Fatal error in checkDomain(${domainName}):`,
      error.message,
    );
    result.spfCheckConsole = `${colors.red}✗${colors.reset}`;
    result.spfRecord = 'Error';
    result.spfStatus = `error "${error.message}"`;
    result.dmarcCheckConsole = `${colors.red}✗${colors.reset}`;
    result.dmarcRecord = 'Error';
    result.dmarcStatus = `error "${error.message}"`;
    result.dkimCheckConsole = `${colors.red}✗${colors.reset}`;
    result.dkimInfo = 'Error';
    result.dkimStatus = `error "${error.message}"`;
    result.healthSummary = 'Error';
    return result;
  }
}

/**
 * Check DKIM for a domain
 * @param {string} domainName - Domain name
 * @param {object} dkimConfig - DKIM configuration
 * @param {object} result - Result object to populate
 */
async function checkDKIMForDomain(domainName, dkimConfig, result) {
  const desiredFromConfig = dkimConfig[domainName] || {};
  const hasNonEmptyValues = Object.values(desiredFromConfig).some(
    (v) => v && v.trim() !== '',
  );

  if (Object.keys(desiredFromConfig).length === 0 || !hasNonEmptyValues) {
    result.dkimCheckConsole = `${colors.gray}-${colors.reset}`;
    result.dkimInfo = 'DKIM: Skipped';
    result.dkimStatus = 'skipped';
    return;
  }

  let dkimResults = await checkDKIMRecords(domainName);
  if (dkimResults.length === 0) {
    const zoneDkim = await listZoneDKIMRecords(domainName);
    if (zoneDkim.length > 0) {
      dkimResults = zoneDkim;
    }
  }

  if (dkimResults.length > 0) {
    result.dkimCheckConsole = `${colors.green}✓${colors.reset}`;
    const selectors = dkimResults.map((r) => r.selector).join(', ');
    result.dkimInfo = `DKIM: Found (${selectors})`;
    result.dkimStatus = `ok - selectors: ${selectors}`;
  } else {
    result.dkimCheckConsole = `${colors.red}✗${colors.reset}`;
    result.dkimInfo = 'DKIM: No records found';
    result.dkimStatus = 'fail "No DKIM records found"';
  }

  // Ensure missing or mismatched selectors are created/updated
  for (const [selector, desiredValue] of Object.entries(desiredFromConfig)) {
    if (!desiredValue || desiredValue.trim() === '') {
      continue;
    }

    const found = dkimResults.find((r) => r.selector === selector);
    const normalize = (s) => (s || '').replace(/\s+/g, ' ').trim();

    if (!found) {
      const ok = await updateDomainDKIMRecord(
        domainName,
        selector,
        desiredValue,
      );
      if (ok) {
        result.dkimStatus = `ok - created selector ${selector}`;
      } else {
        result.dkimStatus = `error "Failed to create selector ${selector}"`;
      }
    } else if (normalize(found.fullValue) !== normalize(desiredValue)) {
      const ok = await updateDomainDKIMRecord(
        domainName,
        selector,
        desiredValue,
      );
      if (ok) {
        result.dkimStatus = `ok - updated selector ${selector}`;
      } else {
        result.dkimStatus = `error "Failed to update selector ${selector}"`;
      }
    }
  }
}

/**
 * Get A, AAAA, and MX records for a domain
 * @param {string} domainName - Domain name
 * @param {object} result - Result object to populate
 */
async function getRecordsForDomain(domainName, result) {
  try {
    const zoneInfo = await getZone(domainName);
    if (
      zoneInfo.data &&
      Array.isArray(zoneInfo.data) &&
      zoneInfo.data.length > 0
    ) {
      const zone = zoneInfo.data[0];

      const aRecords = await getARecords(zone, domainName);
      const aaaaRecords = await getAAAARecords(zone, domainName);
      const mxRecords = await getMXRecords(zone, domainName);

      result.aDisplay = aRecords.length ? aRecords.join(',') : '-';
      result.aaaaDisplay = aaaaRecords.length ? aaaaRecords.join(',') : '-';
      result.mxDisplay = mxRecords.length ? mxRecords.join(',') : '-';
    }
  } catch (_error) {
    // Keep default '-' values
  }
}

/**
 * Compute compact DNS health summary and attach to result
 */
async function addHealthChecks(domainName, result) {
  try {
    const ns = await checkNS(domainName);
    const soa = await checkSOA(domainName);
    const caa = await checkCAA(domainName);
    const mta = await checkMtaSts(domainName);
    const tls = await checkTlsRpt(domainName);
    const mxHosts = result.mxDisplay === '-' ? [] : result.mxDisplay.split(',');
    const mxInt = await checkMXIntegrity(domainName, mxHosts);
    const ptr = mxHosts.length
      ? await checkPTRForOutbound(mxHosts[0])
      : { ok: false };

    const status = { ns, soa, caa, mta, tls, mx: mxInt, ptr };
    result.healthSummary = buildHealthSummary(status);
  } catch {
    result.healthSummary =
      'NS:fail; SOA:fail; CAA:fail; MTA:fail; TLS:fail; PTR:fail';
  }
}
