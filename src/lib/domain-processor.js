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
      if (result.spfStatus.startsWith('ok')) {
        counts.spf.ok++;
      } else if (result.spfStatus.startsWith('fail')) {
        counts.spf.fail++;
        failuresByType.SPF.push(domainName);
      } else if (result.spfStatus.startsWith('error')) {
        counts.spf.error++;
        failuresByType.SPF.push(domainName);
      } else if (result.spfStatus.startsWith('skipped')) {
        counts.spf.skipped++;
      }

      if (result.dmarcStatus.startsWith('ok')) {
        counts.dmarc.ok++;
      } else if (result.dmarcStatus.startsWith('fail')) {
        counts.dmarc.fail++;
        failuresByType.DMARC.push(domainName);
      } else if (result.dmarcStatus.startsWith('error')) {
        counts.dmarc.error++;
        failuresByType.DMARC.push(domainName);
      } else if (result.dmarcStatus.startsWith('skipped')) {
        counts.dmarc.skipped++;
      }

      if (result.dkimStatus.startsWith('ok')) {
        counts.dkim.ok++;
      } else if (result.dkimStatus.startsWith('fail')) {
        counts.dkim.fail++;
        failuresByType.DKIM.push(domainName);
      } else if (result.dkimStatus.startsWith('error')) {
        counts.dkim.error++;
        failuresByType.DKIM.push(domainName);
      } else if (result.dkimStatus.startsWith('skipped')) {
        counts.dkim.skipped++;
      }

      counts.a[aStatus === 'ok' ? 'ok' : 'fail']++;
      if (aStatus === 'fail') failuresByType.A.push(domainName);
      counts.aaaa[aaaaStatus === 'ok' ? 'ok' : 'fail']++;
      if (aaaaStatus === 'fail') failuresByType.AAAA.push(domainName);

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
        result.spfStatus === 'fail' ||
        result.spfStatus === 'error' ||
        result.dmarcStatus === 'fail' ||
        result.dmarcStatus === 'error' ||
        result.dkimStatus === 'fail' ||
        result.dkimStatus === 'error' ||
        aStatus === 'fail' ||
        aaaaStatus === 'fail'
      ) {
        hasFailures = true;
      }

      // Write multi-line format to file output
      domainDetailsOutput += `${timestamp} ${domainName}\n`;
      domainDetailsOutput += `    SPF:        ${result.spfStatus}\n`;
      domainDetailsOutput += `    DMARC:      ${result.dmarcStatus}\n`;
      domainDetailsOutput += `    DKIM:       ${result.dkimStatus}\n`;
      domainDetailsOutput += `    A:          ${aStatus}${result.aDisplay !== '-' ? ` - ${result.aDisplay}` : ''}\n`;
      domainDetailsOutput += `    AAAA:       ${aaaaStatus}${result.aaaaDisplay !== '-' ? ` - ${result.aaaaDisplay}` : ''}\n`;
      domainDetailsOutput += `    MX:         ${result.mxDisplay}\n`;
      domainDetailsOutput += `    Nameserver: ${healthParts.NS || 'unknown'}\n`;
      domainDetailsOutput += `    SOA:        ${healthParts.SOA || 'unknown'}\n`;
      domainDetailsOutput += `    CAA:        ${healthParts.CAA || 'unknown'}\n`;
      domainDetailsOutput += `    MTA:        ${healthParts.MTA || 'unknown'}\n`;
      domainDetailsOutput += `    TLS:        ${healthParts.TLS || 'unknown'}\n`;
      domainDetailsOutput += `    PTR:        ${healthParts.PTR || 'unknown'}\n\n`;

      // Print console output in same multi-line format
      console.log(`${timestamp} ${domainName}`);
      console.log(`    SPF:        ${result.spfStatus}`);
      console.log(`    DMARC:      ${result.dmarcStatus}`);
      console.log(`    DKIM:       ${result.dkimStatus}`);
      console.log(
        `    A:          ${aStatus}${result.aDisplay !== '-' ? ` - ${result.aDisplay}` : ''}`,
      );
      console.log(
        `    AAAA:       ${aaaaStatus}${result.aaaaDisplay !== '-' ? ` - ${result.aaaaDisplay}` : ''}`,
      );
      console.log(`    MX:         ${result.mxDisplay}`);
      console.log(`    Nameserver: ${healthParts.NS || 'unknown'}`);
      console.log(`    SOA:        ${healthParts.SOA || 'unknown'}`);
      console.log(`    CAA:        ${healthParts.CAA || 'unknown'}`);
      console.log(`    MTA:        ${healthParts.MTA || 'unknown'}`);
      console.log(`    TLS:        ${healthParts.TLS || 'unknown'}`);
      console.log(`    PTR:        ${healthParts.PTR || 'unknown'}`);
      console.log(''); // Empty line between domains
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
  const reportFailureTypes = [
    ['SPF', failuresByType.SPF],
    ['DMARC', failuresByType.DMARC],
    ['DKIM', failuresByType.DKIM],
    ['A', failuresByType.A],
    ['AAAA', failuresByType.AAAA],
  ];
  for (const [type, domains] of reportFailureTypes) {
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
      if (currentSpf === config.expectedSpf) {
        result.spfCheckConsole = `${colors.green}✓${colors.reset}`;
        result.spfRecord = 'SPF: Correct';
        result.spfStatus = 'ok';
      } else if (currentSpf) {
        result.spfCheckConsole = `${colors.red}✗${colors.reset}`;
        result.spfRecord = `SPF: ${currentSpf}`;
        spfNeedsUpdate = true;
        spfCurrentValue = currentSpf;
        result.spfStatus = 'needs-update';
      } else {
        result.spfCheckConsole = `${colors.red}✗${colors.reset}`;
        result.spfRecord = 'SPF: No record';
        spfNeedsUpdate = true;
        spfCurrentValue = 'No SPF record';
        result.spfStatus = 'needs-update';
      }
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

      if (normalizedCurrent === normalizedExpected) {
        result.dmarcCheckConsole = `${colors.green}✓${colors.reset}`;
        result.dmarcRecord = 'DMARC: Correct';
        result.dmarcStatus = 'ok';
      } else if (currentDmarc) {
        result.dmarcCheckConsole = `${colors.red}✗${colors.reset}`;
        result.dmarcRecord = `DMARC: ${currentDmarc}`;
        dmarcNeedsUpdate = true;
        dmarcCurrentValue = currentDmarc;
        result.dmarcStatus = 'needs-update';
      } else {
        result.dmarcCheckConsole = `${colors.red}✗${colors.reset}`;
        result.dmarcRecord = 'DMARC: No record';
        dmarcNeedsUpdate = true;
        dmarcCurrentValue = 'No DMARC record';
        result.dmarcStatus = 'needs-update';
      }
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
    if (spfNeedsUpdate) {
      try {
        await updateDomainSPFRecord(domainName, config.expectedSpf);
        result.spfCheckConsole = `${colors.green}✓${colors.reset}(updated)`;
        result.spfRecord = 'SPF: Correct (updated)';
        result.spfStatus = `ok - updated from "${spfCurrentValue}"`;
      } catch (error) {
        result.spfCheckConsole = `${colors.red}✗${colors.reset}(failed)`;
        result.spfStatus = `error "Update failed: ${error.message}"`;
      }
    } else if (result.spfStatus === 'error') {
      result.spfStatus = `error "${spfCurrentValue}"`;
    }

    // Update DMARC record if needed
    if (dmarcNeedsUpdate) {
      try {
        await addDMARCReportAuthRecord(domainName);
        await updateDomainDMARCRecord(domainName, config.expectedDmarc);
        result.dmarcCheckConsole = `${colors.green}✓${colors.reset}(updated)`;
        result.dmarcRecord = 'DMARC: Correct (updated)';
        result.dmarcStatus = `ok - updated from "${dmarcCurrentValue}"`;
      } catch (error) {
        result.dmarcCheckConsole = `${colors.red}✗${colors.reset}(failed)`;
        result.dmarcStatus = `error "Update failed: ${error.message}"`;
      }
    } else if (result.dmarcStatus === 'error') {
      result.dmarcStatus = `error "${dmarcCurrentValue}"`;
    }

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
