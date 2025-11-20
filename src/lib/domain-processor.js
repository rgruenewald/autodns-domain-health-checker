import { getZone } from './autodns-client.js';
import { getSPFRecord, updateDomainSPFRecord } from './spf.js';
import { getDMARCRecord, normalizeDMARC, updateDomainDMARCRecord,
  addDMARCReportAuthRecord } from './dmarc.js';
import { checkDKIMRecords, listZoneDKIMRecords, updateDomainDKIMRecord,
  loadDkimConfig, saveDkimConfig } from './dkim.js';
import { getARecords, getAAAARecords, getMXRecords }
  from './dns-operations.js';
import { checkNS, checkSOA, checkCAA, checkMtaSts, checkTlsRpt,
  checkPTRForOutbound, checkMXIntegrity, buildHealthSummary,
  usesAutoDNSNameservers }
  from './health-checks.js';
import { colors, formatTimestamp } from '../utils/helpers.js';
import { config } from './config.js';

/**
 * Process and check all domains
 * @param {object} data - API response with domain data
 * @param {string} originalSpf - Original SPF value
 * @param {string} flattenedSpf - Flattened SPF value
 * @returns {Promise<string>} Report content
 */
export async function processDomains(data, originalSpf, flattenedSpf) {
  // Check for errors
  if (!data || data.status?.type === 'ERROR') {
    console.log('Error in API response:',
      data?.status?.text || 'Unknown error');
    return '';
  }

  // The API returns data directly at the root level
  let domains = data.data || [];

  console.log(`\nFound ${domains.length} domain(s) total`);

  if (domains.length === 0) {
    console.log('No domains found in this account.');
    return '';
  }

  // Limit to specific domains for testing (if enabled)
  if (config.testDomainsEnabled && config.testDomains.length > 0) {
    domains = domains.filter(d => config.testDomains.includes(d.name || d.origin));
  }

  // Sort domains alphabetically by name
  domains.sort((a, b) => {
    const nameA = (a.name || a.origin || '').toLowerCase();
    const nameB = (b.name || b.origin || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });

  if (config.testDomainsEnabled) {
    const testingList = domains.map(d => d.name || d.origin).join(', ');
    console.log(`Testing with domain(s): ${testingList || 'none found'}\n`);
  }

  // Build output for both console and file
  let fileOutput = '';

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
      result.healthSummary.split('; ').forEach(part => {
        const [key, value] = part.split(':');
        healthParts[key] = value;
      });

      // Determine A/AAAA status
      const aStatus = result.aDisplay !== '-' ? 'ok' : 'fail';
      const aaaaStatus = result.aaaaDisplay !== '-' ? 'ok' : 'fail';

      // Write multi-line format to file output
      fileOutput += `${timestamp} ${domainName}\n`;
      fileOutput += `    SPF:        ${result.spfStatus}\n`;
      fileOutput += `    DMARC:      ${result.dmarcStatus}\n`;
      fileOutput += `    DKIM:       ${result.dkimStatus}\n`;
      fileOutput += `    A:          ${aStatus}${result.aDisplay !== '-' ? ` - ${  result.aDisplay}` : ''}\n`;
      fileOutput += `    AAAA:       ${aaaaStatus}${result.aaaaDisplay !== '-' ? ` - ${  result.aaaaDisplay}` : ''}\n`;
      fileOutput += `    MX:         ${result.mxDisplay}\n`;
      fileOutput += `    Nameserver: ${healthParts.NS || 'unknown'}\n`;
      fileOutput += `    SOA:        ${healthParts.SOA || 'unknown'}\n`;
      fileOutput += `    CAA:        ${healthParts.CAA || 'unknown'}\n`;
      fileOutput += `    MTA:        ${healthParts.MTA || 'unknown'}\n`;
      fileOutput += `    TLS:        ${healthParts.TLS || 'unknown'}\n`;
      fileOutput += `    PTR:        ${healthParts.PTR || 'unknown'}\n\n`;

      // Print console output in same multi-line format
      console.log(`${timestamp} ${domainName}`);
      console.log(`    SPF:        ${result.spfStatus}`);
      console.log(`    DMARC:      ${result.dmarcStatus}`);
      console.log(`    DKIM:       ${result.dkimStatus}`);
      console.log(`    A:          ${aStatus}${result.aDisplay !== '-' ? ` - ${  result.aDisplay}` : ''}`);
      console.log(`    AAAA:       ${aaaaStatus}${result.aaaaDisplay !== '-' ? ` - ${  result.aaaaDisplay}` : ''}`);
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
      fileOutput += `${timestamp} ${domainName}\n`;
      fileOutput += `    ERROR: processing failed: ${msg}\n\n`;
      // continue with next domain
    }
  }

  console.log(`\nExpected SPF: ${config.expectedSpf}`);
  console.log(`Expected DMARC: ${config.expectedDmarc}\n`);

  // Append SPF flattening information to the report
  if (originalSpf && flattenedSpf) {
    fileOutput += '\n==============\nSPF Flattening\n==============\n\n';
    fileOutput += `Original:\n${originalSpf}\n\n`;
    fileOutput += `Flattened:\n${flattenedSpf}\n`;
  }

  return fileOutput;
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
      console.log('  → Domain not using AutoDNS nameservers, skipping DNS updates');
      console.log(`  → Checking A/AAAA/MX for ${domainName}`);
      await getRecordsForDomain(domainName, result);

      // Still run health checks
      console.log(`  → Running health checks for ${domainName}`);
      await addHealthChecks(domainName, result);

      return result;
    }

    // Query SPF record
    console.log(`  → Checking SPF for ${domainName}`);
    let spfNeedsUpdate = false, spfCurrentValue = '';
    try {
      const currentSpf = await Promise.race([
        getSPFRecord(domainName),
        new Promise((_, reject) => setTimeout(() => reject(new Error('SPF query timeout')), 5000)),
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
    let dmarcNeedsUpdate = false, dmarcCurrentValue = '';
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
    console.error(`  ✗ Fatal error in checkDomain(${domainName}):`, error.message);
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
  const hasNonEmptyValues = Object.values(desiredFromConfig)
    .some(v => v && v.trim() !== '');

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
    const selectors = dkimResults.map(r => r.selector).join(', ');
    result.dkimInfo = `DKIM: Found (${selectors})`;
    result.dkimStatus = `ok - selectors: ${selectors}`;
  } else {
    result.dkimCheckConsole = `${colors.red}✗${colors.reset}`;
    result.dkimInfo = 'DKIM: No records found';
    result.dkimStatus = 'fail "No DKIM records found"';
  }

  // Ensure missing or mismatched selectors are created/updated
  for (const [selector, desiredValue] of Object.entries(desiredFromConfig)) {
    if (!desiredValue || desiredValue.trim() === '') {continue;}

    const found = dkimResults.find(r => r.selector === selector);
    const normalize = (s) => (s || '').replace(/\s+/g, ' ').trim();

    if (!found) {
      const ok = await updateDomainDKIMRecord(domainName, selector,
        desiredValue);
      if (ok) {
        result.dkimStatus = `ok - created selector ${selector}`;
      } else {
        result.dkimStatus = `error "Failed to create selector ${selector}"`;
      }
    } else if (normalize(found.fullValue) !== normalize(desiredValue)) {
      const ok = await updateDomainDKIMRecord(domainName, selector,
        desiredValue);
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
    if (zoneInfo.data && Array.isArray(zoneInfo.data) &&
      zoneInfo.data.length > 0) {
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
    const ptr = mxHosts.length ? await checkPTRForOutbound(mxHosts[0]) : { ok: false };

    const status = { ns, soa, caa, mta, tls, mx: mxInt, ptr };
    result.healthSummary = buildHealthSummary(status);
  } catch {
    result.healthSummary = 'NS:fail; SOA:fail; CAA:fail; MTA:fail; TLS:fail; PTR:fail';
  }
}
