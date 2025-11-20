import { resolveTxt,
  resolveHostToIPs, resolveMxToIPs } from './dns-operations.js';
import { getZone, updateZone } from './autodns-client.js';
import { colors } from '../utils/helpers.js';
import { logger } from '../utils/logger.js';

/**
 * Query SPF record for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string|null>} SPF record or null
 */
export async function getSPFRecord(domain) {
  try {
    const records = await resolveTxt(domain);
    const spfRecords = records
      .map(record => record.join(''))
      .filter(record => record.startsWith('v=spf1'));

    return spfRecords.length > 0 ? spfRecords[0] : null;
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return null;
    }
    throw error;
  }
}

/**
 * Recursively resolve all SPF includes and flatten them
 * @param {string} spfRecord - SPF record to flatten
 * @param {Set<string>} visited - Set of already visited domains
 * @param {number} depth - Current recursion depth
 * @returns {Promise<object>} Object with mechanisms and modifiers arrays
 */
export async function resolveSpfIncludes(spfRecord, visited = new Set(),
  depth = 0) {
  // Prevent infinite loops and limit recursion depth
  if (depth > 10) {
    logger.warn({ depth }, 'Max SPF recursion depth reached');
    return { mechanisms: [], modifiers: [] };
  }

  const mechanisms = [];
  const modifiers = [];

  // Parse SPF record
  const parts = spfRecord.split(/\s+/);

  for (const part of parts) {
    if (part === 'v=spf1') {
      continue; // Skip version
    }

    if (part.startsWith('include:')) {
      const includeDomain = part.substring(8);

      // Prevent circular includes
      if (visited.has(includeDomain)) {
        logger.warn({ domain: includeDomain }, 'Circular SPF include detected');
        continue;
      }

      visited.add(includeDomain);

      try {
        const includeSpf = await getSPFRecord(includeDomain);
        if (includeSpf) {
          // Recursively resolve this include
          const resolved = await resolveSpfIncludes(includeSpf, visited,
            depth + 1);
          mechanisms.push(...resolved.mechanisms);
          modifiers.push(...resolved.modifiers);
        } else {
          logger.warn({ domain: includeDomain }, 'Could not resolve SPF for include');
        }
      } catch (error) {
        logger.warn(
          { domain: includeDomain, error: error.message },
          'Error resolving SPF include',
        );
      }
    } else if (part.startsWith('redirect=')) {
      modifiers.push(part);
    } else if (part === 'all' || part.startsWith('-all') ||
      part.startsWith('~all') || part.startsWith('+all') ||
      part.startsWith('?all')) {
      modifiers.push(part);
    } else if (part === 'a' || part === 'mx') {
      // Don't resolve plain 'a' or 'mx' as they reference current domain
      mechanisms.push(part);
    } else if (part.startsWith('a:')) {
      const hostname = part.substring(2);
      try {
        const ips = await resolveHostToIPs(hostname);
        mechanisms.push(...ips);
      } catch (error) {
        logger.warn(
          { hostname, error: error.message },
          'Could not resolve A record',
        );
        mechanisms.push(part);
      }
    } else if (part.startsWith('mx:')) {
      const domain = part.substring(3);
      try {
        const ips = await resolveMxToIPs(domain);
        mechanisms.push(...ips);
      } catch (error) {
        logger.warn({ domain, error: error.message }, 'Could not resolve MX');
        mechanisms.push(part);
      }
    } else {
      // Keep other mechanisms as-is (ip4, ip6, etc.)
      mechanisms.push(part);
    }
  }

  return { mechanisms, modifiers };
}

/**
 * Build flattened SPF record by resolving all includes
 * @param {string} baseSpfRecord - Base SPF record to flatten
 * @returns {Promise<string>} Flattened SPF record
 */
export async function buildFlattenedSpfRecord(baseSpfRecord) {
  console.log(`\nResolving SPF includes from: ${baseSpfRecord}`);

  const resolved = await resolveSpfIncludes(baseSpfRecord);

  // Remove duplicates
  const uniqueMechanisms = [...new Set(resolved.mechanisms)];
  const uniqueModifiers = [...new Set(resolved.modifiers)];

  // Build final SPF record
  const parts = ['v=spf1', ...uniqueMechanisms];

  // Add modifiers at the end (all mechanism should be last)
  const allModifier = uniqueModifiers.find(m => m.includes('all'));
  const otherModifiers = uniqueModifiers.filter(m => !m.includes('all'));

  parts.push(...otherModifiers);
  if (allModifier) {
    parts.push(allModifier);
  }

  const flattenedSpf = parts.join(' ');

  console.log(`Flattened SPF: ${flattenedSpf}`);
  console.log(`Original mechanisms: ${resolved.mechanisms.length}, ` +
    `Unique: ${uniqueMechanisms.length}\n`);

  return flattenedSpf;
}

/**
 * Update domain's SPF record
 * @param {string} domainName - Domain name
 * @param {string} spfValue - New SPF value
 * @returns {Promise<object>} Update result
 */
export async function updateDomainSPFRecord(domainName, spfValue) {
  try {
    // Get current zone data
    const zoneInfo = await getZone(domainName);

    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      throw new Error('Invalid zone data received');
    }

    const zone = zoneInfo.data[0];

    // Find existing SPF TXT record or create new one
    let recordFound = false;
    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    // Guard: Apex CNAME conflicts with any other record
    const hasApexCname = zone.resourceRecords.some(rr =>
      rr.type === 'CNAME' && (rr.name === '' || rr.name === '@'));
    if (hasApexCname) {
      throw new Error('Apex has a CNAME record; cannot add/update ' +
        'SPF TXT at zone apex due to DNS constraints');
    }

    for (const record of zone.resourceRecords) {
      // SPF record is a TXT record with empty name for the domain itself
      if (record.type === 'TXT' && (record.name === '' ||
        record.name === '@') && record.value &&
        record.value.startsWith('v=spf1')) {
        // Update existing SPF record
        record.value = spfValue;
        record.ttl = 300;
        recordFound = true;
        break;
      }
    }

    if (!recordFound) {
      // Add new SPF record
      zone.resourceRecords.push({
        name: '',
        type: 'TXT',
        value: spfValue,
        ttl: 300,
      });
    }

    // Update the zone
    const updateResult = await updateZone(domainName, zone);
    return updateResult;
  } catch (error) {
    console.error(`  ${colors.red}✗${colors.reset} ` +
      `Failed to update SPF for ${domainName}`);
    throw error;
  }
}

/**
 * Update the _spf.diebasis.de TXT record specifically
 * @param {string} recordName - Full record name (e.g., _spf.diebasis.de)
 * @param {string} spfValue - New SPF value
 * @returns {Promise<object>} Update result
 */
export async function updateDiebasisSPFRecord(recordName, spfValue) {
  logger.info({ record: recordName, value: spfValue }, 'Updating diebasis SPF record');
  logger.info({ record: recordName, value: spfValue }, 'Updating diebasis SPF record');
  console.log(`\nUpdating DNS record: ${recordName}`);
  console.log(`New value: ${spfValue}\n`);

  // Extract the zone name
  const parts = recordName.split('.');
  const zoneName = parts.slice(-2).join('.');
  const recordPrefix = parts.slice(0, -2).join('.');

  try {
    // Get current zone data
    const zoneInfo = await getZone(zoneName);

    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      console.error('Full zone response:',
        JSON.stringify(zoneInfo, null, 2));
      throw new Error('Invalid zone data received');
    }

    const zone = zoneInfo.data[0];

    // Find existing TXT record or create new one
    let recordFound = false;
    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    for (const record of zone.resourceRecords) {
      if (record.type === 'TXT' && record.name === recordPrefix) {
        // Update existing record
        record.value = spfValue;
        record.ttl = 300;
        recordFound = true;
        break;
      }
    }

    if (!recordFound) {
      // Add new record
      console.log(`No existing TXT record found for ${recordName}, ` +
        'creating new...');
      zone.resourceRecords.push({
        name: recordPrefix,
        type: 'TXT',
        value: spfValue,
        ttl: 300,
      });
    }

    // Update the zone
    const updateResult = await updateZone(zoneName, zone);

    if (updateResult.status?.type === 'SUCCESS') {
      console.log(`${colors.green}✓${colors.reset} ` +
        `Successfully updated ${recordName}`);
    } else {
      console.log(`${colors.red}✗${colors.reset} ` +
        'Update may have failed, check response above');
    }

    return updateResult;
  } catch (error) {
    console.error(`${colors.red}✗${colors.reset} ` +
      `Failed to update ${recordName}`);
    console.error('Error details:', error.message);
    throw error;
  }
}
