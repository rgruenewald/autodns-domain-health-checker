import { resolveTxt } from './dns-operations.js';
import { getZone, updateZone } from './autodns-client.js';
import { config } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Get DMARC record for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string|null>} DMARC record or null
 */
export async function getDMARCRecord(domain) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const records = await resolveTxt(dmarcDomain);
    const dmarcRecords = records
      .map(record => record.join(''))
      .filter(record => record.startsWith('v=DMARC1'));

    return dmarcRecords.length > 0 ? dmarcRecords[0] : null;
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return null;
    }
    throw error;
  }
}

/**
 * Normalize DMARC record for comparison (removes spaces after semicolons)
 * @param {string} dmarc - DMARC record to normalize
 * @returns {string|null} Normalized DMARC record
 */
export function normalizeDMARC(dmarc) {
  if (!dmarc) {return null;}
  // Remove all spaces after semicolons and ensure consistent spacing
  return dmarc.replace(/;\s*/g, ';').replace(/\s+/g, ' ').trim();
}

/**
 * Update domain's DMARC record
 * @param {string} domainName - Domain name
 * @param {string} dmarcValue - New DMARC value
 * @returns {Promise<boolean>} Success status
 */
export async function updateDomainDMARCRecord(domainName, dmarcValue) {
  try {
    // Get current zone data
    const zoneInfo = await getZone(domainName);

    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      throw new Error('Invalid zone data received');
    }

    const zone = zoneInfo.data[0];

    // Find existing DMARC record (_dmarc) or create new one
    let recordFound = false;
    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    for (const record of zone.resourceRecords) {
      if (record.type === 'TXT' && record.name === '_dmarc') {
        // Update existing record
        record.value = dmarcValue;
        record.ttl = 300;
        recordFound = true;
        break;
      }
    }

    if (!recordFound) {
      // Add new DMARC record
      zone.resourceRecords.push({
        name: '_dmarc',
        type: 'TXT',
        value: dmarcValue,
        ttl: 300,
      });
    }

    // Update the zone
    await updateZone(domainName, zone);
    return true;
  } catch (error) {
    logger.error(
      { domain: domainName, error: error.message },
      'Failed to update DMARC record',
    );
    return false;
  }
}

/**
 * Add DMARC reporting authorization record to diebasis.de zone
 * @param {string} domainName - Domain requesting authorization
 * @returns {Promise<boolean>} Success status
 */
export async function addDMARCReportAuthRecord(domainName) {
  const recordName = `${domainName}._report._dmarc`;
  const recordValue = 'v=DMARC1';

  try {
    // Get current zone data for diebasis.de
    const zoneInfo = await getZone(config.dmarcReportAuthDomain);

    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      throw new Error('Invalid zone data received');
    }

    const zone = zoneInfo.data[0];

    // Check if record already exists
    let recordFound = false;
    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    for (const record of zone.resourceRecords) {
      if (record.type === 'TXT' && record.name === recordName) {
        recordFound = true;
        break;
      }
    }

    if (!recordFound) {
      // Add new reporting authorization record
      zone.resourceRecords.push({
        name: recordName,
        type: 'TXT',
        value: recordValue,
        ttl: 300,
      });

      // Update the zone
      await updateZone(config.dmarcReportAuthDomain, zone);
      return true;
    } else {
      return true;
    }
  } catch (_error) {
    return false;
  }
}
