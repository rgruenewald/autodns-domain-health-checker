import fs from 'fs/promises';
import path from 'path';
import { resolveTxt } from './dns-operations.js';
import { getZone, updateZone } from './autodns-client.js';
import { config } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Check DKIM records for a domain using configured selectors
 * @param {string} domain - Domain to check
 * @returns {Promise<Array>} Array of DKIM check results
 */
export async function checkDKIMRecords(domain) {
  const dkimResults = [];

  for (const selector of config.dkimSelectors) {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const records = await resolveTxt(dkimDomain);

      // DKIM records are TXT records that contain "v=DKIM1"
      const dkimRecords = records
        .map(record => record.join(''))
        .filter(record => record.includes('v=DKIM1') ||
          record.includes('k=rsa') || record.includes('p='));

      if (dkimRecords.length > 0) {
        const full = dkimRecords[0];
        dkimResults.push({
          selector,
          found: true,
          record: full.substring(0, 50) + (full.length > 50 ? '...' : ''),
          fullValue: full,
        });
      }
    } catch (error) {
      if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
        dkimResults.push({
          selector,
          found: false,
          error: error.message,
        });
      }
      // If ENODATA or ENOTFOUND, just skip this selector (not found)
    }
  }

  return dkimResults;
}

/**
 * List DKIM records directly from AutoDNS zone
 * @param {string} domainName - Domain name
 * @returns {Promise<Array>} Array of DKIM records found in zone
 */
export async function listZoneDKIMRecords(domainName) {
  try {
    const zoneInfo = await getZone(domainName);
    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      return [];
    }
    const zone = zoneInfo.data[0];
    const out = [];
    for (const rr of zone.resourceRecords || []) {
      if (rr.type === 'TXT' && typeof rr.name === 'string' &&
        rr.name.endsWith('._domainkey')) {
        const selector = rr.name.replace('._domainkey', '');
        const full = rr.value || '';
        out.push({
          selector,
          found: true,
          record: full.substring(0, 50) + (full.length > 50 ? '...' : ''),
          fullValue: full,
        });
      }
    }
    return out;
  } catch (_error) {
    return [];
  }
}

/**
 * Load DKIM desired config from JSON file
 * @returns {Promise<object>} DKIM configuration object
 */
export async function loadDkimConfig() {
  try {
    const content = await fs.readFile(
      path.resolve(process.cwd(), config.dkimConfigPath),
      'utf8',
    );
    const json = JSON.parse(content);
    return json || {};
  } catch (error) {
    if (error.code !== 'ENOENT') {
      logger.error({ error: error.message }, 'Failed to read DKIM config file');
    }
    return {};
  }
}

/**
 * Save DKIM config to JSON file (sorted alphabetically)
 * @param {object} dkimConfig - DKIM configuration object
 */
export async function saveDkimConfig(dkimConfig) {
  try {
    // Sort domains alphabetically
    const sortedConfig = Object.keys(dkimConfig)
      .sort()
      .reduce((acc, key) => {
        acc[key] = dkimConfig[key];
        return acc;
      }, {});

    const content = JSON.stringify(sortedConfig, null, 2);
    await fs.writeFile(
      path.resolve(process.cwd(), config.dkimConfigPath),
      content,
      'utf8',
    );
  } catch (error) {
    logger.error({ error: error.message }, 'Failed to save DKIM config file');
  }
}

/**
 * Create or update DKIM TXT record in the domain's zone
 * @param {string} domainName - Domain name
 * @param {string} selector - DKIM selector
 * @param {string} dkimValue - DKIM TXT record value
 * @returns {Promise<boolean>} Success status
 */
export async function updateDomainDKIMRecord(domainName, selector,
  dkimValue) {
  try {
    // Load zone data
    const zoneInfo = await getZone(domainName);
    if (!zoneInfo.data || !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0) {
      throw new Error('Invalid zone data received');
    }

    const zone = zoneInfo.data[0];
    if (!zone.resourceRecords) {zone.resourceRecords = [];}

    const recordName = `${selector}._domainkey`;
    let updated = false;
    for (const rr of zone.resourceRecords) {
      if (rr.type === 'TXT' && rr.name === recordName) {
        rr.value = dkimValue;
        rr.ttl = 300;
        updated = true;
        break;
      }
    }
    if (!updated) {
      zone.resourceRecords.push({
        name: recordName,
        type: 'TXT',
        value: dkimValue,
        ttl: 300,
      });
    }

    await updateZone(domainName, zone);
    return true;
  } catch (error) {
    logger.error(
      { domain: domainName, selector, error: error.message },
      'Failed to update DKIM record',
    );
    return false;
  }
}
