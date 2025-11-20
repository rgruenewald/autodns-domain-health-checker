import dns from 'dns';
import { promisify } from 'util';
import { logger } from '../utils/logger.js';

export const resolveTxt = promisify(dns.resolveTxt);
export const resolve4 = promisify(dns.resolve4);
export const resolve6 = promisify(dns.resolve6);
export const resolveMx = promisify(dns.resolveMx);
export const resolveNs = promisify(dns.resolveNs);
export const resolveSoa = promisify(dns.resolveSoa);
export const resolveCaa = promisify(dns.resolveCaa);
export const reversePtr = promisify(dns.reverse);

/**
 * Resolve a TXT name safely (returns [])
 */
export async function safeResolveTxt(name) {
  try { return await resolveTxt(name); } catch { return []; }
}

/**
 * Resolve A and AAAA records for a hostname
 * @param {string} hostname - Hostname to resolve
 * @returns {Promise<string[]>} Array of IP addresses with ip4:/ip6: prefix
 */
export async function resolveHostToIPs(hostname) {
  const ips = [];

  try {
    const ipv4 = await resolve4(hostname);
    ips.push(...ipv4.map(ip => `ip4:${ip}`));
  } catch (_error) {
    // No IPv4 records
  }

  try {
    const ipv6 = await resolve6(hostname);
    ips.push(...ipv6.map(ip => `ip6:${ip}`));
  } catch (_error) {
    // No IPv6 records
  }

  return ips;
}

/**
 * Resolve MX records and their IPs
 * @param {string} domain - Domain to query MX records
 * @returns {Promise<string[]>} Array of IP addresses from MX hosts
 */
export async function resolveMxToIPs(domain) {
  const ips = [];

  try {
    const mxRecords = await resolveMx(domain);
    for (const mx of mxRecords) {
      const mxIps = await resolveHostToIPs(mx.exchange);
      ips.push(...mxIps);
    }
  } catch (error) {
    logger.warn({ domain, error: error.message }, 'Could not resolve MX records');
  }

  return ips;
}

/**
 * Get A records for a domain (hybrid: zone API + DNS fallback)
 * @param {object} zone - Zone data from AutoDNS
 * @param {string} domainName - Domain name
 * @returns {Promise<string[]>} Array of A record IPs
 */
export async function getARecords(zone, domainName) {
  const aRecords = [];

  // First try zone API
  for (const rr of zone.resourceRecords || []) {
    if (rr.type === 'A' && (rr.name === '' || rr.name === '@')) {
      aRecords.push(rr.value);
    }
  }

  // Fallback to DNS resolution (handles main IP)
  if (aRecords.length === 0) {
    try {
      const resolved = await resolve4(domainName);
      aRecords.push(...resolved);
    } catch (_e) {
      // No A records
    }
  }

  return aRecords;
}

/**
 * Get AAAA records for a domain (hybrid: zone API + DNS fallback)
 * @param {object} zone - Zone data from AutoDNS
 * @param {string} domainName - Domain name
 * @returns {Promise<string[]>} Array of AAAA record IPs
 */
export async function getAAAARecords(zone, domainName) {
  const aaaaRecords = [];

  // First try zone API
  for (const rr of zone.resourceRecords || []) {
    if (rr.type === 'AAAA' && (rr.name === '' || rr.name === '@')) {
      aaaaRecords.push(rr.value);
    }
  }

  // Fallback to DNS resolution
  if (aaaaRecords.length === 0) {
    try {
      const resolved = await resolve6(domainName);
      aaaaRecords.push(...resolved);
    } catch (_e) {
      // No AAAA records
    }
  }

  return aaaaRecords;
}

/**
 * Get MX records for a domain (hybrid: zone API + DNS fallback)
 * @param {object} zone - Zone data from AutoDNS
 * @param {string} domainName - Domain name
 * @returns {Promise<string[]>} Array of MX record hostnames
 */
export async function getMXRecords(zone, domainName) {
  const mxRecords = [];

  // First try zone API
  for (const rr of zone.resourceRecords || []) {
    if (rr.type === 'MX' && (rr.name === '' || rr.name === '@')) {
      mxRecords.push(rr.value);
    }
  }

  // Fallback to DNS resolution
  if (mxRecords.length === 0) {
    try {
      const mxRaw = await resolveMx(domainName);
      mxRecords.push(...mxRaw.map(r => r.exchange));
    } catch (_e) {
      // No MX records
    }
  }

  return mxRecords;
}

/**
 * Check that each NS hostname resolves to at least one address
 */
export async function nsHostsResolvable(nsHosts) {
  let ok = true;
  for (const host of nsHosts) {
    try {
      const a = await resolve4(host).catch(() => []);
      const aaaa = await resolve6(host).catch(() => []);
      if (a.length === 0 && aaaa.length === 0) {ok = false;}
    } catch {
      ok = false;
    }
  }
  return ok;
}
