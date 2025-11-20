import axios from 'axios';
import { resolveNs, resolveSoa, resolveCaa, safeResolveTxt,
  resolve4, resolve6, reversePtr, nsHostsResolvable } from './dns-operations.js';

// Timeouts for HTTP checks
const HTTP_TIMEOUT = 5000;

export async function checkNS(domain) {
  try {
    const ns = await resolveNs(domain);
    const countOk = Array.isArray(ns) && ns.length >= 2;
    const resolvesOk = await nsHostsResolvable(ns);
    return { ok: countOk && resolvesOk, ns, details: { countOk, resolvesOk }};
  } catch (e) {
    return { ok: false, ns: [], details: { error: e.message } };
  }
}

/**
 * Check if domain uses AutoDNS nameservers
 * @param {string} domain - Domain to check
 * @returns {Promise<boolean>} True if domain uses AutoDNS nameservers
 */
export async function usesAutoDNSNameservers(domain) {
  try {
    const ns = await resolveNs(domain);
    if (!Array.isArray(ns) || ns.length === 0) {
      return false;
    }

    // Check if any nameserver matches AutoDNS patterns
    const autodnsPatterns = [
      'a.ns14.net',
      'b.ns14.net',
      'c.ns14.net',
      'd.ns14.net',
    ];

    return ns.some(nameserver => {
      const nsLower = nameserver.toLowerCase().replace(/\.$/, ''); // Remove trailing dot
      return autodnsPatterns.some(pattern => nsLower === pattern || nsLower.endsWith(`.${  pattern}`));
    });
  } catch (_) {
    return false;
  }
}

export function checkSOASanity(soa) {
  if (!soa) {return { ok: false, reason: 'no-soa' };}
  const { refresh, retry, expire, minttl } = soa;
  // sane ranges (very rough)
  const ok = refresh >= 3600 && refresh <= 86400 &&
    retry >= 300 && retry <= 7200 &&
    expire >= 604800 && expire <= 2419200 &&
    minttl >= 60 && minttl <= 86400;
  return { ok, refresh, retry, expire, minttl };
}

export async function checkSOA(domain) {
  try {
    const soa = await resolveSoa(domain);
    const sanity = checkSOASanity(soa);
    return { ok: sanity.ok, soa, details: sanity };
  } catch (e) {
    return { ok: false, soa: null, details: { error: e.message } };
  }
}

export async function checkCAA(domain) {
  try {
    const caa = await resolveCaa(domain).catch(() => []);
    // CAA optional; if present ensure at least one issue/issuewild
    const hasIssue = (caa || []).some(r =>
      r && (r.issue || r.issuewild || (r.tag && r.tag.startsWith('issue'))),
    );
    const present = (caa || []).length > 0;
    const ok = !present || hasIssue;
    return { ok, present, caa };
  } catch (e) {
    return { ok: false, present: false, caa: [], details: { error: e.message }};
  }
}

export async function checkMtaSts(domain) {
  try {
    const txt = await safeResolveTxt(`_mta-sts.${domain}`);
    const txtFound = txt.length > 0 && txt.flat().join('').includes('v=STSv1');
    let httpsOk = false;
    if (txtFound) {
      try {
        const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
        const resp = await axios.get(url, { timeout: HTTP_TIMEOUT });
        httpsOk = typeof resp.data === 'string' && resp.data.includes('version: STSv1');
      } catch {
        httpsOk = false;
      }
    }
    return { ok: txtFound && httpsOk, txtFound, httpsOk };
  } catch (e) {
    return { ok: false, txtFound: false, httpsOk: false, details: { error: e.message } };
  }
}

export async function checkTlsRpt(domain) {
  try {
    const txt = await safeResolveTxt(`_smtp._tls.${domain}`);
    const joined = txt.flat().join('');
    const ok = joined.includes('v=TLSRPTv1') && joined.includes('rua=');
    return { ok, txtFound: joined.length > 0 };
  } catch (e) {
    return { ok: false, txtFound: false, details: { error: e.message } };
  }
}

export async function checkPTRForOutbound(mxHost) {
  try {
    const v4 = await resolve4(mxHost).catch(() => []);
    const v6 = await resolve6(mxHost).catch(() => []);
    const ips = [...v4, ...v6];
    if (ips.length === 0) {return { ok: false, reason: 'no-a-for-mx', ptr: [] };}
    // Check first IP only for speed
    const ip = ips[0];
    const ptr = await reversePtr(ip).catch(() => []);
    return { ok: ptr.length > 0, ip, ptr };
  } catch (e) {
    return { ok: false, ptr: [], details: { error: e.message } };
  }
}

export async function checkMXIntegrity(domain, mxHosts) {
  const countOk = (mxHosts || []).length >= 1; // >=2 recommended; >=1 minimal
  let targetsResolvable = true;
  for (const h of mxHosts || []) {
    const a = await resolve4(h).catch(() => []);
    const aaaa = await resolve6(h).catch(() => []);
    if (a.length === 0 && aaaa.length === 0) {targetsResolvable = false;}
  }
  return { ok: countOk && targetsResolvable, count: (mxHosts||[]).length, targetsResolvable };
}

export function buildHealthSummary(status) {
  // compact inline summary string
  const flag = (v) => v ? 'ok' : 'fail';
  const parts = [];
  parts.push(`NS:${flag(status.ns.ok)}`);
  parts.push(`SOA:${flag(status.soa.ok)}`);
  parts.push(`CAA:${flag(status.caa.ok)}`);
  parts.push(`MTA:${flag(status.mta.ok)}`);
  parts.push(`TLS:${flag(status.tls.ok)}`);
  parts.push(`PTR:${flag(status.ptr.ok)}`);
  return parts.join('; ');
}
