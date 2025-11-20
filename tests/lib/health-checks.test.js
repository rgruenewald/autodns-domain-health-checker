import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/lib/dns-operations.js', async () => {
  return {
    resolveNs: vi.fn(async (_d) => ['ns1.example.net', 'ns2.example.net']),
    resolveSoa: vi.fn(async (_d) => ({
      nsname: 'ns1.example.net', hostmaster: 'hostmaster.example.net',
      serial: 2024010101, refresh: 3600, retry: 600, expire: 1209600, minttl: 300,
    })),
    resolveCaa: vi.fn(async (_d) => [{critical: 0, iodef: undefined, tag: 'issue', value: 'letsencrypt.org'}]),
    resolve4: vi.fn(async (_h) => ['192.0.2.1']),
    resolve6: vi.fn(async (_h) => []),
    reversePtr: vi.fn(async (_ip) => ['mail.example.net']),
    safeResolveTxt: vi.fn(async (name) => name.startsWith('_mta-sts')
      ? [['v=STSv1; id=12345']] : name.startsWith('_smtp._tls')
        ? [['v=TLSRPTv1; rua=mailto:tls@example.net']] : []),
    nsHostsResolvable: vi.fn(async (_hosts) => true),
  };
});

vi.mock('axios', () => ({
  default: {
    get: vi.fn(async () => ({ data: 'version: STSv1\nmode: testing\nmx: mail.example.net' })),
  },
}));

import { checkNS, checkSOA, checkCAA, checkMtaSts, checkTlsRpt, checkPTRForOutbound, checkMXIntegrity, buildHealthSummary } from '../../src/lib/health-checks.js';

describe('health-checks', () => {
  it('checkNS returns ok with 2 resolvable NS', async () => {
    const res = await checkNS('example.com');
    expect(res.ok).toBe(true);
    expect(res.ns.length).toBeGreaterThanOrEqual(2);
  });

  it('checkSOA sanity passes for sane values', async () => {
    const res = await checkSOA('example.com');
    expect(res.ok).toBe(true);
    expect(res.details.refresh).toBe(3600);
  });

  it('checkCAA ok if no record or issue tag present', async () => {
    const res = await checkCAA('example.com');
    expect(res.ok).toBe(true);
  });

  it('checkMtaSts ok when TXT and HTTPS policy present', async () => {
    const res = await checkMtaSts('example.com');
    expect(res.ok).toBe(true);
    expect(res.txtFound).toBe(true);
    expect(res.httpsOk).toBe(true);
  });

  it('checkTlsRpt ok when TXT present', async () => {
    const res = await checkTlsRpt('example.com');
    expect(res.ok).toBe(true);
  });

  it('checkPTRForOutbound ok when PTR exists', async () => {
    const res = await checkPTRForOutbound('mail.example.net');
    expect(res.ok).toBe(true);
    expect(res.ptr.length).toBeGreaterThan(0);
  });

  it('checkMXIntegrity ok when targets resolve', async () => {
    const res = await checkMXIntegrity('example.com', ['mail.example.net']);
    expect(res.ok).toBe(true);
  });

  it('buildHealthSummary composes flags', () => {
    const status = {
      ns: { ok: true }, soa: { ok: true }, caa: { ok: true },
      mta: { ok: true }, tls: { ok: true }, ptr: { ok: true },
    };
    const s = buildHealthSummary(status);
    expect(s).toContain('NS:ok');
    expect(s).toContain('SOA:ok');
    expect(s).toContain('CAA:ok');
    expect(s).toContain('MTA:ok');
    expect(s).toContain('TLS:ok');
    expect(s).toContain('PTR:ok');
  });
});
