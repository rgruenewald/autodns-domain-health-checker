import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as dns from 'dns';

// Mock dns module
vi.mock('dns', () => ({
  default: {
    resolveTxt: vi.fn(),
    resolve4: vi.fn(),
    resolve6: vi.fn(),
    resolveMx: vi.fn(),
    resolveNs: vi.fn(),
    resolveSoa: vi.fn(),
    resolveCaa: vi.fn(),
    reverse: vi.fn(),
  },
}));

// --- Mock helpers to reduce duplication across test cases ---
function mockResolve4(ips) {
  dns.default.resolve4.mockImplementation((name, callback) => {
    callback(null, ips);
  });
}
function mockResolve4Error() {
  dns.default.resolve4.mockImplementation((name, callback) => {
    callback(new Error('No A records'), null);
  });
}
function mockResolve6(ips) {
  dns.default.resolve6.mockImplementation((name, callback) => {
    callback(null, ips);
  });
}
function mockResolve6Error() {
  dns.default.resolve6.mockImplementation((name, callback) => {
    callback(new Error('No AAAA records'), null);
  });
}

describe('dns-operations', () => {
  let dnsOps;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Import after mocking
    dnsOps = await import('../../src/lib/dns-operations.js');
  });

  describe('safeResolveTxt', () => {
    it('should return TXT records on success', async () => {
      const mockRecords = [['v=spf1 include:example.com ~all']];
      dns.default.resolveTxt.mockImplementation((name, callback) => {
        callback(null, mockRecords);
      });

      const result = await dnsOps.safeResolveTxt('example.com');
      expect(result).toEqual(mockRecords);
    });

    it('should return empty array on DNS error', async () => {
      dns.default.resolveTxt.mockImplementation((name, callback) => {
        callback(new Error('ENOTFOUND'), null);
      });

      const result = await dnsOps.safeResolveTxt('nonexistent.example.com');
      expect(result).toEqual([]);
    });

    it('should return empty array on NXDOMAIN', async () => {
      dns.default.resolveTxt.mockImplementation((name, callback) => {
        const error = new Error('queryTxt ENOTFOUND');
        error.code = 'ENOTFOUND';
        callback(error, null);
      });

      const result = await dnsOps.safeResolveTxt('nxdomain.example.com');
      expect(result).toEqual([]);
    });
  });

  describe('resolveHostToIPs', () => {
    it('should resolve IPv4 addresses', async () => {
      mockResolve4(['192.0.2.1', '192.0.2.2']);
      mockResolve6Error();

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip4:192.0.2.1', 'ip4:192.0.2.2']);
    });

    it('should resolve IPv6 addresses', async () => {
      mockResolve4Error();
      mockResolve6(['2001:db8::1', '2001:db8::2']);

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip6:2001:db8::1', 'ip6:2001:db8::2']);
    });

    it('should resolve both IPv4 and IPv6 addresses', async () => {
      mockResolve4(['192.0.2.1']);
      mockResolve6(['2001:db8::1']);

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip4:192.0.2.1', 'ip6:2001:db8::1']);
    });

    it('should return empty array when no records exist', async () => {
      mockResolve4Error();
      mockResolve6Error();

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual([]);
    });
  });

  describe('resolveMxToIPs', () => {
    it('should resolve MX records and their IPs', async () => {
      dns.default.resolveMx.mockImplementation((domain, callback) => {
        callback(null, [
          { exchange: 'mail1.example.com', priority: 10 },
          { exchange: 'mail2.example.com', priority: 20 },
        ]);
      });

      dns.default.resolve4.mockImplementation((name, callback) => {
        if (name === 'mail1.example.com') {
          callback(null, ['192.0.2.1']);
        } else if (name === 'mail2.example.com') {
          callback(null, ['192.0.2.2']);
        } else {
          callback(new Error('Not found'), null);
        }
      });

      mockResolve6Error();

      const result = await dnsOps.resolveMxToIPs('example.com');
      expect(result).toEqual(['ip4:192.0.2.1', 'ip4:192.0.2.2']);
    });

    it('should return empty array when no MX records exist', async () => {
      dns.default.resolveMx.mockImplementation((domain, callback) => {
        callback(new Error('No MX records'), null);
      });

      const result = await dnsOps.resolveMxToIPs('example.com');
      expect(result).toEqual([]);
    });

    it('should handle MX hosts that do not resolve', async () => {
      dns.default.resolveMx.mockImplementation((domain, callback) => {
        callback(null, [{ exchange: 'mail.example.com', priority: 10 }]);
      });
      mockResolve4Error();
      mockResolve6Error();

      const result = await dnsOps.resolveMxToIPs('example.com');
      expect(result).toEqual([]);
    });
  });

  describe.each([
    {
      label: 'getARecords',
      fn: 'getARecords',
      records: [
        { type: 'A', name: '', value: '192.0.2.1' },
        { type: 'A', name: '@', value: '192.0.2.2' },
        { type: 'A', name: 'www', value: '192.0.2.3' },
      ],
      expected: ['192.0.2.1', '192.0.2.2'],
      expectedFallback: ['192.0.2.100'],
      mockFallback: () => mockResolve4(['192.0.2.100']),
      mockError: mockResolve4Error,
    },
    {
      label: 'getAAAARecords',
      fn: 'getAAAARecords',
      records: [
        { type: 'AAAA', name: '', value: '2001:db8::1' },
        { type: 'AAAA', name: '@', value: '2001:db8::2' },
        { type: 'AAAA', name: 'www', value: '2001:db8::3' },
      ],
      expected: ['2001:db8::1', '2001:db8::2'],
      expectedFallback: ['2001:db8::100'],
      mockFallback: () => mockResolve6(['2001:db8::100']),
      mockError: mockResolve6Error,
    },
    {
      label: 'getMXRecords',
      fn: 'getMXRecords',
      records: [
        { type: 'MX', name: '', value: 'mail1.example.com' },
        { type: 'MX', name: '@', value: 'mail2.example.com' },
        { type: 'MX', name: 'subdomain', value: 'mail3.example.com' },
      ],
      expected: ['mail1.example.com', 'mail2.example.com'],
      expectedFallback: ['mail.example.com'],
      mockFallback: () => {
        dns.default.resolveMx.mockImplementation((domain, callback) => {
          callback(null, [{ exchange: 'mail.example.com', priority: 10 }]);
        });
      },
      mockError: () => {
        dns.default.resolveMx.mockImplementation((domain, callback) => {
          callback(new Error('No MX records'), null);
        });
      },
    },
  ])('$label', ({ fn, records, expected, expectedFallback, mockFallback, mockError }) => {
    it('should return records from zone data', async () => {
      const zone = { resourceRecords: records };
      const result = await dnsOps[fn](zone, 'example.com');
      expect(result).toEqual(expected);
    });

    it('should fallback to DNS resolution when no zone records', async () => {
      const zone = { resourceRecords: [] };
      mockFallback();
      const result = await dnsOps[fn](zone, 'example.com');
      expect(result).toEqual(expectedFallback);
    });

    it('should return empty array when no records exist', async () => {
      const zone = { resourceRecords: [] };
      mockError();
      const result = await dnsOps[fn](zone, 'example.com');
      expect(result).toEqual([]);
    });
  });

  describe('nsHostsResolvable', () => {
    it('should return true when all NS hosts resolve', async () => {
      mockResolve4(['192.0.2.1']);
      mockResolve6Error();

      const result = await dnsOps.nsHostsResolvable([
        'ns1.example.com',
        'ns2.example.com',
      ]);
      expect(result).toBe(true);
    });

    it('should return false when any NS host does not resolve', async () => {
      dns.default.resolve4.mockImplementation((name, callback) => {
        if (name === 'ns1.example.com') {
          callback(null, ['192.0.2.1']);
        } else {
          callback(new Error('No A records'), null);
        }
      });
      mockResolve6Error();

      const result = await dnsOps.nsHostsResolvable([
        'ns1.example.com',
        'ns2.example.com',
      ]);
      expect(result).toBe(false);
    });

    it('should return true for empty array', async () => {
      const result = await dnsOps.nsHostsResolvable([]);
      expect(result).toBe(true);
    });
  });
});
