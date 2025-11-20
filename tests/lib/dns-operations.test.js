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
      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(null, ['192.0.2.1', '192.0.2.2']);
      });
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA records'), null);
      });

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip4:192.0.2.1', 'ip4:192.0.2.2']);
    });

    it('should resolve IPv6 addresses', async () => {
      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(new Error('No A records'), null);
      });
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(null, ['2001:db8::1', '2001:db8::2']);
      });

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip6:2001:db8::1', 'ip6:2001:db8::2']);
    });

    it('should resolve both IPv4 and IPv6 addresses', async () => {
      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(null, ['192.0.2.1']);
      });
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(null, ['2001:db8::1']);
      });

      const result = await dnsOps.resolveHostToIPs('example.com');
      expect(result).toEqual(['ip4:192.0.2.1', 'ip6:2001:db8::1']);
    });

    it('should return empty array when no records exist', async () => {
      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(new Error('No A records'), null);
      });
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA records'), null);
      });

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

      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA'), null);
      });

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

      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(new Error('No A records'), null);
      });

      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA records'), null);
      });

      const result = await dnsOps.resolveMxToIPs('example.com');
      expect(result).toEqual([]);
    });
  });

  describe('getARecords', () => {
    it('should return A records from zone data', async () => {
      const zone = {
        resourceRecords: [
          { type: 'A', name: '', value: '192.0.2.1' },
          { type: 'A', name: '@', value: '192.0.2.2' },
          { type: 'A', name: 'www', value: '192.0.2.3' },
        ],
      };

      const result = await dnsOps.getARecords(zone, 'example.com');
      expect(result).toEqual(['192.0.2.1', '192.0.2.2']);
    });

    it('should fallback to DNS resolution when no zone records', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(null, ['192.0.2.100']);
      });

      const result = await dnsOps.getARecords(zone, 'example.com');
      expect(result).toEqual(['192.0.2.100']);
    });

    it('should return empty array when no A records exist', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(new Error('No A records'), null);
      });

      const result = await dnsOps.getARecords(zone, 'example.com');
      expect(result).toEqual([]);
    });
  });

  describe('getAAAARecords', () => {
    it('should return AAAA records from zone data', async () => {
      const zone = {
        resourceRecords: [
          { type: 'AAAA', name: '', value: '2001:db8::1' },
          { type: 'AAAA', name: '@', value: '2001:db8::2' },
          { type: 'AAAA', name: 'www', value: '2001:db8::3' },
        ],
      };

      const result = await dnsOps.getAAAARecords(zone, 'example.com');
      expect(result).toEqual(['2001:db8::1', '2001:db8::2']);
    });

    it('should fallback to DNS resolution when no zone records', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(null, ['2001:db8::100']);
      });

      const result = await dnsOps.getAAAARecords(zone, 'example.com');
      expect(result).toEqual(['2001:db8::100']);
    });

    it('should return empty array when no AAAA records exist', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA records'), null);
      });

      const result = await dnsOps.getAAAARecords(zone, 'example.com');
      expect(result).toEqual([]);
    });
  });

  describe('getMXRecords', () => {
    it('should return MX records from zone data', async () => {
      const zone = {
        resourceRecords: [
          { type: 'MX', name: '', value: 'mail1.example.com' },
          { type: 'MX', name: '@', value: 'mail2.example.com' },
          { type: 'MX', name: 'subdomain', value: 'mail3.example.com' },
        ],
      };

      const result = await dnsOps.getMXRecords(zone, 'example.com');
      expect(result).toEqual(['mail1.example.com', 'mail2.example.com']);
    });

    it('should fallback to DNS resolution when no zone records', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolveMx.mockImplementation((domain, callback) => {
        callback(null, [
          { exchange: 'mail.example.com', priority: 10 },
        ]);
      });

      const result = await dnsOps.getMXRecords(zone, 'example.com');
      expect(result).toEqual(['mail.example.com']);
    });

    it('should return empty array when no MX records exist', async () => {
      const zone = { resourceRecords: [] };

      dns.default.resolveMx.mockImplementation((domain, callback) => {
        callback(new Error('No MX records'), null);
      });

      const result = await dnsOps.getMXRecords(zone, 'example.com');
      expect(result).toEqual([]);
    });
  });

  describe('nsHostsResolvable', () => {
    it('should return true when all NS hosts resolve', async () => {
      dns.default.resolve4.mockImplementation((name, callback) => {
        callback(null, ['192.0.2.1']);
      });
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA'), null);
      });

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
      dns.default.resolve6.mockImplementation((name, callback) => {
        callback(new Error('No AAAA'), null);
      });

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
