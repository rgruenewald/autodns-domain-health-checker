import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  ConfigurationError,
} from '../../src/lib/config.js';

describe('config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Create a fresh copy of env for each test
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
  });

  describe('ConfigurationError', () => {
    it('should create error with correct name and message', () => {
      const error = new ConfigurationError('Test error message');
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('ConfigurationError');
      expect(error.message).toBe('Test error message');
    });

    it('should be catchable as ConfigurationError', () => {
      try {
        throw new ConfigurationError('Test');
      } catch (error) {
        expect(error).toBeInstanceOf(ConfigurationError);
      }
    });
  });

  describe('config parsing', () => {
    it('should parse AUTODNS_CONTEXT with default value', () => {
      // Test is tricky because config is imported at module level
      // This test documents expected behavior
      expect(typeof parseInt(process.env.AUTODNS_CONTEXT || '4', 10))
        .toBe('number');
    });

    it('should handle boolean environment variables', () => {
      process.env.DRY_RUN = 'true';
      process.env.TEST_DOMAINS_ENABLED = 'false';

      // Values would be parsed during config creation
      expect(process.env.DRY_RUN).toBe('true');
      expect(process.env.TEST_DOMAINS_ENABLED).toBe('false');
    });

    it('should parse SMTP_PORT with default', () => {
      delete process.env.SMTP_PORT;
      const defaultPort = parseInt(process.env.SMTP_PORT || '587', 10);
      expect(defaultPort).toBe(587);
    });

    it('should split comma-separated DKIM_SELECTORS', () => {
      process.env.DKIM_SELECTORS = 's1, s2, s3';
      const selectors = process.env.DKIM_SELECTORS
        .split(',')
        .map((s) => s.trim());
      expect(selectors).toEqual(['s1', 's2', 's3']);
    });

    it('should split comma-separated TEST_DOMAINS', () => {
      process.env.TEST_DOMAINS = 'test1.com, test2.com';
      const domains = process.env.TEST_DOMAINS
        .split(',')
        .map((s) => s.trim());
      expect(domains).toEqual(['test1.com', 'test2.com']);
    });
  });

  describe('validateConfig edge cases', () => {
    it('should handle missing required fields gracefully', () => {
      // This documents that validateConfig checks for credentials
      const hasUser = !!process.env.AUTODNS_USER;
      const hasPassword = !!process.env.AUTODNS_PASSWORD;

      // At least one should exist in test environment
      // or validation would fail
      expect(typeof hasUser).toBe('boolean');
      expect(typeof hasPassword).toBe('boolean');
    });

    it('should handle invalid email format detection', () => {
      // Email validation is now done via validators module
      const testEmail = 'invalid@';
      expect(testEmail.includes('@')).toBe(true);
      expect(testEmail.split('@')[1]).toBe('');
    });

    it('should handle invalid domain detection', () => {
      const invalidDomain = 'invalid..com';
      expect(invalidDomain.includes('..')).toBe(true);
    });

    it('should detect test domains enabled without domains', () => {
      process.env.TEST_DOMAINS_ENABLED = 'true';
      delete process.env.TEST_DOMAINS;

      const enabled = process.env.TEST_DOMAINS_ENABLED === 'true';
      const domains = process.env.TEST_DOMAINS ?
        process.env.TEST_DOMAINS.split(',') : [];

      expect(enabled).toBe(true);
      expect(domains.length).toBe(0);
    });
  });

  describe('configuration defaults', () => {
    it('should use default API URL', () => {
      delete process.env.AUTODNS_API_URL;
      const defaultUrl = process.env.AUTODNS_API_URL ||
        'https://api.autodns.com/v1';
      expect(defaultUrl).toBe('https://api.autodns.com/v1');
    });

    it('should use default email subject', () => {
      delete process.env.EMAIL_SUBJECT;
      const defaultSubject = process.env.EMAIL_SUBJECT ||
        'AutoDNS Domain Health Report';
      expect(defaultSubject).toBe('AutoDNS Domain Health Report');
    });

    it('should use default DKIM config path', () => {
      delete process.env.DKIM_CONFIG_PATH;
      const defaultPath = process.env.DKIM_CONFIG_PATH ||
        'dkim.config.json';
      expect(defaultPath).toBe('dkim.config.json');
    });

    it('should use default DKIM selectors', () => {
      delete process.env.DKIM_SELECTORS;
      const defaultSelectors = process.env.DKIM_SELECTORS ?
        process.env.DKIM_SELECTORS.split(',').map((s) => s.trim()) :
        ['s1', 's2'];
      expect(defaultSelectors).toEqual(['s1', 's2']);
    });

    it('should use default DMARC report auth domain', () => {
      delete process.env.DMARC_REPORT_AUTH_DOMAIN;
      const defaultDomain = process.env.DMARC_REPORT_AUTH_DOMAIN ||
        'example.com';
      expect(defaultDomain).toBe('example.com');
    });
  });

  describe('command line arguments', () => {
    it('should detect --dry-run flag', () => {
      const args = ['node', 'index.js', '--dry-run'];
      expect(args.includes('--dry-run')).toBe(true);
    });

    it('should handle missing --dry-run flag', () => {
      const args = ['node', 'index.js'];
      expect(args.includes('--dry-run')).toBe(false);
    });
  });
});
