import { describe, it, expect } from 'vitest';
import {
  isValidDomainName,
  isValidEmail,
  isSafeFilePath,
  parseBoolean,
  parseInteger,
  isSafeDNSValue,
  isValidPort,
  sanitizeDomainName,
} from '../../src/utils/validators.js';

describe('validators', () => {
  describe('isValidDomainName', () => {
    it('should validate correct domain names', () => {
      expect(isValidDomainName('example.com')).toBe(true);
      expect(isValidDomainName('sub.example.com')).toBe(true);
      expect(isValidDomainName('multi.level.sub.example.com')).toBe(true);
      expect(isValidDomainName('example-with-dash.com')).toBe(true);
      expect(isValidDomainName('123.com')).toBe(true);
    });

    it('should reject invalid domain names', () => {
      expect(isValidDomainName('')).toBe(false);
      expect(isValidDomainName('invalid..com')).toBe(false);
      expect(isValidDomainName('-invalid.com')).toBe(false);
      expect(isValidDomainName('invalid-.com')).toBe(false);
      expect(isValidDomainName('invalid_domain.com')).toBe(false);
      expect(isValidDomainName(`${'a'.repeat(64)}.com`)).toBe(false);
      expect(isValidDomainName('a'.repeat(254))).toBe(false);
    });

    it('should throw TypeError for non-string input', () => {
      expect(() => isValidDomainName(123)).toThrow(TypeError);
      expect(() => isValidDomainName(null)).toThrow(TypeError);
      expect(() => isValidDomainName(undefined)).toThrow(TypeError);
    });
  });

  describe('isValidEmail', () => {
    it('should validate correct email addresses', () => {
      expect(isValidEmail('user@example.com')).toBe(true);
      expect(isValidEmail('user.name@example.com')).toBe(true);
      expect(isValidEmail('user+tag@example.com')).toBe(true);
      expect(isValidEmail('user123@sub.example.com')).toBe(true);
    });

    it('should reject invalid email addresses', () => {
      expect(isValidEmail('')).toBe(false);
      expect(isValidEmail('invalid')).toBe(false);
      expect(isValidEmail('invalid@')).toBe(false);
      expect(isValidEmail('@invalid.com')).toBe(false);
      expect(isValidEmail('invalid@.com')).toBe(false);
      expect(isValidEmail(`${'a'.repeat(65)}@example.com`)).toBe(false);
    });

    it('should throw TypeError for non-string input', () => {
      expect(() => isValidEmail(123)).toThrow(TypeError);
      expect(() => isValidEmail(null)).toThrow(TypeError);
    });
  });

  describe('isSafeFilePath', () => {
    it('should allow safe file paths', () => {
      expect(isSafeFilePath('./config.json', '/app')).toBe(true);
      expect(isSafeFilePath('config/file.json', '/app')).toBe(true);
      expect(isSafeFilePath('file.json', '/app')).toBe(true);
    });

    it('should reject dangerous file paths', () => {
      expect(isSafeFilePath('../../etc/passwd', '/app')).toBe(false);
      expect(isSafeFilePath('/etc/passwd', '/app')).toBe(false);
      expect(isSafeFilePath('/root/.ssh/id_rsa', '/app')).toBe(false);
      expect(isSafeFilePath('/proc/self/environ', '/app')).toBe(false);
      expect(isSafeFilePath('file\0.txt', '/app')).toBe(false);
    });

    it('should throw TypeError for non-string input', () => {
      expect(() => isSafeFilePath(123, '/app')).toThrow(TypeError);
      expect(() => isSafeFilePath('./file', 123)).toThrow(TypeError);
    });
  });

  describe('parseBoolean', () => {
    it('should parse boolean strings correctly', () => {
      expect(parseBoolean('true')).toBe(true);
      expect(parseBoolean('TRUE')).toBe(true);
      expect(parseBoolean('yes')).toBe(true);
      expect(parseBoolean('1')).toBe(true);
      expect(parseBoolean('on')).toBe(true);
      expect(parseBoolean('false')).toBe(false);
      expect(parseBoolean('FALSE')).toBe(false);
      expect(parseBoolean('no')).toBe(false);
      expect(parseBoolean('0')).toBe(false);
      expect(parseBoolean('off')).toBe(false);
    });

    it('should handle boolean values directly', () => {
      expect(parseBoolean(true)).toBe(true);
      expect(parseBoolean(false)).toBe(false);
    });

    it('should return default value for invalid input', () => {
      expect(parseBoolean('invalid', false)).toBe(false);
      expect(parseBoolean('invalid', true)).toBe(true);
      expect(parseBoolean(null, true)).toBe(true);
      expect(parseBoolean(undefined, false)).toBe(false);
    });
  });

  describe('parseInteger', () => {
    it('should parse integer strings correctly', () => {
      expect(parseInteger('42', 0)).toBe(42);
      expect(parseInteger('0', 10)).toBe(0);
      expect(parseInteger('-5', 0)).toBe(-5);
    });

    it('should handle number values directly', () => {
      expect(parseInteger(42, 0)).toBe(42);
      expect(parseInteger(3.7, 0)).toBe(3);
    });

    it('should return default value for invalid input', () => {
      expect(parseInteger('invalid', 10)).toBe(10);
      expect(parseInteger('', 5)).toBe(5);
      expect(parseInteger(null, 0)).toBe(0);
    });

    it('should validate min/max bounds', () => {
      expect(parseInteger('50', 0, 1, 100)).toBe(50);
      expect(() => parseInteger('150', 0, 1, 100)).toThrow(RangeError);
      expect(() => parseInteger('0', 0, 1, 100)).toThrow(RangeError);
    });
  });

  describe('isSafeDNSValue', () => {
    it('should allow safe DNS values', () => {
      expect(isSafeDNSValue('v=spf1 include:example.com ~all')).toBe(true);
      expect(isSafeDNSValue('v=DMARC1; p=none; rua=mailto:dmarc@example.com'))
        .toBe(true);
      expect(isSafeDNSValue('k=rsa; p=MIGfMA0GCS...')).toBe(true);
    });

    it('should reject dangerous DNS values', () => {
      expect(isSafeDNSValue('malicious\x00value')).toBe(false);
      expect(isSafeDNSValue('control\x1Fchar')).toBe(false);
      expect(isSafeDNSValue('a'.repeat(1001))).toBe(false);
    });

    it('should throw TypeError for non-string input', () => {
      expect(() => isSafeDNSValue(123)).toThrow(TypeError);
      expect(() => isSafeDNSValue(null)).toThrow(TypeError);
    });
  });

  describe('isValidPort', () => {
    it('should validate correct port numbers', () => {
      expect(isValidPort(80)).toBe(true);
      expect(isValidPort(443)).toBe(true);
      expect(isValidPort('8080')).toBe(true);
      expect(isValidPort(1)).toBe(true);
      expect(isValidPort(65535)).toBe(true);
    });

    it('should reject invalid port numbers', () => {
      expect(isValidPort(0)).toBe(false);
      expect(isValidPort(-1)).toBe(false);
      expect(isValidPort(65536)).toBe(false);
      expect(isValidPort(70000)).toBe(false);
      expect(isValidPort('invalid')).toBe(false);
      expect(isValidPort(3.14)).toBe(false);
    });
  });

  describe('sanitizeDomainName', () => {
    it('should sanitize valid domain names', () => {
      expect(sanitizeDomainName('EXAMPLE.COM')).toBe('example.com');
      expect(sanitizeDomainName(' example.com ')).toBe('example.com');
      expect(sanitizeDomainName('Example.Com')).toBe('example.com');
    });

    it('should throw error for invalid domain names', () => {
      expect(() => sanitizeDomainName('invalid..com')).toThrow(Error);
      expect(() => sanitizeDomainName('')).toThrow(Error);
      expect(() => sanitizeDomainName('-invalid.com')).toThrow(Error);
    });

    it('should throw TypeError for non-string input', () => {
      expect(() => sanitizeDomainName(123)).toThrow(TypeError);
      expect(() => sanitizeDomainName(null)).toThrow(TypeError);
    });
  });
});
