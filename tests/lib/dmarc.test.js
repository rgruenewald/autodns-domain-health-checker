import { describe, it, expect } from 'vitest';
import { normalizeDMARC } from '../../src/lib/dmarc.js';

describe('normalizeDMARC', () => {
  it('should remove spaces after semicolons', () => {
    const dmarc = 'v=DMARC1; p=reject; sp=reject';
    const result = normalizeDMARC(dmarc);
    expect(result).toBe('v=DMARC1;p=reject;sp=reject');
  });

  it('should normalize multiple spaces to single space', () => {
    const dmarc = 'v=DMARC1;p=reject;  sp=reject';
    const result = normalizeDMARC(dmarc);
    expect(result).toBe('v=DMARC1;p=reject;sp=reject');
  });

  it('should trim leading and trailing spaces', () => {
    const dmarc = '  v=DMARC1;p=reject  ';
    const result = normalizeDMARC(dmarc);
    expect(result).toBe('v=DMARC1;p=reject');
  });

  it('should handle complex DMARC records', () => {
    const dmarc = 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@example.com; fo=d:s';
    const result = normalizeDMARC(dmarc);
    expect(result).toBe('v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s;rua=mailto:dmarc-reports@example.com;fo=d:s');
  });

  it('should return null for null input', () => {
    const result = normalizeDMARC(null);
    expect(result).toBeNull();
  });

  it('should return null for undefined input', () => {
    const result = normalizeDMARC(undefined);
    expect(result).toBeNull();
  });

  it('should handle DMARC with no spaces', () => {
    const dmarc = 'v=DMARC1;p=reject;sp=reject';
    const result = normalizeDMARC(dmarc);
    expect(result).toBe('v=DMARC1;p=reject;sp=reject');
  });
});
