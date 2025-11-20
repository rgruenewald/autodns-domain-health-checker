import { describe, it, expect } from 'vitest';
import { colors, formatTimestamp, getTimestamp, parseSummaryCounts }
  from '../../src/utils/helpers.js';

describe('colors', () => {
  it('should export ANSI color codes', () => {
    expect(colors.green).toBe('\x1b[32m');
    expect(colors.red).toBe('\x1b[31m');
    expect(colors.reset).toBe('\x1b[0m');
    expect(colors.bold).toBe('\x1b[1m');
    expect(colors.gray).toBe('\x1b[90m');
  });
});

describe('formatTimestamp', () => {
  it('should format timestamp in YYYY-MM-DD HH:MM:SS format', () => {
    const date = new Date('2024-11-14T15:30:45');
    const result = formatTimestamp(date);
    expect(result).toBe('2024-11-14 15:30:45');
  });

  it('should pad single digits with zeros', () => {
    const date = new Date('2024-01-05T09:05:08');
    const result = formatTimestamp(date);
    expect(result).toBe('2024-01-05 09:05:08');
  });

  it('should use current date when no date provided', () => {
    const result = formatTimestamp();
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });
});

describe('getTimestamp', () => {
  it('should format timestamp in YYYYMMDD-HHMMSS format', () => {
    const date = new Date('2024-11-14T15:30:45');
    const result = getTimestamp(date);
    expect(result).toBe('20241114-153045');
  });

  it('should pad single digits with zeros', () => {
    const date = new Date('2024-01-05T09:05:08');
    const result = getTimestamp(date);
    expect(result).toBe('20240105-090508');
  });

  it('should use current date when no date provided', () => {
    const result = getTimestamp();
    expect(result).toMatch(/^\d{8}-\d{6}$/);
  });
});

describe('parseSummaryCounts', () => {
  it('should parse SPF counts correctly', () => {
    const report = `
2024-11-14 15:30:00 domain1.com
    SPF:        ok
    DMARC:      ok
    DKIM:       ok

2024-11-14 15:30:01 domain2.com
    SPF:        fail
    DMARC:      ok
    DKIM:       ok

2024-11-14 15:30:02 domain3.com
    SPF:        error
    DMARC:      ok
    DKIM:       ok

`;
    const result = parseSummaryCounts(report);

    expect(result.total).toBe(3);
    expect(result.spf.ok).toBe(1);
    expect(result.spf.fail).toBe(1);
    expect(result.spf.error).toBe(1);
  });

  it('should parse DMARC counts correctly', () => {
    const report = `
2024-11-14 15:30:00 domain1.com
    SPF:        ok
    DMARC:      ok
    DKIM:       ok

2024-11-14 15:30:01 domain2.com
    SPF:        ok
    DMARC:      fail
    DKIM:       ok

2024-11-14 15:30:02 domain3.com
    SPF:        ok
    DMARC:      error
    DKIM:       ok

`;
    const result = parseSummaryCounts(report);

    expect(result.dmarc.ok).toBe(1);
    expect(result.dmarc.fail).toBe(1);
    expect(result.dmarc.error).toBe(1);
  });

  it('should parse DKIM counts correctly including skipped', () => {
    const report = `
2024-11-14 15:30:00 domain1.com
    SPF:        ok
    DMARC:      ok
    DKIM:       ok

2024-11-14 15:30:01 domain2.com
    SPF:        ok
    DMARC:      ok
    DKIM:       fail

2024-11-14 15:30:02 domain3.com
    SPF:        ok
    DMARC:      ok
    DKIM:       error

2024-11-14 15:30:03 domain4.com
    SPF:        ok
    DMARC:      ok
    DKIM:       skipped

`;
    const result = parseSummaryCounts(report);

    expect(result.dkim.ok).toBe(1);
    expect(result.dkim.fail).toBe(1);
    expect(result.dkim.error).toBe(1);
    expect(result.dkim.skipped).toBe(1);
  });

  it('should handle empty report', () => {
    const result = parseSummaryCounts('');

    expect(result.total).toBe(0);
    expect(result.spf.ok).toBe(0);
    expect(result.dmarc.ok).toBe(0);
    expect(result.dkim.ok).toBe(0);
  });

  it('should handle report with mixed statuses', () => {
    const report = `
2024-11-14 15:30:00 domain1.com
    SPF:        ok
    DMARC:      fail
    DKIM:       skipped

2024-11-14 15:30:01 domain2.com
    SPF:        error
    DMARC:      ok
    DKIM:       ok

`;
    const result = parseSummaryCounts(report);

    expect(result.total).toBe(2);
    expect(result.spf.ok).toBe(1);
    expect(result.spf.error).toBe(1);
    expect(result.dmarc.ok).toBe(1);
    expect(result.dmarc.fail).toBe(1);
    expect(result.dkim.ok).toBe(1);
    expect(result.dkim.skipped).toBe(1);
  });
});
