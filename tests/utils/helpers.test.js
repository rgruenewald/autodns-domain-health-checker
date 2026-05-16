import { describe, it, expect } from 'vitest';
import { colors, formatTimestamp, getTimestamp, parseSummaryCounts }
  from '../../src/utils/helpers.js';

/**
 * Build a mock summary report string from domain entries.
 * Each entry is [timestamp, domain, spfStatus, dmarcStatus, dkimStatus].
 * @param {Array<[string,string,string,string,string]>} entries
 * @returns {string}
 */
function buildReport(entries) {
  return entries.map(([ts, domain, spf, dmarc, dkim]) =>
    `${ts} ${domain}\n    SPF:        ${spf}\n    DMARC:      ${dmarc}\n    DKIM:       ${dkim}\n`,
  ).join('\n');
}

const TS = '2024-11-14 15:30:0';

describe('colors', () => {
  it('should export ANSI color codes', () => {
    expect(colors.green).toBe('\x1b[32m');
    expect(colors.red).toBe('\x1b[31m');
    expect(colors.reset).toBe('\x1b[0m');
    expect(colors.bold).toBe('\x1b[1m');
    expect(colors.gray).toBe('\x1b[90m');
  });
});

describe.each([
  {
    label: 'formatTimestamp',
    fn: formatTimestamp,
    fmtDate: '2024-11-14 15:30:45',
    fmtPad:  '2024-01-05 09:05:08',
    noArgRe: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/,
  },
  {
    label: 'getTimestamp',
    fn: getTimestamp,
    fmtDate: '20241114-153045',
    fmtPad:  '20240105-090508',
    noArgRe: /^\d{8}-\d{6}$/,
  },
])('$label', ({ fn, fmtDate, fmtPad, noArgRe }) => {
  it('should format a specific date correctly', () => {
    expect(fn(new Date('2024-11-14T15:30:45'))).toBe(fmtDate);
  });

  it('should pad single digits with zeros', () => {
    expect(fn(new Date('2024-01-05T09:05:08'))).toBe(fmtPad);
  });

  it('should use current date when no date provided', () => {
    expect(fn()).toMatch(noArgRe);
  });
});

describe('parseSummaryCounts', () => {
  it.each([
    {
      label: 'SPF',
      entries: [
        [`${TS}0`, 'd1.com', 'ok', 'ok', 'ok'],
        [`${TS}1`, 'd2.com', 'fail', 'ok', 'ok'],
        [`${TS}2`, 'd3.com', 'error', 'ok', 'ok'],
      ],
      protocol: 'spf',
      expected: { ok: 1, fail: 1, error: 1, skipped: 0 },
    },
    {
      label: 'DMARC',
      entries: [
        [`${TS}0`, 'd1.com', 'ok', 'ok', 'ok'],
        [`${TS}1`, 'd2.com', 'ok', 'fail', 'ok'],
        [`${TS}2`, 'd3.com', 'ok', 'error', 'ok'],
      ],
      protocol: 'dmarc',
      expected: { ok: 1, fail: 1, error: 1, skipped: 0 },
    },
    {
      label: 'DKIM',
      entries: [
        [`${TS}0`, 'd1.com', 'ok', 'ok', 'ok'],
        [`${TS}1`, 'd2.com', 'ok', 'ok', 'fail'],
        [`${TS}2`, 'd3.com', 'ok', 'ok', 'error'],
        [`${TS}3`, 'd4.com', 'ok', 'ok', 'skipped'],
      ],
      protocol: 'dkim',
      expected: { ok: 1, fail: 1, error: 1, skipped: 1 },
    },
  ])('should parse $label counts correctly', ({ entries, protocol, expected }) => {
    const result = parseSummaryCounts(buildReport(entries));
    expect(result.total).toBe(entries.length);
    expect(result[protocol].ok).toBe(expected.ok);
    expect(result[protocol].fail).toBe(expected.fail);
    expect(result[protocol].error).toBe(expected.error);
    expect(result[protocol].skipped).toBe(expected.skipped);
  });

  it('should handle empty report', () => {
    const result = parseSummaryCounts('');

    expect(result.total).toBe(0);
    expect(result.spf.ok).toBe(0);
    expect(result.dmarc.ok).toBe(0);
    expect(result.dkim.ok).toBe(0);
  });

  it('should handle report with mixed statuses', () => {
    const report = buildReport([
      [`${TS}0`, 'domain1.com', 'ok', 'fail', 'skipped'],
      [`${TS}1`, 'domain2.com', 'error', 'ok', 'ok'],
    ]);
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
