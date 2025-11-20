/**
 * ANSI color codes for terminal output
 */
export const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  gray: '\x1b[90m',
};

/**
 * Format local timestamp for display (YYYY-MM-DD HH:MM:SS)
 * @param {Date} date - Date to format (defaults to current date)
 * @returns {string} Formatted timestamp
 */
export function formatTimestamp(date = new Date()) {
  return `${[
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, '0'),
    String(date.getDate()).padStart(2, '0'),
  ].join('-')  } ${  [
    String(date.getHours()).padStart(2, '0'),
    String(date.getMinutes()).padStart(2, '0'),
    String(date.getSeconds()).padStart(2, '0'),
  ].join(':')}`;
}

/**
 * Generate timestamp string in YYYYMMDD-HHMMSS format for filenames
 * @param {Date} date - Date to format (defaults to current date)
 * @returns {string} Formatted timestamp for filenames
 */
export function getTimestamp(date = new Date()) {
  return `${[
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, '0'),
    String(date.getDate()).padStart(2, '0'),
  ].join('')  }-${  [
    String(date.getHours()).padStart(2, '0'),
    String(date.getMinutes()).padStart(2, '0'),
    String(date.getSeconds()).padStart(2, '0'),
  ].join('')}`;
}

/**
 * Parse summary counts from report lines
 * @param {string} reportContent - Full report content
 * @returns {object} Structured counts for SPF, DMARC, DKIM
 */
export function parseSummaryCounts(reportContent) {
  const lines = reportContent.split('\n');

  // Find all domain entries (lines with timestamp and domain name at start)
  const domainLines = lines.filter(l => /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} /.test(l));

  const countField = (fieldName, regex) => {
    let count = 0;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith(`${fieldName}:`)) {
        if (regex.test(lines[i])) {
          count++;
        }
      }
    }
    return count;
  };

  return {
    total: domainLines.length,
    spf: {
      ok: countField('SPF', /:\s+ok(?:\s|$|-)/),
      fail: countField('SPF', /:\s+fail/),
      error: countField('SPF', /:\s+error/),
      skipped: countField('SPF', /:\s+skipped/),
    },
    dmarc: {
      ok: countField('DMARC', /:\s+ok(?:\s|$|-)/),
      fail: countField('DMARC', /:\s+fail/),
      error: countField('DMARC', /:\s+error/),
      skipped: countField('DMARC', /:\s+skipped/),
    },
    dkim: {
      ok: countField('DKIM', /:\s+ok(?:\s|$|-)/),
      fail: countField('DKIM', /:\s+fail/),
      error: countField('DKIM', /:\s+error/),
      skipped: countField('DKIM', /:\s+skipped/),
    },
  };
}
