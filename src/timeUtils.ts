/**
 * Utility functions for parsing and formatting WordPress timestamps
 * with strict awareness of the server's WordPress site timezone and browser timezone.
 */

export interface WpTimezoneContext {
  timezoneOffsetSec: number;
  timezoneString: string;
  gmtOffset: number;
  browserTimezone: string;
}

export interface FormattedTimeDetail {
  relative: string;
  siteTime: string;
  siteTimezone: string;
  userLocalTime: string;
  userTimezone: string;
  utcIso: string;
  tooltip: string;
}

/**
 * Safely resolves WordPress site timezone settings localized via wp_localize_script.
 * Handles string-to-number casting since WordPress casts all scalar localized values to string.
 */
export const getWpTimezoneSettings = (): WpTimezoneContext => {
  const settings = (typeof window !== 'undefined' ? (window as any).webcareScannerSettings : null) || {};
  const rawOffset = settings.timezoneOffset;
  const parsedOffset = rawOffset !== undefined && rawOffset !== null ? Number(rawOffset) : NaN;
  const timezoneOffsetSec = !isNaN(parsedOffset) ? parsedOffset : 0;
  
  const timezoneString = typeof settings.timezoneString === 'string' && settings.timezoneString.trim()
    ? settings.timezoneString.trim()
    : 'UTC';
    
  const rawGmt = settings.gmtOffset;
  const parsedGmt = rawGmt !== undefined && rawGmt !== null ? Number(rawGmt) : NaN;
  const gmtOffset = !isNaN(parsedGmt) ? parsedGmt : timezoneOffsetSec / 3600;

  let browserTimezone = 'UTC';
  try {
    browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch (e) {
    browserTimezone = 'Local';
  }

  return {
    timezoneOffsetSec,
    timezoneString,
    gmtOffset,
    browserTimezone,
  };
};

/**
 * Parses any date input into a high-precision JavaScript Date object in true UTC epoch.
 * Supports:
 * - Date instances
 * - Pure ISO 8601 strings with 'Z' or [+-]HH:MM offset
 * - MySQL datetime strings "YYYY-MM-DD HH:MM:SS(.uuu)?" calibrated to the WordPress site's timezone
 */
export const parseWpDate = (timeInput?: string | Date | null): Date | null => {
  if (!timeInput) return null;
  if (timeInput instanceof Date) return isNaN(timeInput.getTime()) ? null : timeInput;

  const str = String(timeInput).trim();
  if (!str) return null;

  // 1. If timestamp already has explicit ISO timezone indicator (Z or +/-HH:MM)
  if (str.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(str)) {
    const d = new Date(str);
    return isNaN(d.getTime()) ? null : d;
  }

  // 2. Handle standard MySQL format "YYYY-MM-DD HH:MM:SS(.uuu)?"
  const mysqlRegex = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;
  const match = str.match(mysqlRegex);
  if (match) {
    const year = parseInt(match[1], 10);
    const month = parseInt(match[2], 10) - 1;
    const day = parseInt(match[3], 10);
    const hour = parseInt(match[4], 10);
    const min = parseInt(match[5], 10);
    const sec = parseInt(match[6], 10);
    const millis = match[7] ? parseInt(match[7].padEnd(3, '0').slice(0, 3), 10) : 0;

    // Retrieve server timezone offset from WordPress site settings (seconds from UTC)
    const { timezoneOffsetSec } = getWpTimezoneSettings();
    const offsetMs = timezoneOffsetSec * 1000;

    // Date.UTC creates timestamp as if values were UTC; minus offsetMs converts the server local clock into true UTC epoch
    const utcEpoch = Date.UTC(year, month, day, hour, min, sec, millis) - offsetMs;
    const d = new Date(utcEpoch);
    return isNaN(d.getTime()) ? null : d;
  }

  // Fallback to standard parser
  const cleanStr = str.includes('T') ? str : str.replace(' ', 'T');
  const d = new Date(cleanStr);
  return isNaN(d.getTime()) ? null : d;
};

/**
 * Calculates human-readable relative time ("12m ago", "2h ago", "3d ago", "Just now").
 * Resilient against minor clock skew between browser device and server.
 */
export const formatRelativeTime = (timeInput?: string | Date | null): string => {
  if (!timeInput) return 'Just now';
  const d = parseWpDate(timeInput);
  if (!d) return 'Recently';

  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);

  // Slight clock skew between client computer and server (-60s to 0s)
  if (diffSec < 0 && diffSec >= -60) {
    return 'Just now';
  }

  // Future scheduled action or significant clock drift
  if (diffSec < -60) {
    const futureMin = Math.abs(Math.floor(diffSec / 60));
    if (futureMin < 60) return `in ${futureMin}m`;
    const futureHour = Math.floor(futureMin / 60);
    if (futureHour < 24) return `in ${futureHour}h`;
    const futureDay = Math.floor(futureHour / 24);
    return `in ${futureDay}d`;
  }

  if (diffSec < 60) return 'Just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 7) return `${diffDay}d ago`;

  // Fallback to formatted short date for old history
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
};

export const formatTelemetryTime = (timeStr?: string | null): string => {
  if (!timeStr) return 'N/A';
  const d = parseWpDate(timeStr);
  if (!d) return timeStr;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
};

export const formatTelemetryDateFull = (timeStr?: string | null): string => {
  if (!timeStr) return '';
  const d = parseWpDate(timeStr);
  if (!d) return timeStr;
  return d.toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
};

/**
 * Returns complete multi-region breakdown for audit inspection.
 * Formats time in both WordPress site timezone, user's local browser timezone, and UTC.
 */
export const formatDateTimeComprehensive = (timeInput?: string | Date | null): FormattedTimeDetail => {
  const emptyResult: FormattedTimeDetail = {
    relative: 'N/A',
    siteTime: 'N/A',
    siteTimezone: 'UTC',
    userLocalTime: 'N/A',
    userTimezone: 'UTC',
    utcIso: 'N/A',
    tooltip: 'No timestamp available',
  };

  if (!timeInput) return emptyResult;
  const d = parseWpDate(timeInput);
  if (!d) {
    const raw = String(timeInput);
    return {
      ...emptyResult,
      relative: raw,
      siteTime: raw,
      tooltip: raw,
    };
  }

  const { timezoneString, browserTimezone } = getWpTimezoneSettings();
  const relative = formatRelativeTime(d);
  const utcIso = d.toISOString();

  // 1. Site Time
  let siteTime = '';
  try {
    siteTime = d.toLocaleString('en-US', {
      timeZone: timezoneString,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch (e) {
    siteTime = d.toUTCString();
  }

  // 2. User Local Time (viewer's browser)
  let userLocalTime = '';
  try {
    userLocalTime = d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    });
  } catch (e) {
    userLocalTime = d.toLocaleString();
  }

  const tooltip = `Site Time: ${siteTime} (${timezoneString}) • Your Device: ${userLocalTime} (${browserTimezone}) • UTC: ${utcIso}`;

  return {
    relative,
    siteTime,
    siteTimezone: timezoneString,
    userLocalTime,
    userTimezone: browserTimezone,
    utcIso,
    tooltip,
  };
};
