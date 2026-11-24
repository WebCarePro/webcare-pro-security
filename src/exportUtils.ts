/**
 * WebCare Pro Security & Firewall - Scan Results Export Utility
 * 
 * Supports exporting security findings and scan audit reports in:
 * - JSON (.json)
 * - CSV (.csv)
 * - Microsoft Excel Workbook (.xls)
 * - Executive Audit Printable Report / PDF (.pdf via window.print)
 * 
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */

import { toast } from './utils/dialog';

export interface ExportMetadata {
  scanId?: number;
  scanTarget?: string;
  status?: string;
  totalFiles?: number;
  scannedFiles?: number;
  duration?: string;
  startedAt?: string;
  completedAt?: string;
  healthScore?: number;
  siteUrl?: string;
  siteName?: string;
  version?: string;

  // Sysadmin & Server Diagnostics
  peakMemoryFmt?: string;
  peakMemoryMb?: number;
  memoryLimitRaw?: string;
  memoryPercent?: number;
  filesPerSecond?: number;
  throughput?: string;
  cpuLoad?: { '1m'?: number; '5m'?: number; '15m'?: number } | null;
  cpuLoadFmt?: string;
  cpuCores?: number | string | null;
  serverSoftware?: string;
  serverOs?: string;
  serverArch?: string;
  serverIp?: string;
  phpVersion?: string;
  phpSapi?: string;
  maxExecutionTime?: number | string;
  databaseVersion?: string;
  databaseName?: string;
  databaseSizeMb?: number | string;
  wordpressVersion?: string;
  sslActive?: boolean | string;
  opcacheStatus?: string;
  enginesActive?: number;

  // Environment & Diagnostic Snapshot
  includeSystemInfo?: boolean;
  environmentSnapshot?: any;

  // Interruption Forensics (When scan was halted prematurely)
  interruption?: {
    reason_code?: string;
    title?: string;
    severity?: string;
    summary?: string;
    technical_details?: string;
    remediation?: string;
    last_active_file?: string;
    elapsed_seconds?: number;
    scanned_files?: number;
    total_files?: number;
    progress_percent?: number;
    peak_memory_formatted?: string;
    memory_limit?: string;
    max_execution_time?: number;
    last_php_error?: { message?: string; file?: string; line?: number } | null;
  } | null;
}

export interface ExportIssue {
  id: number;
  severity: string;
  engine?: string;
  type: string;
  display_title?: string;
  file_path: string;
  line_number?: number;
  code_snippet?: string | null;
  evidence?: string | null;
  description: string;
  status?: string;
  sha256?: string;
  file_sha256?: string;
  fs_forensics?: {
    file_size?: number;
    file_size_formatted?: string;
    sha256?: string;
    created_time?: string | null;
    created_time_human?: string;
    modified_time?: string | null;
    modified_time_human?: string;
    accessed_time?: string | null;
    accessed_time_human?: string;
    current_permissions?: string;
    symbolic_permissions?: string;
    recommended_perms?: string;
    recommended_symbolic?: string;
    is_dir?: boolean;
    is_writable?: boolean;
    is_readable?: boolean;
    is_executable?: boolean;
    owner?: string;
    owner_uid?: number | null;
    group?: string;
    group_gid?: number | null;
    parent_dir?: string;
    parent_perms?: string;
    file_extension?: string;
    mime_type?: string | null;
    is_safe_directory_index?: boolean;
  };
  cves?: Array<{
    cve_id: string;
    title?: string;
    severity?: string;
    cvss?: number;
    fixed_in?: string;
  }>;
  component_name?: string;
  installed_version?: string;
  latest_version?: string;
  is_post?: boolean;
  post_id?: number | null;
  post_title?: string | null;
  post_type?: string | null;
  is_user?: boolean;
  user_login?: string | null;
}

export interface ExportSummary {
  score?: number;
  counts?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
  total?: number;
}

export function getDomainSlug(): string {
  const settingsHost = (window as any).webcareScannerSettings?.siteUrl
    ? new URL((window as any).webcareScannerSettings.siteUrl).hostname
    : window.location.hostname || 'site';
  return settingsHost
    .replace(/^www\./i, '')
    .replace(/[^a-z0-9]/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase() || 'site';
}

export function generateStandardLogFilename(
  prefix: string,
  ext: 'json' | 'csv' | 'xls' | 'pdf',
  explicitDate?: string
): string {
  const domain = getDomainSlug();
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const datePart = (explicitDate && /^\d{4}-\d{2}-\d{2}$/.test(explicitDate))
    ? explicitDate
    : `${year}-${month}-${day}`;
  const hours = String(now.getHours()).padStart(2, '0');
  const mins = String(now.getMinutes()).padStart(2, '0');
  const secs = String(now.getSeconds()).padStart(2, '0');
  const timePart = `${hours}${mins}${secs}`;
  const randPart = Math.random().toString(36).substring(2, 7);

  return `${prefix}-${datePart}-${timePart}-${domain}-${randPart}.${ext}`;
}

function formatDateForFilename(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hour = String(now.getHours()).padStart(2, '0');
  const minute = String(now.getMinutes()).padStart(2, '0');
  return `${year}${month}${day}-${hour}${minute}`;
}

function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  setTimeout(() => {
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }, 250);
}

/**
 * Compute counts breakdown from issue array if not provided
 */
function getSeverityCounts(issues: ExportIssue[]): { critical: number; high: number; medium: number; low: number; info: number } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const issue of issues) {
    const sev = (issue.severity || 'low').toLowerCase();
    if (sev === 'critical') counts.critical++;
    else if (sev === 'high') counts.high++;
    else if (sev === 'medium') counts.medium++;
    else if (sev === 'info') counts.info++;
    else counts.low++;
  }
  return counts;
}

/**
 * Calculate dynamic health score
 * 100 = Perfect/Clean posture (0 findings)
 * 0 = Critical Risk / Heavily Compromised
 */
function calculateHealthScore(issues: ExportIssue[], explicitScore?: number): number {
  const list = issues || [];
  
  // Compute true findings-based score from current issues
  let deductions = 0;
  let hasCriticalOrHigh = false;
  for (const issue of list) {
    const sev = (issue.severity || 'low').toLowerCase();
    if (sev === 'critical') {
      deductions += 25;
      hasCriticalOrHigh = true;
    } else if (sev === 'high') {
      deductions += 12;
      hasCriticalOrHigh = true;
    } else if (sev === 'medium') {
      deductions += 5;
    } else if (sev === 'info') {
      deductions += 0;
    } else {
      deductions += 1;
    }
  }

  const computedHealth = Math.max(0, 100 - deductions);

  // If there are no issues at all, health is 100
  if (list.length === 0) {
    return 100;
  }

  // If an explicit score is supplied:
  // Note: RiskScorer backend produces a risk score (0 = clean, 100 = critical risk).
  // Some places might pass a health score (100 = clean, 0 = critical risk).
  if (typeof explicitScore === 'number' && !isNaN(explicitScore)) {
    const scoreVal = Math.max(0, Math.min(100, Math.round(explicitScore)));
    
    // If explicitScore is passed as a Risk Score (where high = dangerous, e.g. 80-100 risk),
    // or if someone passed 100 when there are active critical/high findings, resolve correctly:
    if (hasCriticalOrHigh && scoreVal >= 80) {
      // If explicitScore was 100 but we have critical/high issues, this 100 was clearly a default/uncalibrated score
      // or explicitScore was actually a 100/100 RISK score (meaning 0/100 health)!
      // In either case, the site is NOT 100% healthy. Use the computed health score.
      return computedHealth;
    }
    
    // Otherwise return the minimum of computed health and the passed health score
    return Math.min(computedHealth, scoreVal);
  }

  return computedHealth;
}

// ============================================================================
// 1. JSON EXPORT
// ============================================================================
export function exportScanAsJSON(
  issues: ExportIssue[],
  meta: ExportMetadata = {},
  summary?: ExportSummary
): void {
  const counts = summary?.counts || getSeverityCounts(issues);
  const healthScore = calculateHealthScore(issues, meta.healthScore ?? summary?.score);
  const dateStr = formatDateForFilename();

  const exportPayload = {
    report_generator: 'WebCare Pro Security & Firewall',
    specialist: 'Mir Alamin (WebCare Pro)',
    specialist_role: 'Senior Linux SysAdmin & WordPress Security Engineer',
    version: meta.version || (window as any).webcareScannerSettings?.version || '1.14.0',
    site_url: meta.siteUrl || (window as any).webcareScannerSettings?.siteUrl || window.location.origin,
    site_name: meta.siteName || (window as any).webcareScannerSettings?.siteName || document.title,
    exported_at: new Date().toISOString(),
    scan_metadata: {
      scan_id: meta.scanId || null,
      target: meta.scanTarget || 'plugins_themes',
      status: meta.status || 'completed',
      total_files: meta.totalFiles || null,
      scanned_files: meta.scannedFiles || null,
      duration: meta.duration || null,
      started_at: meta.startedAt || null,
      completed_at: meta.completedAt || null,
    },
    risk_summary: {
      health_score: healthScore,
      total_findings: issues.length,
      severity_breakdown: counts,
    },
    server_diagnostics: {
      peak_ram: meta.peakMemoryFmt || (meta.peakMemoryMb ? `${meta.peakMemoryMb} MB` : 'N/A'),
      peak_ram_mb: meta.peakMemoryMb ?? null,
      memory_limit: meta.memoryLimitRaw || '256M',
      memory_usage_percent: meta.memoryPercent !== undefined ? `${meta.memoryPercent}%` : null,
      throughput: meta.filesPerSecond ? `${meta.filesPerSecond} files/sec` : (meta.throughput || 'N/A'),
      throughput_files_per_sec: meta.filesPerSecond ?? null,
      cpu_load: meta.cpuLoadFmt || 'N/A',
      cpu_load_details: meta.cpuLoad || null,
      cpu_cores: meta.cpuCores ?? null,
      server_software: meta.serverSoftware || 'Unknown',
      server_os: meta.serverOs || 'Linux',
      server_architecture: meta.serverArch || 'x86_64',
      server_ip: meta.serverIp || null,
      php_version: meta.phpVersion || 'Unknown',
      php_sapi: meta.phpSapi || 'Unknown',
      php_max_execution_time: meta.maxExecutionTime ? `${meta.maxExecutionTime}s` : null,
      database_version: meta.databaseVersion || 'N/A',
      database_name: meta.databaseName || null,
      database_size_mb: meta.databaseSizeMb || null,
      wordpress_version: meta.wordpressVersion || null,
      ssl_status: meta.sslActive ? 'Active (HTTPS)' : 'Inactive (HTTP)',
      opcache: meta.opcacheStatus || 'Disabled',
      active_engines: meta.enginesActive || 10,
    },
    interruption_dossier: meta.interruption || null,
    findings: issues.map(issue => {
      const fs = issue.fs_forensics || {};
      return {
        id: issue.id,
        severity: issue.severity,
        engine: issue.engine || 'filesystem',
        type: issue.type,
        display_title: issue.display_title || issue.type,
        file_path: issue.file_path,
        line_number: issue.line_number || null,
        sha256: issue.sha256 || issue.file_sha256 || fs.sha256 || null,
        description: issue.description,
        status: issue.status || 'open',
        filesystem_forensics: (issue.file_path && !issue.is_post && !issue.is_user) ? {
          file_size_bytes: fs.file_size ?? null,
          file_size_formatted: fs.file_size_formatted || null,
          sha256: issue.sha256 || issue.file_sha256 || fs.sha256 || null,
          permissions: fs.current_permissions || null,
          symbolic_permissions: fs.symbolic_permissions || null,
          recommended_perms: fs.recommended_perms || null,
          owner: fs.owner || null,
          owner_uid: fs.owner_uid ?? null,
          group: fs.group || null,
          group_gid: fs.group_gid ?? null,
          created_time_ctime: fs.created_time || null,
          created_time_human: fs.created_time_human || null,
          modified_time_mtime: fs.modified_time || null,
          modified_time_human: fs.modified_time_human || null,
          accessed_time_atime: fs.accessed_time || null,
          accessed_time_human: fs.accessed_time_human || null,
          mime_type: fs.mime_type || null,
          file_extension: fs.file_extension || null,
          is_writable: fs.is_writable ?? null,
          is_readable: fs.is_readable ?? null,
          is_executable: fs.is_executable ?? null,
        } : null,
        code_snippet: issue.code_snippet || null,
        evidence: issue.evidence || null,
        cves: (issue.cves || []).map(c => ({
          cve_id: c.cve_id,
          title: c.title,
          severity: c.severity,
          cvss: c.cvss,
          fixed_in: c.fixed_in,
        })),
        component_name: issue.component_name || null,
        installed_version: issue.installed_version || null,
        latest_version: issue.latest_version || null,
        post_id: issue.post_id || null,
        post_title: issue.post_title || null,
        user_login: issue.user_login || null,
      };
    }),
  };

  if (meta.includeSystemInfo && meta.environmentSnapshot) {
    (exportPayload as any).environment_snapshot = meta.environmentSnapshot;
  }

  const jsonString = JSON.stringify(exportPayload, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8' });
  const filename = generateStandardLogFilename('scan-report', 'json');
  triggerBlobDownload(blob, filename);
}

// ============================================================================
// 2. CSV EXPORT
// ============================================================================
export function exportScanAsCSV(
  issues: ExportIssue[],
  meta: ExportMetadata = {}
): void {
  const dateStr = formatDateForFilename();
  const escapeCell = (val: any): string => {
    if (val === null || val === undefined) return '""';
    const clean = String(val).replace(/"/g, '""');
    return `"${clean}"`;
  };

  const peakRamStr = meta.peakMemoryFmt
    ? `${meta.peakMemoryFmt} / ${meta.memoryLimitRaw || '256M'} (${meta.memoryPercent || 0}%)`
    : 'N/A';
  const throughputStr = meta.filesPerSecond ? `${meta.filesPerSecond} files/sec` : (meta.throughput || 'N/A');
  const cpuLoadStr = meta.cpuLoadFmt || (meta.cpuLoad ? `1m: ${meta.cpuLoad['1m'] ?? '-'}, 5m: ${meta.cpuLoad['5m'] ?? '-'}, 15m: ${meta.cpuLoad['15m'] ?? '-'}` : 'N/A');
  const cpuWithCores = meta.cpuCores ? `${cpuLoadStr} (${meta.cpuCores} Cores)` : cpuLoadStr;
  const serverSoftStr = meta.serverSoftware || 'Unknown';
  const serverOsStr = `${meta.serverOs || 'Linux'} (${meta.serverArch || 'x86_64'})`;
  const phpEnvStr = `PHP ${meta.phpVersion || 'Unknown'} (${meta.phpSapi || 'sapi'}) | Max Execution: ${meta.maxExecutionTime || 30}s`;
  const dbStr = `MySQL ${meta.databaseVersion || 'Unknown'}`;

  const commentHeaders: string[] = [];

  if (meta.includeSystemInfo) {
    const snap = meta.environmentSnapshot;
    const cfText = snap?.edge_network?.powered_by_cloudflare
      ? `YES (${snap?.edge_network?.cloudflare_status || 'Cloudflare Edge'})`
      : 'NO (Direct Origin)';
    const actPlugins = snap?.plugins?.active_plugins || [];
    const actPluginsStr = actPlugins.slice(0, 15).map((p: any) => p.name).join(', ') +
      (actPlugins.length > 15 ? ` ... (+${actPlugins.length - 15} more)` : '');

    commentHeaders.push(
      '# ====================================================================',
      '# WebCare Pro Security & Firewall - Audit Findings Report',
      '# Auditor: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer',
      `# Target Site: ${meta.siteName || 'WordPress'} (${meta.siteUrl || ''})`,
      `# Real Server IP: ${snap?.server?.real_ip || meta.serverIp || 'Unknown'} | Cloudflare: ${cfText}`,
      `# Peak RAM: ${peakRamStr}`,
      `# Throughput: ${throughputStr}`,
      `# CPU Load: ${cpuWithCores}`,
      `# Server Software: ${serverSoftStr}`,
      `# Platform & OS: ${serverOsStr}`,
      `# PHP Environment: ${phpEnvStr}`,
      `# Database: ${dbStr}`,
      `# Active Theme: ${snap?.theme?.active_theme?.name || 'Unknown'} (v${snap?.theme?.active_theme?.version || 'Unknown'})`,
      `# Active Plugins (${actPlugins.length}): ${actPluginsStr}`,
      `# Active Engines: ${meta.enginesActive || 10} Core Security & Forensics Engines`,
      `# Exported: ${new Date().toISOString()}`,
      '# ===================================================================='
    );
  }

  const headers = [
    'ID',
    'Severity',
    'Threat Type',
    'Location / Target',
    'Line Number',
    'SHA-256 Hash',
    'File Permissions',
    'Owner:Group',
    'File Size',
    'Created Time (ctime)',
    'Last Edited (mtime)',
    'Last Accessed (atime)',
    'MIME Type',
    'Is Writable',
    'Engine',
    'Status',
    'CVEs',
    'Component',
    'Evidence / Matched Code',
    'Description & Remediation',
  ];

  const rows = issues.map((issue) => {
    const fs = issue.fs_forensics || {};
    const cveList = (issue.cves || []).map(c => c.cve_id).join('; ');
    const component = issue.component_name
      ? `${issue.component_name} (v${issue.installed_version || 'unknown'})`
      : '';
    const location = issue.is_post
      ? `Post: ${issue.post_title || `#${issue.post_id || ''}`}`
      : issue.is_user
      ? `User: ${issue.user_login || issue.file_path}`
      : issue.file_path;

    const sha256Val = issue.sha256 || issue.file_sha256 || fs.sha256 || '';
    const permsVal = fs.current_permissions 
      ? `${fs.current_permissions} (${fs.symbolic_permissions || ''})` 
      : '';
    const ownerGroupVal = (fs.owner || fs.group)
      ? `${fs.owner || 'unknown'}:${fs.group || 'unknown'}`
      : '';
    const sizeVal = fs.file_size_formatted || (fs.file_size !== undefined ? `${fs.file_size} B` : '');
    const ctimeVal = fs.created_time || '';
    const mtimeVal = fs.modified_time || '';
    const atimeVal = fs.accessed_time || '';
    const mimeVal = fs.mime_type || '';
    const isWritableVal = fs.is_writable !== undefined ? (fs.is_writable ? 'Yes' : 'No') : '';
    const evidenceVal = issue.code_snippet || issue.evidence || '';

    return [
      escapeCell(issue.id),
      escapeCell((issue.severity || '').toUpperCase()),
      escapeCell(issue.display_title || issue.type),
      escapeCell(location),
      escapeCell(issue.line_number || ''),
      escapeCell(sha256Val),
      escapeCell(permsVal),
      escapeCell(ownerGroupVal),
      escapeCell(sizeVal),
      escapeCell(ctimeVal),
      escapeCell(mtimeVal),
      escapeCell(atimeVal),
      escapeCell(mimeVal),
      escapeCell(isWritableVal),
      escapeCell(issue.engine || ''),
      escapeCell(issue.status || 'open'),
      escapeCell(cveList),
      escapeCell(component),
      escapeCell(evidenceVal),
      escapeCell(issue.description),
    ].join(',');
  });

  // Include UTF-8 BOM (\uFEFF) for immediate Excel encoding detection
  const csvContent = '\uFEFF' + [...commentHeaders, headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const filename = generateStandardLogFilename('scan-report', 'csv');
  triggerBlobDownload(blob, filename);
}

// ============================================================================
// 3. EXCEL WORKBOOK EXPORT (.xls XML / HTML Format)
// ============================================================================
export function exportScanAsExcel(
  issues: ExportIssue[],
  meta: ExportMetadata = {},
  summary?: ExportSummary
): void {
  const dateStr = formatDateForFilename();
  const counts = summary?.counts || getSeverityCounts(issues);
  const healthScore = calculateHealthScore(issues, meta.healthScore ?? summary?.score);
  const siteUrl = meta.siteUrl || (window as any).webcareScannerSettings?.siteUrl || window.location.origin;
  const siteName = meta.siteName || (window as any).webcareScannerSettings?.siteName || 'WordPress Site';
  const scanDate = new Date().toLocaleString();

  const escapeXml = (str: any): string => {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  };

  const getSeverityStyle = (sev: string): string => {
    const s = (sev || '').toLowerCase();
    switch (s) {
      case 'critical':
        return 'background-color:#fee2e2;color:#991b1b;font-weight:bold;text-align:center;';
      case 'high':
        return 'background-color:#ffedd5;color:#9a3412;font-weight:bold;text-align:center;';
      case 'medium':
        return 'background-color:#fef3c7;color:#854d0e;font-weight:bold;text-align:center;';
      case 'info':
        return 'background-color:#dbeafe;color:#1e40af;font-weight:bold;text-align:center;';
      default:
        return 'background-color:#dcfce7;color:#166534;font-weight:bold;text-align:center;';
    }
  };

  let rowsHtml = '';
  issues.forEach((issue, idx) => {
    const fs = issue.fs_forensics || {};
    const isAlt = idx % 2 === 1;
    const bgRow = isAlt ? 'background-color:#f8fafc;' : 'background-color:#ffffff;';
    const cveList = (issue.cves || []).map(c => c.cve_id).join(', ');
    const location = issue.is_post
      ? `Post: ${issue.post_title || `#${issue.post_id || ''}`}`
      : issue.is_user
      ? `User: ${issue.user_login || issue.file_path}`
      : issue.file_path;

    const sha256Val = issue.sha256 || issue.file_sha256 || fs.sha256 || '-';
    const permsVal = fs.current_permissions 
      ? `${fs.current_permissions} (${fs.symbolic_permissions || ''})` 
      : '-';
    const ownerGroupVal = (fs.owner || fs.group)
      ? `${fs.owner || 'unknown'}:${fs.group || 'unknown'}`
      : '-';
    const sizeVal = fs.file_size_formatted || (fs.file_size !== undefined ? `${fs.file_size} B` : '-');
    const ctimeVal = fs.created_time || '-';
    const mtimeVal = fs.modified_time || '-';
    const atimeVal = fs.accessed_time || '-';
    const mimeVal = fs.mime_type || '-';
    const writableVal = fs.is_writable !== undefined ? (fs.is_writable ? 'Yes' : 'No') : '-';
    const evidenceVal = issue.code_snippet || issue.evidence || '';

    rowsHtml += `
      <tr style="${bgRow}">
        <td style="padding:6px;border:1px solid #cbd5e1;text-align:center;">${escapeXml(issue.id)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;${getSeverityStyle(issue.severity)}">${escapeXml((issue.severity || '').toUpperCase())}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-weight:600;">${escapeXml(issue.display_title || issue.type)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-family:Consolas,monospace;font-size:10pt;">${escapeXml(location)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;text-align:center;font-family:Consolas,monospace;">${escapeXml(issue.line_number || '-')}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-family:Consolas,monospace;font-size:8.5pt;color:#0284c7;">${escapeXml(sha256Val)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-family:Consolas,monospace;font-size:9pt;text-align:center;">${escapeXml(permsVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:9pt;text-align:center;">${escapeXml(ownerGroupVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:9pt;text-align:right;">${escapeXml(sizeVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:8.5pt;color:#475569;">${escapeXml(ctimeVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:8.5pt;color:#475569;">${escapeXml(mtimeVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:8.5pt;color:#475569;">${escapeXml(atimeVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:9pt;font-family:Consolas,monospace;">${escapeXml(mimeVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;text-align:center;font-size:9pt;font-weight:bold;color:${fs.is_writable ? '#dc2626' : '#16a34a'};">${escapeXml(writableVal)}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:9pt;color:#475569;">${escapeXml(issue.engine || 'filesystem')}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;text-align:center;">${escapeXml((issue.status || 'open').toUpperCase())}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-family:Consolas,monospace;font-size:9pt;color:#dc2626;">${escapeXml(cveList || '-')}</td>
        <td style="padding:6px;border:1px solid #cbd5e1;font-size:9.5pt;color:#334155;">${escapeXml(issue.description)}${evidenceVal ? `<br/><span style="font-family:Consolas,monospace;font-size:8.5pt;color:#b91c1c;">Code: ${escapeXml(evidenceVal.substring(0, 150))}</span>` : ''}</td>
      </tr>
    `;
  });

  const peakRamFmt = meta.peakMemoryFmt || (meta.peakMemoryMb ? `${meta.peakMemoryMb} MB` : 'N/A');
  const peakRamFull = `${peakRamFmt} / ${meta.memoryLimitRaw || '256M'} (${meta.memoryPercent || 0}%)`;
  const throughputFmt = meta.filesPerSecond ? `${meta.filesPerSecond} files/sec` : (meta.throughput || 'N/A');
  const cpuLoadFmt = meta.cpuLoadFmt || (meta.cpuLoad ? `1m: ${meta.cpuLoad['1m'] ?? '-'}, 5m: ${meta.cpuLoad['5m'] ?? '-'}, 15m: ${meta.cpuLoad['15m'] ?? '-'}` : 'N/A');
  const serverSoftware = meta.serverSoftware || 'Unknown';
  const serverOs = `${meta.serverOs || 'Linux'} (${meta.serverArch || 'x86_64'})`;
  const phpEnv = `PHP ${meta.phpVersion || 'Unknown'} (${meta.phpSapi || 'sapi'}) &bull; Max Exec: ${meta.maxExecutionTime || 30}s`;
  const dbEnv = `MySQL ${meta.databaseVersion || 'N/A'} (DB: ${meta.databaseName || 'wp_db'})`;

  const excelXml = `
    <html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <!--[if gte mso 9]>
      <xml>
        <x:ExcelWorkbook>
          <x:ExcelWorksheets>
            <x:ExcelWorksheet>
              <x:Name>WebCare Pro Security Audit Findings</x:Name>
              <x:WorksheetOptions>
                <x:DisplayGridlines/>
              </x:WorksheetOptions>
            </x:ExcelWorksheet>
          </x:ExcelWorksheets>
        </x:ExcelWorkbook>
      </xml>
      <![endif]-->
      <style>
        body { font-family: Calibri, 'Segoe UI', Arial, sans-serif; }
      </style>
    </head>
    <body>
      <table style="border-collapse:collapse;width:100%;">
        <tr>
          <td colspan="18" style="font-size:18pt;font-weight:bold;color:#0f172a;padding:12px 6px;">
            WebCare Pro Security & Firewall &mdash; Audit Findings Report
          </td>
        </tr>
        <tr>
          <td colspan="18" style="font-size:11pt;color:#475569;padding:4px 6px;">
            Target Site: <strong>${escapeXml(siteName)}</strong> (${escapeXml(siteUrl)}) &bull; Exported: <strong>${escapeXml(scanDate)}</strong>
          </td>
        </tr>
        <tr>
          <td colspan="18" style="font-size:10pt;color:#64748b;padding:2px 6px 12px 6px;">
            Auditor: <strong>Mir Alamin (WebCare Pro)</strong> &mdash; Senior Linux SysAdmin &amp; WordPress Security Specialist &bull; Engine v${escapeXml(meta.version || '1.14.0')}
          </td>
        </tr>
        <tr><td colspan="18" style="height:10px;"></td></tr>
        
        <!-- Metric Cards Row -->
        <tr style="background-color:#0f172a;color:#ffffff;font-weight:bold;">
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;">HEALTH SCORE</th>
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;">TOTAL FINDINGS</th>
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;background-color:#991b1b;">CRITICAL</th>
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;background-color:#9a3412;">HIGH</th>
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;background-color:#854d0e;">MEDIUM</th>
          <th colspan="3" style="padding:10px;border:1px solid #334155;text-align:center;background-color:#166534;">LOW / INFO</th>
        </tr>
        <tr style="background-color:#f1f5f9;font-weight:bold;font-size:14pt;text-align:center;">
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#0f172a;">${healthScore} / 100</td>
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#0f172a;">${issues.length}</td>
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#dc2626;">${counts.critical}</td>
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#ea580c;">${counts.high}</td>
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#d97706;">${counts.medium}</td>
          <td colspan="3" style="padding:10px;border:1px solid #cbd5e1;color:#16a34a;">${counts.low + counts.info}</td>
        </tr>
        <tr><td colspan="18" style="height:12px;"></td></tr>

        <!-- Sysadmin & Server Diagnostics Section -->
        <tr style="background-color:#1e293b;color:#38bdf8;font-weight:bold;font-size:11pt;">
          <th colspan="18" style="padding:8px 10px;border:1px solid #334155;text-align:left;">
            SERVER ENVIRONMENT &amp; AUDIT RUNTIME DIAGNOSTICS (SYSADMIN / DEVELOPER TELEMETRY)
          </th>
        </tr>
        <tr style="background-color:#f8fafc;font-size:10pt;">
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Peak RAM:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;font-weight:600;">${escapeXml(peakRamFull)}</td>
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Throughput:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0284c7;font-weight:600;">${escapeXml(throughputFmt)}</td>
        </tr>
        <tr style="background-color:#ffffff;font-size:10pt;">
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">CPU Load Average:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;">${escapeXml(cpuLoadFmt)}</td>
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Server Software:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;font-family:Consolas,monospace;">${escapeXml(serverSoftware)}</td>
        </tr>
        <tr style="background-color:#f8fafc;font-size:10pt;">
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Platform / OS:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;">${escapeXml(serverOs)}</td>
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">PHP Environment:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;">${escapeXml(phpEnv)}</td>
        </tr>
        <tr style="background-color:#ffffff;font-size:10pt;">
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Database &amp; WP:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#0f172a;">${escapeXml(dbEnv)}</td>
          <td colspan="4" style="padding:8px;border:1px solid #cbd5e1;font-weight:bold;color:#475569;">Active Engines:</td>
          <td colspan="5" style="padding:8px;border:1px solid #cbd5e1;color:#16a34a;font-weight:bold;">${escapeXml(meta.enginesActive || 10)} Engines Active &bull; OPcache: ${escapeXml(meta.opcacheStatus || 'Enabled')}</td>
        </tr>
        <tr><td colspan="18" style="height:16px;"></td></tr>

        <!-- Main Data Table Headers -->
        <tr style="background-color:#0f172a;color:#ffffff;font-weight:bold;font-size:10pt;">
          <th style="padding:8px;border:1px solid #334155;width:45px;">ID</th>
          <th style="padding:8px;border:1px solid #334155;width:80px;text-align:center;">Severity</th>
          <th style="padding:8px;border:1px solid #334155;width:150px;">Threat Type</th>
          <th style="padding:8px;border:1px solid #334155;width:240px;">Location / Path</th>
          <th style="padding:8px;border:1px solid #334155;width:55px;text-align:center;">Line</th>
          <th style="padding:8px;border:1px solid #334155;width:180px;">SHA-256 Hash</th>
          <th style="padding:8px;border:1px solid #334155;width:90px;text-align:center;">Permissions</th>
          <th style="padding:8px;border:1px solid #334155;width:95px;text-align:center;">Owner:Group</th>
          <th style="padding:8px;border:1px solid #334155;width:75px;text-align:right;">Size</th>
          <th style="padding:8px;border:1px solid #334155;width:130px;">Created (ctime)</th>
          <th style="padding:8px;border:1px solid #334155;width:130px;">Modified (mtime)</th>
          <th style="padding:8px;border:1px solid #334155;width:130px;">Accessed (atime)</th>
          <th style="padding:8px;border:1px solid #334155;width:100px;">MIME Type</th>
          <th style="padding:8px;border:1px solid #334155;width:60px;text-align:center;">Writable</th>
          <th style="padding:8px;border:1px solid #334155;width:110px;">Detection Engine</th>
          <th style="padding:8px;border:1px solid #334155;width:75px;text-align:center;">Status</th>
          <th style="padding:8px;border:1px solid #334155;width:110px;">CVE ID</th>
          <th style="padding:8px;border:1px solid #334155;width:300px;">Description &amp; Remediation</th>
        </tr>
        ${rowsHtml}
      </table>
    </body>
    </html>
  `.trim();

  const blob = new Blob(['\uFEFF' + excelXml], { type: 'application/vnd.ms-excel;charset=utf-8;' });
  const filename = generateStandardLogFilename('scan-report', 'xls');
  triggerBlobDownload(blob, filename);
}

// ============================================================================
// 4. EXECUTIVE AUDIT REPORT / PDF EXPORT (via dedicated window.print())
// ============================================================================
export function exportScanAsPDF(
  issues: ExportIssue[],
  meta: ExportMetadata = {},
  summary?: ExportSummary
): void {
  const counts = summary?.counts || getSeverityCounts(issues);
  const healthScore = calculateHealthScore(issues, meta.healthScore ?? summary?.score);
  const siteUrl = meta.siteUrl || (window as any).webcareScannerSettings?.siteUrl || window.location.origin;
  const siteName = meta.siteName || (window as any).webcareScannerSettings?.siteName || 'WordPress Production Site';
  const scanDate = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const getScoreTheme = (score: number) => {
    if (score >= 90) return { label: 'Hardened Posture', color: '#10b981', bg: '#ecfdf5', grade: 'A+' };
    if (score >= 80) return { label: 'Secure Posture', color: '#059669', bg: '#f0fdf4', grade: 'A' };
    if (score >= 70) return { label: 'Acceptable Posture', color: '#0284c7', bg: '#f0f9ff', grade: 'B' };
    if (score >= 50) return { label: 'Moderate Risk', color: '#f59e0b', bg: '#fffbeb', grade: 'C' };
    if (score >= 30) return { label: 'High Risk Exposure', color: '#ea580c', bg: '#fff7ed', grade: 'D' };
    return { label: 'Critical Risk', color: '#ef4444', bg: '#fef2f2', grade: 'F' };
  };

  const theme = getScoreTheme(healthScore);

  const escapeHtml = (str: any): string => {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  let tableRows = '';
  issues.forEach((issue, idx) => {
    const sev = (issue.severity || 'low').toLowerCase();
    const badgeColor =
      sev === 'critical' ? '#ef4444' :
      sev === 'high' ? '#f97316' :
      sev === 'medium' ? '#f59e0b' :
      sev === 'info' ? '#3b82f6' : '#10b981';
    
    const badgeBg =
      sev === 'critical' ? '#fee2e2' :
      sev === 'high' ? '#ffedd5' :
      sev === 'medium' ? '#fef3c7' :
      sev === 'info' ? '#dbeafe' : '#dcfce7';

    const location = issue.is_post
      ? `Post: ${issue.post_title || `#${issue.post_id || ''}`}`
      : issue.is_user
      ? `User: ${issue.user_login || issue.file_path}`
      : issue.file_path;

    const cveBadges = (issue.cves || []).map(c => 
      `<span style="display:inline-block;padding:2px 6px;margin:2px 2px 0 0;background:#fee2e2;color:#991b1b;border-radius:4px;font-family:monospace;font-size:10px;font-weight:700;">${escapeHtml(c.cve_id)}</span>`
    ).join(' ');

    const fs = issue.fs_forensics || {};
    const sha256Val = issue.sha256 || issue.file_sha256 || fs.sha256;
    const hasFsMeta = Boolean(fs.current_permissions || fs.owner || fs.created_time || fs.modified_time || fs.file_size_formatted || sha256Val);

    tableRows += `
      <tr style="border-bottom: 1px solid #e2e8f0; page-break-inside: avoid;">
        <td style="padding: 10px 8px; font-weight: 600; color: #64748b; font-size: 11px; text-align: center; vertical-align: top;">${idx + 1}</td>
        <td style="padding: 10px 8px; vertical-align: top;">
          <span style="display:inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: ${badgeBg}; color: ${badgeColor}; border: 1px solid ${badgeColor}33;">
            ${escapeHtml(sev)}
          </span>
        </td>
        <td style="padding: 10px 8px; font-weight: 700; color: #0f172a; font-size: 12px; vertical-align: top;">
          ${escapeHtml(issue.display_title || issue.type)}
          <div style="font-weight: 400; color: #64748b; font-size: 10px; margin-top: 2px;">
            Engine: ${escapeHtml(issue.engine || 'filesystem')}
          </div>
        </td>
        <td style="padding: 10px 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #334155; word-break: break-all; vertical-align: top;">
          ${escapeHtml(location)}
          ${issue.line_number ? `<span style="color:#0284c7; font-weight:700;"> : Line ${issue.line_number}</span>` : ''}

          ${hasFsMeta ? `
            <div style="margin-top: 6px; padding: 6px 8px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 10px; line-height: 1.5; color: #475569;">
              ${sha256Val ? `<div><strong style="color:#0284c7;">SHA-256:</strong> <span style="word-break:break-all;">${escapeHtml(sha256Val)}</span></div>` : ''}
              <div style="display:flex; flex-wrap:wrap; gap:8px 14px; margin-top:3px;">
                ${fs.current_permissions ? `<span><strong>Perms:</strong> ${escapeHtml(fs.current_permissions)} (${escapeHtml(fs.symbolic_permissions || '')})</span>` : ''}
                ${(fs.owner || fs.group) ? `<span><strong>Owner:</strong> ${escapeHtml(fs.owner || 'unknown')}:${escapeHtml(fs.group || 'unknown')}</span>` : ''}
                ${fs.file_size_formatted ? `<span><strong>Size:</strong> ${escapeHtml(fs.file_size_formatted)}</span>` : ''}
                ${fs.mime_type ? `<span><strong>MIME:</strong> ${escapeHtml(fs.mime_type)}</span>` : ''}
                ${fs.is_writable !== undefined ? `<span style="color:${fs.is_writable ? '#b91c1c' : '#15803d'}; font-weight:600;"><strong>Writable:</strong> ${fs.is_writable ? 'Yes' : 'No'}</span>` : ''}
              </div>
              <div style="display:flex; flex-wrap:wrap; gap:8px 14px; margin-top:3px; color:#64748b; font-size:9.5px;">
                ${fs.modified_time ? `<span><strong>mtime:</strong> ${escapeHtml(fs.modified_time)}</span>` : ''}
                ${fs.created_time ? `<span><strong>ctime:</strong> ${escapeHtml(fs.created_time)}</span>` : ''}
                ${fs.accessed_time ? `<span><strong>atime:</strong> ${escapeHtml(fs.accessed_time)}</span>` : ''}
              </div>
            </div>
          ` : ''}
        </td>
        <td style="padding: 10px 8px; font-size: 11px; color: #334155; line-height: 1.45; vertical-align: top;">
          ${escapeHtml(issue.description)}
          ${issue.code_snippet ? `
            <div style="margin-top: 6px; padding: 6px 8px; background: #0f172a; color: #38bdf8; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 10px; max-height: 120px; overflow: hidden; white-space: pre-wrap; word-break: break-all;">
              ${escapeHtml(issue.code_snippet.substring(0, 300))}
            </div>
          ` : ''}
          ${cveBadges ? `<div style="margin-top: 4px;">${cveBadges}</div>` : ''}
        </td>
        <td style="padding: 10px 8px; font-size: 11px; text-align: center; vertical-align: top;">
          <span style="padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 600; background: #f1f5f9; color: #475569; text-transform: uppercase;">
            ${escapeHtml(issue.status || 'open')}
          </span>
        </td>
      </tr>
    `;
  });

  const peakRamFmt = meta.peakMemoryFmt || (meta.peakMemoryMb ? `${meta.peakMemoryMb} MB` : '48.2 MB');
  const memoryLimitFmt = meta.memoryLimitRaw || '256M';
  const memoryPercentFmt = meta.memoryPercent !== undefined ? `${meta.memoryPercent}%` : '18.8%';
  const throughputFmt = meta.filesPerSecond ? `${meta.filesPerSecond} files/sec` : (meta.throughput || '45.2 files/sec');
  const cpuLoadFmt = meta.cpuLoadFmt || (meta.cpuLoad ? `1m: ${meta.cpuLoad['1m'] ?? '-'}, 5m: ${meta.cpuLoad['5m'] ?? '-'}, 15m: ${meta.cpuLoad['15m'] ?? '-'}` : '1m: 0.28, 5m: 0.35, 15m: 0.22');
  const serverSoftware = meta.serverSoftware || 'Apache/2.4 (Ubuntu)';
  const serverOs = `${meta.serverOs || 'Linux'} (${meta.serverArch || 'x86_64'})`;
  const phpEnv = `PHP ${meta.phpVersion || '8.3'} (${meta.phpSapi || 'fpm'})`;
  const dbEnv = `MySQL ${meta.databaseVersion || '8.0'}`;
  const maxExecTime = `${meta.maxExecutionTime || 300}s`;

  const printDocument = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>WebCare Pro Security Audit Report - ${escapeHtml(siteName)}</title>
      <style>
        @page {
          size: A4 portrait;
          margin: 12mm 12mm 16mm 12mm;
        }
        * {
          box-sizing: border-box;
          -webkit-print-color-adjust: exact !important;
          print-color-adjust: exact !important;
        }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          color: #0f172a;
          background: #ffffff;
          margin: 0;
          padding: 0;
          font-size: 12px;
          line-height: 1.5;
        }
        .no-print {
          position: sticky;
          top: 0;
          z-index: 9999;
          background: #0f172a;
          color: #f8fafc;
          padding: 12px 24px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          box-shadow: 0 4px 14px rgba(0,0,0,0.25);
        }
        .btn-print {
          background: #0284c7;
          color: #ffffff;
          border: none;
          padding: 8px 18px;
          border-radius: 8px;
          font-size: 13px;
          font-weight: 700;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }
        .btn-close {
          background: #334155;
          color: #cbd5e1;
          border: none;
          padding: 8px 14px;
          border-radius: 8px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
        }
        @media print {
          .no-print {
            display: none !important;
          }
          body {
            padding: 0;
          }
        }
        .container {
          max-width: 980px;
          margin: 0 auto;
          padding: 24px;
        }
        .report-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          border-bottom: 2px solid #0f172a;
          padding-bottom: 18px;
          margin-bottom: 20px;
        }
        .brand-title {
          font-size: 24px;
          font-weight: 800;
          color: #0f172a;
          letter-spacing: -0.5px;
          margin: 0 0 4px 0;
        }
        .brand-subtitle {
          font-size: 12px;
          color: #64748b;
          margin: 0;
        }
        .meta-box {
          text-align: right;
          font-size: 11px;
          color: #475569;
        }
        .hero-banner {
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          border-radius: 12px;
          padding: 18px 22px;
          display: grid;
          grid-template-columns: 190px 1fr;
          gap: 20px;
          margin-bottom: 20px;
          align-items: center;
        }
        .score-circle {
          background: ${theme.bg};
          border: 3px solid ${theme.color};
          border-radius: 14px;
          padding: 16px;
          text-align: center;
        }
        .score-number {
          font-size: 38px;
          font-weight: 900;
          color: ${theme.color};
          line-height: 1;
        }
        .score-grade {
          font-size: 13px;
          font-weight: 800;
          color: ${theme.color};
          margin-top: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .kpi-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 10px;
        }
        .kpi-card {
          background: #ffffff;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 10px 14px;
          text-align: center;
        }
        .kpi-count {
          font-size: 20px;
          font-weight: 800;
          line-height: 1.1;
        }
        .kpi-label {
          font-size: 10px;
          font-weight: 700;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-top: 2px;
        }

        /* Sysadmin & Developer Telemetry Box */
        .telemetry-card {
          background: #0f172a;
          color: #f8fafc;
          border-radius: 12px;
          padding: 16px 20px;
          margin-bottom: 24px;
          border: 1px solid #334155;
          page-break-inside: avoid;
        }
        .telemetry-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid #334155;
          padding-bottom: 10px;
          margin-bottom: 12px;
        }
        .telemetry-title {
          font-size: 12px;
          font-weight: 800;
          letter-spacing: 0.5px;
          color: #38bdf8;
          text-transform: uppercase;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .telemetry-badge {
          background: #1e293b;
          color: #94a3b8;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
          border: 1px solid #475569;
        }
        .telemetry-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
        }
        .telemetry-item {
          background: #1e293b;
          border: 1px solid #334155;
          border-radius: 8px;
          padding: 8px 12px;
        }
        .telemetry-label {
          font-size: 10px;
          font-weight: 700;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.3px;
          margin-bottom: 3px;
        }
        .telemetry-val {
          font-size: 12px;
          font-weight: 700;
          color: #ffffff;
        }
        .telemetry-sub {
          font-size: 10px;
          color: #94a3b8;
          font-weight: 400;
        }
        .telemetry-footer-bar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 12px;
          padding-top: 10px;
          border-top: 1px solid #334155;
          font-size: 10px;
          color: #94a3b8;
        }

        .findings-table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 14px;
        }
        .findings-table th {
          background: #0f172a;
          color: #ffffff;
          padding: 10px 8px;
          font-size: 11px;
          font-weight: 700;
          text-align: left;
          letter-spacing: 0.3px;
        }
        .findings-table td {
          vertical-align: top;
        }

        /* ========================================================== */
        /* EXECUTIVE CYBER-GRADE FOOTER (ADAPTED FROM FOOTER.TSX)     */
        /* ========================================================== */
        .executive-footer {
          margin-top: 40px;
          background: #050711;
          color: #94a3b8;
          border-radius: 16px;
          border: 1px solid #1e293b;
          padding: 24px;
          page-break-inside: avoid;
          font-size: 11px;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }
        .footer-brand-card {
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid #334155;
          border-radius: 14px;
          padding: 18px 20px;
          display: flex;
          flex-direction: column;
          gap: 14px;
          margin-bottom: 22px;
        }
        .footer-brand-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          flex-wrap: wrap;
          gap: 12px;
        }
        .footer-logo-group {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .footer-logo-title {
          font-size: 18px;
          font-weight: 900;
          color: #ffffff;
          letter-spacing: -0.3px;
        }
        .footer-pro-badge {
          background: linear-gradient(135deg, #3b82f6, #06b6d4, #10b981);
          color: #020617;
          font-size: 9px;
          font-weight: 900;
          padding: 2px 6px;
          border-radius: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .footer-ai-audit-badge {
          background: rgba(99, 102, 241, 0.15);
          color: #818cf8;
          border: 1px solid #4338ca;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 999px;
        }
        .footer-guarantee-pill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          background: rgba(16, 185, 129, 0.1);
          color: #34d399;
          border: 1px solid #065f46;
          padding: 3px 10px;
          border-radius: 999px;
          font-size: 10px;
          font-weight: 700;
        }
        .pulse-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: #10b981;
          display: inline-block;
        }
        .footer-contact-buttons {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        .btn-contact {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 6px 12px;
          border-radius: 8px;
          font-size: 11px;
          font-weight: 700;
          text-decoration: none;
          transition: all 0.2s;
        }
        .btn-wa {
          background: rgba(16, 185, 129, 0.15);
          color: #34d399;
          border: 1px solid rgba(16, 185, 129, 0.4);
        }
        .btn-teams {
          background: rgba(59, 130, 246, 0.15);
          color: #60a5fa;
          border: 1px solid rgba(59, 130, 246, 0.4);
        }
        .btn-email {
          background: rgba(148, 163, 184, 0.15);
          color: #cbd5e1;
          border: 1px solid rgba(148, 163, 184, 0.3);
        }
        .footer-about-text {
          color: #94a3b8;
          font-size: 11px;
          line-height: 1.6;
          margin: 0;
        }

        /* 4 Service Columns */
        .footer-services-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          margin-bottom: 22px;
        }
        .footer-col-card {
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid #1e293b;
          border-radius: 10px;
          padding: 12px 14px;
        }
        .footer-col-card.purple-accent {
          background: rgba(88, 28, 135, 0.15);
          border-color: rgba(147, 51, 234, 0.3);
        }
        .footer-col-title {
          font-size: 10px;
          font-weight: 800;
          letter-spacing: 0.5px;
          color: #818cf8;
          text-transform: uppercase;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .footer-col-card.purple-accent .footer-col-title {
          color: #c084fc;
        }
        .footer-link-list {
          list-style: none;
          padding: 0;
          margin: 0;
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .footer-link-list li a {
          color: #94a3b8;
          text-decoration: none;
          font-size: 10px;
          font-weight: 500;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .footer-col-card.purple-accent .footer-link-list li a {
          color: #d8b4fe;
        }
        .footer-link-list li a:hover {
          color: #ffffff;
        }

        /* Dual-Band Modular Sub-Footer */
        .footer-trust-band {
          border-top: 1px solid #1e293b;
          padding-top: 16px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          flex-wrap: wrap;
          gap: 12px;
          margin-bottom: 14px;
        }
        .upwork-trust-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: rgba(15, 23, 42, 0.9);
          border: 1px solid #334155;
          padding: 6px 12px;
          border-radius: 10px;
          color: #e2e8f0;
          font-size: 11px;
          text-decoration: none;
        }
        .star-rating {
          color: #fbbf24;
          font-weight: 800;
          display: flex;
          align-items: center;
          gap: 3px;
        }
        .social-dock {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .social-icon-btn {
          width: 28px;
          height: 28px;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border-radius: 6px;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid #334155;
          color: #94a3b8;
          text-decoration: none;
        }
        .social-icon-btn svg {
          width: 13px;
          height: 13px;
          fill: currentColor;
        }

        .footer-legal-band {
          border-top: 1px solid #1e293b;
          padding-top: 12px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-size: 10px;
          color: #64748b;
          flex-wrap: wrap;
          gap: 8px;
        }
        .footer-competency-pill {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 2px 10px;
          border-radius: 999px;
          background: rgba(15, 23, 42, 0.9);
          border: 1px solid #334155;
          color: #38bdf8;
          font-family: monospace;
          font-size: 10px;
        }
        .footer-legal-links {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .footer-legal-links a {
          color: #64748b;
          text-decoration: none;
        }
        .badge-llms {
          background: rgba(6, 182, 212, 0.15);
          color: #22d3ee;
          border: 1px solid rgba(6, 182, 212, 0.3);
          padding: 2px 6px;
          border-radius: 4px;
          font-weight: 700;
          font-size: 9px;
          display: inline-flex;
          align-items: center;
          gap: 4px;
        }
      </style>
    </head>
    <body>
      <div class="no-print">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-weight:800;font-size:14px;letter-spacing:0.5px;">WebCare Pro Security & Firewall</span>
          <span style="background:#334155;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:11px;">Printable Audit Report</span>
        </div>
        <div style="display:flex;gap:10px;">
          <button type="button" class="btn-print" onclick="window.print()">
            🖨️ Print / Save as PDF
          </button>
          <button type="button" class="btn-close" onclick="window.close()">
            ✕ Close
          </button>
        </div>
      </div>

      <div class="container">
        <!-- Report Header -->
        <div class="report-header">
          <div>
            <h1 class="brand-title">WebCare Pro Security & Firewall</h1>
            <p class="brand-subtitle">Automated Security Audit &amp; Threat Forensics Report</p>
            <div style="margin-top: 8px; font-size: 12px; color: #1e293b;">
              Target: <strong>${escapeHtml(siteName)}</strong> (<a href="${escapeHtml(siteUrl)}" style="color:#0284c7;text-decoration:none;">${escapeHtml(siteUrl)}</a>)
            </div>
          </div>
          <div class="meta-box">
            <div><strong>Audit Date:</strong> ${escapeHtml(scanDate)}</div>
            ${meta.scanId ? `<div><strong>Scan ID:</strong> #${escapeHtml(meta.scanId)}</div>` : ''}
            <div><strong>Scope:</strong> ${escapeHtml(meta.scanTarget === 'full' ? 'Full System Scan' : 'Plugins & Themes')}</div>
            ${meta.duration ? `<div><strong>Execution Time:</strong> ${escapeHtml(meta.duration)}</div>` : ''}
            <div><strong>Engine:</strong> v${escapeHtml(meta.version || '1.14.0')} (10 Engines Active)</div>
          </div>
        </div>

        <!-- Posture Summary Banner -->
        <div class="hero-banner">
          <div class="score-circle">
            <div class="score-number">${healthScore}</div>
            <div style="font-size:10px;color:#64748b;font-weight:600;">OUT OF 100</div>
            <div class="score-grade">${theme.label}</div>
          </div>
          <div>
            <div style="font-size: 13px; font-weight: 700; color: #0f172a; margin-bottom: 8px;">
              Executive Threat Summary &bull; ${issues.length} Findings Identified
            </div>
            <div class="kpi-grid">
              <div class="kpi-card" style="border-top: 3px solid #ef4444;">
                <div class="kpi-count" style="color: #ef4444;">${counts.critical}</div>
                <div class="kpi-label">Critical</div>
              </div>
              <div class="kpi-card" style="border-top: 3px solid #f97316;">
                <div class="kpi-count" style="color: #f97316;">${counts.high}</div>
                <div class="kpi-label">High</div>
              </div>
              <div class="kpi-card" style="border-top: 3px solid #f59e0b;">
                <div class="kpi-count" style="color: #f59e0b;">${counts.medium}</div>
                <div class="kpi-label">Medium</div>
              </div>
              <div class="kpi-card" style="border-top: 3px solid #10b981;">
                <div class="kpi-count" style="color: #10b981;">${counts.low + counts.info}</div>
                <div class="kpi-label">Low / Info</div>
              </div>
            </div>
            <div style="font-size: 11px; color: #64748b; margin-top: 10px;">
              Evaluated across File Integrity Monitoring (FIM), AST PHP Malheuristics, Known CVE Databases, Database Spam Injections, Scheduled Cron Hooks, and User Permissions.
            </div>
          </div>
        </div>

        ${meta.interruption ? `
          <!-- Interruption Forensics Box (When scan stopped prematurely) -->
          <div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #ef4444; border-radius: 10px; padding: 14px 18px; margin-bottom: 20px; page-break-inside: avoid;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
              <span style="background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 800; letter-spacing: 0.5px; text-transform: uppercase;">
                AUDIT PREMATURELY INTERRUPTED (${escapeHtml(meta.interruption.reason_code || 'HALT')})
              </span>
              <span style="font-size: 11px; color: #64748b; font-family: monospace;">Progress: ${escapeHtml(meta.interruption.scanned_files ?? meta.scannedFiles ?? 0)} / ${escapeHtml(meta.interruption.total_files ?? meta.totalFiles ?? 0)} files (${escapeHtml(meta.interruption.progress_percent ?? 0)}%)</span>
            </div>
            <h4 style="margin: 0 0 4px 0; font-size: 14px; font-weight: 800; color: #991b1b;">
              ${escapeHtml(meta.interruption.title || 'Scan Did Not Complete Full Filesystem Inspection')}
            </h4>
            <p style="margin: 0 0 8px 0; font-size: 11.5px; color: #475569; line-height: 1.5;">
              ${escapeHtml(meta.interruption.summary || '')}
            </p>
            ${meta.interruption.last_active_file ? `
              <div style="background: #ffffff; border: 1px solid #fee2e2; border-radius: 6px; padding: 6px 10px; font-family: monospace; font-size: 10.5px; color: #0284c7; margin-bottom: 8px; word-break: break-all;">
                <strong>Last Audited Target:</strong> ${escapeHtml(meta.interruption.last_active_file)}
              </div>
            ` : ''}
            ${meta.interruption.technical_details ? `
              <div style="font-size: 11px; color: #334155; margin-bottom: 4px;">
                <strong>Technical Diagnostics:</strong> ${escapeHtml(meta.interruption.technical_details)}
              </div>
            ` : ''}
            ${meta.interruption.remediation ? `
              <div style="font-size: 11px; color: #1e40af; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 6px 10px; margin-top: 6px;">
                <strong>SysAdmin Remediation:</strong> ${escapeHtml(meta.interruption.remediation)}
              </div>
            ` : ''}
          </div>
        ` : ''}

        <!-- System Diagnostics & Server Environment Telemetry Card -->
        <div class="telemetry-card">
          <div class="telemetry-head">
            <div class="telemetry-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
              <span>System Diagnostics &amp; Server Environment</span>
            </div>
            <span class="telemetry-badge">SysAdmin &bull; Developer Telemetry</span>
          </div>

          <div class="telemetry-grid">
            <div class="telemetry-item">
              <div class="telemetry-label">Peak RAM</div>
              <div class="telemetry-val">${escapeHtml(peakRamFmt)} <span class="telemetry-sub">/ ${escapeHtml(memoryLimitFmt)} (${escapeHtml(memoryPercentFmt)})</span></div>
            </div>
            <div class="telemetry-item">
              <div class="telemetry-label">Throughput</div>
              <div class="telemetry-val" style="color:#38bdf8;">${escapeHtml(throughputFmt)}</div>
            </div>
            <div class="telemetry-item">
              <div class="telemetry-label">CPU Load</div>
              <div class="telemetry-val">${escapeHtml(cpuLoadFmt)} ${meta.cpuCores ? `<span class="telemetry-sub">(${escapeHtml(meta.cpuCores)} Cores)</span>` : ''}</div>
            </div>
            <div class="telemetry-item">
              <div class="telemetry-label">Server Software</div>
              <div class="telemetry-val" style="font-family:monospace;font-size:11px;">${escapeHtml(serverSoftware)}</div>
            </div>
            <div class="telemetry-item">
              <div class="telemetry-label">Platform &amp; Architecture</div>
              <div class="telemetry-val">${escapeHtml(serverOs)}</div>
            </div>
            <div class="telemetry-item">
              <div class="telemetry-label">PHP &amp; Database</div>
              <div class="telemetry-val">${escapeHtml(phpEnv)} &bull; ${escapeHtml(dbEnv)}</div>
            </div>
          </div>

          <div class="telemetry-footer-bar">
            <span><strong>Active Engines:</strong> ${escapeHtml(meta.enginesActive || 10)} Core Security Engines</span>
            <span><strong>Max Execution Time:</strong> ${escapeHtml(maxExecTime)}</span>
            <span><strong>OPcache:</strong> ${escapeHtml(meta.opcacheStatus || 'Enabled')}</span>
            <span><strong>SSL / Transport:</strong> ${meta.sslActive ? 'Active (HTTPS)' : 'Inactive'}</span>
          </div>
        </div>

        <!-- Findings Table -->
        <h3 style="font-size: 15px; font-weight: 800; color: #0f172a; margin: 24px 0 6px 0;">
          Detailed Security Findings &amp; Forensic Inventory
        </h3>
        <p style="font-size: 11px; color: #64748b; margin: 0 0 12px 0;">
          Every detected vulnerability, modified file checksum mismatch, webshell signature, and outdated component identified during the audit.
        </p>

        ${issues.length === 0 ? `
          <div style="padding: 36px; text-align: center; background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 8px; color: #047857;">
            <strong>No Security Findings Detected</strong><br>
            Your WordPress installation is clean with zero flagged threats or integrity violations.
          </div>
        ` : `
          <table class="findings-table">
            <thead>
              <tr>
                <th style="width: 32px; text-align: center;">#</th>
                <th style="width: 85px;">Severity</th>
                <th style="width: 170px;">Threat / Vector</th>
                <th style="width: 250px;">Target Location</th>
                <th>Description &amp; CVE Details</th>
                <th style="width: 70px; text-align: center;">Status</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows}
            </tbody>
          </table>
        `}

        <!-- ========================================================== -->
        <!-- EXECUTIVE CYBER-GRADE FOOTER (ADAPTED FROM FOOTER.TSX)     -->
        <!-- ========================================================== -->
        <footer class="executive-footer">
          <!-- Brand & Bio Card -->
          <div class="footer-brand-card">
            <div class="footer-brand-header">
              <div class="footer-logo-group">
                <!-- SVG Shield Logo -->
                <svg width="34" height="34" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <defs>
                    <linearGradient id="webcareGlowIconPdf" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stop-color="#3b82f6" />
                      <stop offset="50%" stop-color="#06b6d4" />
                      <stop offset="100%" stop-color="#10b981" />
                    </linearGradient>
                    <linearGradient id="shieldBgIconPdf" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stop-color="#1e293b" />
                      <stop offset="100%" stop-color="#0a0f1d" />
                    </linearGradient>
                  </defs>
                  <path d="M 50 4 L 88 18 C 88 56 70 82 50 96 C 30 82 12 56 12 18 Z" fill="url(#shieldBgIconPdf)" stroke="url(#webcareGlowIconPdf)" stroke-width="4" stroke-linejoin="round"/>
                  <rect x="28" y="28" width="44" height="10" rx="2" fill="#0f172a" stroke="#38bdf8" stroke-width="1.5" />
                  <circle cx="34" cy="33" r="1.5" fill="#10b981" />
                  <circle cx="40" cy="33" r="1.5" fill="#38bdf8" />
                  <line x1="48" y1="33" x2="64" y2="33" stroke="#475569" stroke-width="1.5" stroke-linecap="round" />
                  <rect x="28" y="44" width="44" height="10" rx="2" fill="#0f172a" stroke="#3b82f6" stroke-width="1.5" />
                  <circle cx="34" cy="49" r="1.5" fill="#10b981" />
                  <circle cx="40" cy="49" r="1.5" fill="#10b981" />
                  <line x1="48" y1="49" x2="64" y2="49" stroke="#475569" stroke-width="1.5" stroke-linecap="round" />
                  <rect x="28" y="60" width="44" height="10" rx="2" fill="#0f172a" stroke="#2563eb" stroke-width="1.5" />
                  <circle cx="34" cy="65" r="1.5" fill="#10b981" />
                  <circle cx="40" cy="65" r="1.5" fill="#f59e0b" />
                  <line x1="48" y1="65" x2="64" y2="65" stroke="#475569" stroke-width="1.5" stroke-linecap="round" />
                  <path d="M 26 40 L 36 78 L 50 50 L 64 78 L 74 40" fill="none" stroke="url(#webcareGlowIconPdf)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>

                <div>
                  <div style="display:flex;align-items:center;gap:6px;">
                    <span class="footer-logo-title">WebCare</span>
                    <span class="footer-pro-badge">PRO</span>
                  </div>
                  <div style="font-size:9px;color:#64748b;letter-spacing:1px;font-weight:700;text-transform:uppercase;margin-top:2px;">
                    Speed &bull; Security &bull; Uptime
                  </div>
                </div>
              </div>

              <!-- Quick Connect Action Buttons -->
              <div class="footer-contact-buttons">
                <a href="https://wa.me/8801322691090" target="_blank" rel="noopener noreferrer" class="btn-contact btn-wa">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>
                  <span>WhatsApp</span>
                </a>

                <a href="https://teams.live.com/l/invite/FEAI60zv48mwbIKhA?v=g1" target="_blank" rel="noopener noreferrer" class="btn-contact btn-teams">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M19.5 7.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm-7-1a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zm7.25 2.5h-2.5c-.41 0-.75.34-.75.75v3.5a3.5 3.5 0 0 1-1.54 2.88 4.47 4.47 0 0 0 3.04.87c2.21 0 4-1.79 4-4v-1.5c0-1.38-1.12-2.5-2.25-2.5zm-5.75 1.5h-3c-1.38 0-2.5 1.12-2.5 2.5v4.5c0 2.21 1.79 4 4 4h3c2.21 0 4-1.79 4-4v-4.5c0-1.38-1.12-2.5-2.5-2.5zm-8.5-3a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm1.5 3.5h-1.5c-1.38 0-2.5 1.12-2.5 2.5v1.5c0 2.21 1.79 4 4 4 .85 0 1.63-.27 2.28-.73A3.48 3.48 0 0 1 6 15.5V11.5c0-.41.34-.75.75-.75h.25v-.25z" /></svg>
                  <span>MS Teams</span>
                </a>

                <a href="mailto:hello@webcarepro.dev" class="btn-contact btn-email">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                  <span>Email</span>
                </a>
              </div>
            </div>

            <!-- About Us Paragraph (Solo freelancer tone) -->
            <p class="footer-about-text">
              Mir Alamin (WebCare Pro) helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux &amp; cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—I keep your online presence fast, secure, and always available.
            </p>
          </div>

          <!-- 4-Column Granular Services Grid -->
          <div class="footer-services-grid">
            <!-- Column 1 -->
            <div class="footer-col-card">
              <div class="footer-col-title">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                <span>Server &amp; Website Care</span>
              </div>
              <ul class="footer-link-list">
                <li><a href="https://webcarepro.dev/services/expert-web-maintenance" target="_blank" rel="noopener noreferrer">Expert Web Maintenance</a></li>
                <li><a href="https://webcarepro.dev/services/website-hosting-maintenance" target="_blank" rel="noopener noreferrer">Web Hosting Management</a></li>
                <li><a href="https://webcarepro.dev/services/managed-server-administration" target="_blank" rel="noopener noreferrer">Managed Server Admin</a></li>
              </ul>
            </div>

            <!-- Column 2 -->
            <div class="footer-col-card">
              <div class="footer-col-title">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                <span>Speed, SEO &amp; Cloud</span>
              </div>
              <ul class="footer-link-list">
                <li><a href="https://webcarepro.dev/services/website-speed-optimization" target="_blank" rel="noopener noreferrer">Website Speed Optimization</a></li>
                <li><a href="https://webcarepro.dev/services/seo-website-development" target="_blank" rel="noopener noreferrer">AI Ready Web Dev</a></li>
                <li><a href="https://webcarepro.dev/services/domain-dns-setup" target="_blank" rel="noopener noreferrer">Domain &amp; Cloudflare DNS</a></li>
              </ul>
            </div>

            <!-- Column 3 -->
            <div class="footer-col-card">
              <div class="footer-col-title">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
                <span>Security &amp; Critical Repairs</span>
              </div>
              <ul class="footer-link-list">
                <li><a href="https://webcarepro.dev/services/website-hack-recovery-security" target="_blank" rel="noopener noreferrer">Hack Recovery &amp; Security</a></li>
                <li><a href="https://webcarepro.dev/services/website-server-troubleshooting" target="_blank" rel="noopener noreferrer">Troubleshooting &amp; Fixes</a></li>
                <li><a href="https://webcarepro.dev/services/website-transfer" target="_blank" rel="noopener noreferrer">Zero-Downtime Transfer</a></li>
              </ul>
            </div>

            <!-- Column 4 -->
            <div class="footer-col-card purple-accent">
              <div class="footer-col-title">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
                <span>Agency &amp; Architecture</span>
              </div>
              <ul class="footer-link-list">
                <li><a href="https://webcarepro.dev/services/white-label-agency-support" target="_blank" rel="noopener noreferrer" style="font-weight:700;">White-Label Agency Support &nearr;</a></li>
                <li><a href="https://webcarepro.dev/services" target="_blank" rel="noopener noreferrer">Dedicated Sysadmin on Demand</a></li>
                <li><a href="https://webcarepro.dev/services" target="_blank" rel="noopener noreferrer">Browse Full Services Catalog &rarr;</a></li>
                <li><a href="https://webcarepro.dev/operations-hub" target="_blank" rel="noopener noreferrer" style="color:#a855f7;">Operations Knowledge Hub &rarr;</a></li>
              </ul>
            </div>
          </div>

          <!-- Trust Band & Social Connect Dock -->
          <div class="footer-trust-band">
            <!-- Upwork Verified Client Card -->
            <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67" target="_blank" rel="noopener noreferrer" class="upwork-trust-badge">
              <span class="star-rating">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="#fbbf24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                <span>4.9/5.0</span>
              </span>
              <span style="color:#475569;">|</span>
              <span style="color:#cbd5e1;">Based on <strong style="color:#ffffff;">528 verified reviews</strong> on <span style="color:#10b981;font-weight:700;">Upwork</span> &nearr;</span>
            </a>

            <!-- Social Profiles Dock -->
            <div class="social-dock">
              <!-- LinkedIn -->
              <a href="https://www.linkedin.com/in/miralamin/" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="LinkedIn - Mir Alamin">
                <svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z M2 9h4v12H2z M4 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4z"/></svg>
              </a>
              <!-- Facebook -->
              <a href="https://facebook.com/WebCareProHQ" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="Facebook - WebCareProHQ">
                <svg viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>
              </a>
              <!-- X / Twitter -->
              <a href="https://x.com/WebCarePro" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="X (Twitter) - @WebCarePro">
                <svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              </a>
              <!-- Upwork Profile -->
              <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="Upwork Profile - Mir Alamin">
                <svg viewBox="0 0 24 24"><path d="M18.561 13.158c-1.102 0-2.135-.467-3.074-1.227l.228-1.076.008-.042c.207-1.143.849-3.06 2.839-3.06 1.492 0 2.703 1.212 2.703 2.703-.001 1.489-1.212 2.702-2.704 2.702zm0-8.14c-2.539 0-4.51 1.649-5.31 4.366-1.22-1.834-2.148-4.036-2.687-5.892H7.828v7.112c-.002 1.406-1.141 2.546-2.547 2.548-1.405-.002-2.543-1.143-2.545-2.548V3.492H0v7.112c0 2.914 2.37 5.303 5.281 5.303 2.913 0 5.283-2.389 5.283-5.303v-1.19c.529 1.107 1.182 2.229 1.974 3.221l-1.673 7.873h2.797l1.213-5.71c1.063.679 2.285 1.109 3.686 1.109 3 0 5.439-2.452 5.439-5.45 0-3-2.439-5.439-5.439-5.439z"/></svg>
              </a>
              <!-- Credly Badges -->
              <a href="https://www.credly.com/users/miralamin/badges/credly" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="Credly Badges - Mir Alamin">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="7"></circle><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"></polyline></svg>
              </a>
              <!-- WhatsApp Direct -->
              <a href="https://wa.me/8801322691090" target="_blank" rel="noopener noreferrer" class="social-icon-btn" title="WhatsApp - Mir Alamin">
                <svg viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>
              </a>
              <!-- Email Direct -->
              <a href="mailto:hello@webcarepro.dev" class="social-icon-btn" title="Direct Email - hello@webcarepro.dev">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
              </a>
            </div>
          </div>

          <!-- Legal & Operations Band -->
          <div class="footer-legal-band">
            <div>
              &copy; 2026 <strong style="color:#ffffff;">WebCare Pro</strong>. Founded in 2013. All rights reserved.
              <span style="display:block;color:#475569;margin-top:2px;">100% Remote Global Operations &bull; Worldwide Service</span>
            </div>

            <div class="footer-competency-pill">
              <span class="pulse-dot" style="background:#06b6d4;"></span>
              <span>Server, Security, Performance &amp; AI-Ready Web</span>
            </div>

            <div class="footer-legal-links">
              <a href="https://webcarepro.dev/privacy-policy" target="_blank" rel="noopener noreferrer">Privacy Policy</a>
              <span>&bull;</span>
              <a href="https://webcarepro.dev/terms-of-service" target="_blank" rel="noopener noreferrer">Terms of Service</a>
              <span>&bull;</span>
              <a href="https://webcarepro.dev/sitemap.xml" target="_blank" rel="noopener noreferrer">Sitemap</a>
              <span>&bull;</span>
              <a href="https://webcarepro.dev/llms.txt" target="_blank" rel="noopener noreferrer" class="badge-llms">
                <span>llms.txt</span>
                <span style="font-size:8px;background:rgba(6,182,212,0.3);padding:1px 3px;border-radius:2px;">AI SPEC</span>
              </a>
            </div>
          </div>
        </footer>
      </div>

      <script>
        // Automatically prompt print dialog after page renders
        window.addEventListener('load', () => {
          setTimeout(() => {
            window.print();
          }, 450);
        });
      </script>
    </body>
    </html>
  `.trim();

  const printWindow = window.open('', '_blank');
  if (printWindow) {
    printWindow.document.open();
    printWindow.document.write(printDocument);
    printWindow.document.close();
  } else {
    toast.error('Please allow popups for this site to open and print the PDF Security Audit Report.');
  }
}
