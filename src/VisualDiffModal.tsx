import { useState, useEffect, useRef } from '@wordpress/element';
import {
  FileCode,
  AlertTriangle,
  RefreshCw,
  X,
  Copy,
  Check,
  CheckCircle2,
  ExternalLink,
  RotateCcw,
  Wand2,
  Sparkles,
  Loader2,
  Shield,
  Clock,
  Lock,
  User,
  GitBranch,
  ArrowRight,
  ShieldAlert,
  ChevronDown,
  Terminal,
  FileText,
  Globe,
  Database,
} from 'lucide-react';
import AiForensicReportView from './components/AiForensicReportView';
import { ConfirmDialog } from './components/ConfirmDialog';
import { formatRelativeTime } from './timeUtils';
import { toast } from './utils/dialog';

export interface DiffLine {
  type: 'unchanged' | 'added' | 'removed';
  old_line: number | null;
  new_line: number | null;
  content: string;
}

export interface ForensicFileRecord {
  size: number;
  size_formatted: string;
  perms: string;
  owner: string;
  uid?: number;
  gid?: number;
  mtime: number;
  mtime_human: string;
  ctime: number;
  ctime_human: string;
  atime?: number;
  atime_human?: string;
  sha256: string;
  is_symlink: boolean;
  symlink_target?: string | null;
  calibrated?: boolean;
}

export interface DiffForensicMeta {
  live: ForensicFileRecord;
  baseline: ForensicFileRecord | null;
  change_types: string[];
}

export interface DiffData {
  success: boolean;
  file_path: string;
  relative_path: string;
  filename: string;
  category: string;
  is_official_compared: boolean;
  is_identical?: boolean;
  official_source_url: string | null;
  message: string;
  stats: {
    additions: number;
    deletions: number;
    total_changes: number;
    local_lines: number;
  };
  diff_lines: DiffLine[];
  forensic_meta?: DiffForensicMeta;
}

export interface VisualDiffModalProps {
  isOpen: boolean;
  filePath: string | null;
  issueId?: number | null;
  onClose: () => void;
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onRemediated?: (filePath: string, issueId?: number | null) => void;
  onAiAnalyze?: (code: string, filePath: string, threatType?: string, lineNumber?: number) => void;
}

export default function VisualDiffModal({
  isOpen,
  filePath,
  issueId,
  onClose,
  apiRequest,
  onRemediated,
  onAiAnalyze,
}: VisualDiffModalProps) {
  const [diffLoading, setDiffLoading] = useState<boolean>(false);
  const [diffData, setDiffData] = useState<DiffData | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [copiedPath, setCopiedPath] = useState<boolean>(false);
  const [remediating, setRemediating] = useState<boolean>(false);
  const [internalAiModal, setInternalAiModal] = useState<{
    isOpen: boolean;
    loading: boolean;
    error: string | null;
    analysis: string | null;
    provider: string | null;
    model: string | null;
    filePath?: string;
    threatType?: string;
  }>({
    isOpen: false,
    loading: false,
    error: null,
    analysis: null,
    provider: null,
    model: null,
  });

  useEffect(() => {
    if (isOpen && filePath) {
      loadDiff(filePath);
    } else {
      setDiffData(null);
      setDiffError(null);
      setDiffLoading(false);
    }
  }, [isOpen, filePath]);

  const loadDiff = async (targetPath: string) => {
    setDiffLoading(true);
    setDiffError(null);
    setDiffData(null);

    try {
      let res: any = null;
      try {
        // Preferred: POST payload
        res = await apiRequest({
          path: '/webcare-pro-security/v1/integrity/diff',
          method: 'POST',
          data: { file_path: targetPath },
        });
      } catch (postErr) {
        // Fallback to GET
        let encodedPath = targetPath;
        try {
          encodedPath = `b64:${btoa(unescape(encodeURIComponent(targetPath)))}`;
        } catch (e) {
          encodedPath = targetPath;
        }
        res = await apiRequest({
          path: `/webcare-pro-security/v1/integrity/diff?path=${encodeURIComponent(encodedPath)}`,
          method: 'GET',
        });
      }

      if (res && res.success) {
        setDiffData(res);
      } else {
        setDiffError(res?.message || 'Could not compute file diff.');
      }
    } catch (err: any) {
      setDiffError(err?.message || 'Error occurred fetching file diff from server.');
    } finally {
      setDiffLoading(false);
    }
  };

  const [copyDropdownOpen, setCopyDropdownOpen] = useState<boolean>(false);
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);
  const copyDropdownRef = useRef<HTMLDivElement | null>(null);

  // Close copy dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (copyDropdownRef.current && !copyDropdownRef.current.contains(e.target as Node)) {
        setCopyDropdownOpen(false);
      }
    };
    if (copyDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [copyDropdownOpen]);

  /**
   * Multi-format diff & forensic copy helper
   * Formats: 'forensic_text', 'markdown', 'html', 'csv', 'raw_patch' (normal patch diff)
   */
  const handleCopyDiffBundle = (format: 'forensic_text' | 'markdown' | 'html' | 'csv' | 'raw_patch') => {
    if (!diffData) return;

    const filename = diffData.filename || (diffData.file_path ? diffData.file_path.split(/[\\/]/).pop() : 'file') || 'file';
    const filePath = diffData.file_path || 'Unknown File';
    const relPath = diffData.relative_path || filePath;
    const categoryName = diffData.category === 'theme' ? 'WordPress Theme' : diffData.category === 'plugin' ? 'WordPress Plugin' : 'WordPress Core File';
    const reference = diffData.is_official_compared ? 'Official WordPress.org Release Baseline' : 'Local File Comparison';
    const additions = diffData.stats?.additions || 0;
    const deletions = diffData.stats?.deletions || 0;
    const totalChanges = diffData.stats?.total_changes || (additions + deletions);
    const localLines = diffData.stats?.local_lines || 0;

    const live = diffData.forensic_meta?.live;
    const base = diffData.forensic_meta?.baseline;

    const liveSha256 = live?.sha256 || 'N/A';
    const baseSha256 = base?.sha256 || 'N/A';
    const livePerms = live?.perms || 'N/A';
    const basePerms = base?.perms || 'N/A';
    const liveOwner = live?.owner || 'N/A';
    const baseOwner = base?.owner || 'N/A';
    const liveSize = live?.size_formatted || (live?.size ? `${live.size} bytes` : 'N/A');
    const liveMtime = live?.mtime_human || 'N/A';
    const liveCtime = live?.ctime_human || 'N/A';
    const liveAtime = live?.atime_human || 'N/A';

    const diffLines = diffData.diff_lines || [];
    const rawPatch = diffLines.map((l) => {
      const sign = l.type === 'added' ? '+' : l.type === 'removed' ? '-' : ' ';
      return `${sign} ${l.content}`;
    }).join('\n');

    let payload = '';

    if (format === 'raw_patch') {
      // Normal copy: standard patch / unified diff lines
      payload = `--- official/${relPath}\n+++ local/${relPath}\n@@ -1,${localLines} +1,${localLines} @@\n${rawPatch}`;
    } else if (format === 'forensic_text') {
      payload = `=== WebCare Pro Security & Firewall: FORENSIC CODE DIFF AUDIT ===
File Name:            ${filename}
Relative Path:        ${relPath}
Full System Path:     ${filePath}
Component Type:       ${categoryName}
Reference Baseline:   ${reference}
Modifications Count:  +${additions} additions, -${deletions} deletions (${totalChanges} total line changes)
Local Line Count:     ${localLines}

--- FORENSIC INODE & ATTRIBUTES AUDIT ---
Current SHA-256:      ${liveSha256}
Baseline SHA-256:     ${baseSha256}
File Permissions:     ${livePerms} (Baseline: ${basePerms})
Owner & Group:        ${liveOwner} (Baseline: ${baseOwner})
File Size:            ${liveSize}
Last Modified (mtime): ${liveMtime}
Created / Inode (ctime): ${liveCtime}
Last Accessed (atime): ${liveAtime}
Baseline Status:      ${base ? 'Calibrated Vault Baseline' : 'No Prior Snapshot'}

--- UNIFIED CODE DIFF BEGIN ---
${rawPatch}
--- UNIFIED CODE DIFF END ---
`;
    } else if (format === 'markdown') {
      payload = `# 🛡️ WebCare Pro Security & Firewall — Visual Code Diff & Forensic Audit

| Forensic Property | Live Inspection Value | Official Baseline Reference |
| :--- | :--- | :--- |
| **File Name** | \`${filename}\` | \`${filename}\` |
| **Relative Path** | \`${relPath}\` | \`${relPath}\` |
| **Full System Path** | \`${filePath}\` | \`${filePath}\` |
| **Component Type** | ${categoryName} | WordPress.org Mirror |
| **Diff Changes** | **+${additions} lines / -${deletions} lines** | 0 Changes (Baseline) |
| **SHA-256 Hash** | \`${liveSha256}\` | \`${baseSha256}\` |
| **Permissions** | \`${livePerms}\` | \`${basePerms}\` |
| **Owner & Group** | \`${liveOwner}\` | \`${baseOwner}\` |
| **File Size** | ${liveSize} | ${base?.size_formatted || 'N/A'} |
| **Last Modified (mtime)** | ${liveMtime} | ${base?.mtime_human || 'N/A'} |
| **Created Time (ctime)** | ${liveCtime} | ${base?.ctime_human || 'N/A'} |
| **Last Accessed (atime)** | ${liveAtime} | N/A |

### Unified Line-by-Line Code Diff

\`\`\`diff
--- official/${relPath}
+++ local/${relPath}
${rawPatch}
\`\`\`
`;
    } else if (format === 'html') {
      const escapeHtml = (str: string) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      const formattedDiffHtml = diffLines.map((l) => {
        const sign = l.type === 'added' ? '+' : l.type === 'removed' ? '-' : ' ';
        const bg = l.type === 'added' ? 'rgba(34, 197, 94, 0.15)' : l.type === 'removed' ? 'rgba(239, 68, 68, 0.15)' : 'transparent';
        const color = l.type === 'added' ? '#4ade80' : l.type === 'removed' ? '#f87171' : '#cbd5e1';
        return `<div style="background:${bg};color:${color};padding:2px 8px;font-family:monospace;white-space:pre-wrap;">${sign} ${escapeHtml(l.content)}</div>`;
      }).join('');

      payload = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WebCare Pro Security & Firewall - Code Diff Audit - ${escapeHtml(filename)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; line-height: 1.5; }
    h1 { color: #38bdf8; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; background: #1e293b; border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 14px; border: 1px solid #334155; text-align: left; }
    th { background: #090d16; color: #94a3b8; width: 220px; }
    code { font-family: monospace; color: #38bdf8; background: #090d16; padding: 2px 6px; border-radius: 4px; }
    .diff-box { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 12px; font-size: 12px; max-height: 700px; overflow-y: auto; }
  </style>
</head>
<body>
  <h1>🛡️ Forensic Code Diff Audit: ${escapeHtml(filename)}</h1>
  <table>
    <tr><th>File Name</th><td><code>${escapeHtml(filename)}</code></td></tr>
    <tr><th>Relative Path</th><td><code>${escapeHtml(relPath)}</code></td></tr>
    <tr><th>Full System Path</th><td><code>${escapeHtml(filePath)}</code></td></tr>
    <tr><th>Component Type</th><td>${escapeHtml(categoryName)}</td></tr>
    <tr><th>Reference Baseline</th><td>${escapeHtml(reference)}</td></tr>
    <tr><th>Diff Statistics</th><td><strong>+${additions} lines added / -${deletions} lines removed</strong> (${totalChanges} changes across ${localLines} lines)</td></tr>
    <tr><th>Live SHA-256</th><td><code>${escapeHtml(liveSha256)}</code></td></tr>
    <tr><th>Baseline SHA-256</th><td><code>${escapeHtml(baseSha256)}</code></td></tr>
    <tr><th>Permissions</th><td><code>${escapeHtml(livePerms)}</code> (Baseline: <code>${escapeHtml(basePerms)}</code>)</td></tr>
    <tr><th>Owner & Group</th><td><code>${escapeHtml(liveOwner)}</code> (Baseline: <code>${escapeHtml(baseOwner)}</code>)</td></tr>
    <tr><th>File Size</th><td>${escapeHtml(liveSize)}</td></tr>
    <tr><th>Last Modified (mtime)</th><td>${escapeHtml(liveMtime)}</td></tr>
    <tr><th>Created Time (ctime)</th><td>${escapeHtml(liveCtime)}</td></tr>
    <tr><th>Last Accessed (atime)</th><td>${escapeHtml(liveAtime)}</td></tr>
  </table>

  <h3>Unified Line-by-Line Code Diff</h3>
  <div class="diff-box">
    ${formattedDiffHtml}
  </div>
</body>
</html>`;
    } else if (format === 'csv') {
      const escapeCsv = (val: any) => `"${String(val ?? '').replace(/"/g, '""')}"`;
      payload = [
        ['Property', 'Live Value', 'Baseline Reference'].map(escapeCsv).join(','),
        ['File Name', filename, filename].map(escapeCsv).join(','),
        ['Relative Path', relPath, relPath].map(escapeCsv).join(','),
        ['Full Path', filePath, filePath].map(escapeCsv).join(','),
        ['Component Type', categoryName, 'Official WordPress.org Mirror'].map(escapeCsv).join(','),
        ['Additions', additions, 0].map(escapeCsv).join(','),
        ['Deletions', deletions, 0].map(escapeCsv).join(','),
        ['Total Line Changes', totalChanges, 0].map(escapeCsv).join(','),
        ['Local Total Lines', localLines, localLines].map(escapeCsv).join(','),
        ['SHA-256 Hash', liveSha256, baseSha256].map(escapeCsv).join(','),
        ['Permissions', livePerms, basePerms].map(escapeCsv).join(','),
        ['Owner & Group', liveOwner, baseOwner].map(escapeCsv).join(','),
        ['File Size', liveSize, base?.size_formatted || 'N/A'].map(escapeCsv).join(','),
        ['Modified Time (mtime)', liveMtime, base?.mtime_human || 'N/A'].map(escapeCsv).join(','),
        ['Created Time (ctime)', liveCtime, base?.ctime_human || 'N/A'].map(escapeCsv).join(','),
        ['Accessed Time (atime)', liveAtime, 'N/A'].map(escapeCsv).join(','),
      ].join('\n');
    }

    if (navigator.clipboard) {
      navigator.clipboard.writeText(payload);
      setCopiedFormat(format);
      setTimeout(() => setCopiedFormat(null), 2200);
      setCopyDropdownOpen(false);
    }
  };

  const handleCopy = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedPath(true);
      setTimeout(() => setCopiedPath(false), 2000);
    }
  };

  // In-App Confirm Dialog State
  const [diffConfirmDialog, setDiffConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    isLoading?: boolean;
    onConfirm?: () => void | Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
  });

  const requestDiffConfirm = ({
    title,
    message,
    targetItem,
    confirmLabel = 'Confirm Action',
    variant = 'danger',
    onConfirm,
  }: {
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    onConfirm: () => void | Promise<void>;
  }) => {
    setDiffConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setDiffConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setDiffConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setDiffConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  const handleAutoCurePlugin = async (targetFile: string) => {
    requestDiffConfirm({
      title: 'Auto-Cure Plugin File',
      message: 'Are you sure you want to restore this plugin file to its pristine official WordPress.org release? An automated safety backup will be created in your vault before updating.',
      targetItem: targetFile,
      confirmLabel: 'Restore Official Release',
      variant: 'primary',
      onConfirm: async () => {
        try {
          setRemediating(true);
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/restore-plugin',
            method: 'POST',
            data: { file_path: targetFile, issue_id: issueId },
          });
          if (res && res.success) {
            toast.success(res.message || 'File restored to official release successfully!');
            loadDiff(targetFile);
            if (onRemediated) onRemediated(targetFile, issueId);
          } else {
            toast.error(res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          toast.error(err?.message || 'Error executing auto-cure.');
        } finally {
          setRemediating(false);
        }
      },
    });
  };

  const handleAutoCureTheme = async (targetFile: string) => {
    requestDiffConfirm({
      title: 'Auto-Cure Theme File',
      message: 'Are you sure you want to restore this theme file to its official WordPress.org copy? An automated safety backup will be created before updating.',
      targetItem: targetFile,
      confirmLabel: 'Restore Official Release',
      variant: 'primary',
      onConfirm: async () => {
        try {
          setRemediating(true);
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/restore-theme',
            method: 'POST',
            data: { file_path: targetFile, issue_id: issueId },
          });
          if (res && res.success) {
            toast.success(res.message || 'Theme file restored to official release!');
            loadDiff(targetFile);
            if (onRemediated) onRemediated(targetFile, issueId);
          } else {
            toast.error(res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          toast.error(err?.message || 'Error executing auto-cure.');
        } finally {
          setRemediating(false);
        }
      },
    });
  };

  const handleAutoCureCore = async (targetFile: string) => {
    requestDiffConfirm({
      title: 'Auto-Cure WordPress Core File',
      message: 'Are you sure you want to restore this WordPress core file to its pristine official WordPress.org release? An automated safety backup will be created in your vault before updating.',
      targetItem: targetFile,
      confirmLabel: 'Restore Core File',
      variant: 'primary',
      onConfirm: async () => {
        try {
          setRemediating(true);
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/restore-core',
            method: 'POST',
            data: { file_path: targetFile, issue_id: issueId },
          });
          if (res && res.success) {
            toast.success(res.message || 'WordPress core file restored to official release successfully!');
            loadDiff(targetFile);
            if (onRemediated) onRemediated(targetFile, issueId);
          } else {
            toast.error(res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          toast.error(err?.message || 'Error executing auto-cure.');
        } finally {
          setRemediating(false);
        }
      },
    });
  };

  const handleAutoCureStrip = async (targetFile: string) => {
    requestDiffConfirm({
      title: 'Strip Injected Malware Wrapper',
      message: 'Are you sure you want to strip the prepended malware wrapper from this file? The malicious header will be removed while preserving legitimate code. An automated safety backup will be created before modification.',
      targetItem: targetFile,
      confirmLabel: 'Strip Malware Header',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setRemediating(true);
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/strip',
            method: 'POST',
            data: { file_path: targetFile, issue_id: issueId },
          });
          if (res && res.success) {
            toast.success(res.message || 'Malicious wrapper stripped successfully!');
            loadDiff(targetFile);
            if (onRemediated) onRemediated(targetFile, issueId);
          } else {
            toast.error(res?.message || 'Malware strip failed.');
          }
        } catch (err: any) {
          toast.error(err?.message || 'Error executing malware strip.');
        } finally {
          setRemediating(false);
        }
      },
    });
  };

  const handleMarkResolved = async (targetFile: string) => {
    if (issueId) {
      try {
        setRemediating(true);
        await apiRequest({
          path: `/webcare-pro-security/v1/issues/${issueId}`,
          method: 'POST',
          data: { status: 'repaired' },
        });
        toast.success('Finding marked as resolved.');
        if (onRemediated) onRemediated(targetFile, issueId);
        onClose();
      } catch (e: any) {
        toast.error(e?.message || 'Failed to update finding status.');
      } finally {
        setRemediating(false);
      }
    } else {
      onClose();
    }
  };

  const getDiffSnippetForAi = () => {
    if (!diffData) return '';
    const categoryName =
      diffData.category === 'theme'
        ? 'WordPress Theme'
        : diffData.category === 'plugin'
        ? 'WordPress Plugin'
        : 'WordPress Core File';

    if (!diffData.diff_lines || diffData.diff_lines.length === 0) {
      return `// Target File: ${diffData.file_path}\n// Component: ${categoryName}\n// Result: File content is bit-for-bit identical to official WordPress.org release (+0 lines, -0 lines).`;
    }

    const modifiedLines = diffData.diff_lines
      .filter((l) => l.type === 'added' || l.type === 'removed')
      .slice(0, 150)
      .map((l) => {
        const prefix = l.type === 'added' ? '[ADDED (+)]' : '[REMOVED (-)]';
        const lineNum = l.type === 'added' ? l.new_line : l.old_line;
        return `${prefix} (Line ${lineNum || '?'}): ${l.content}`;
      })
      .join('\n');

    return (
      `// FORENSIC CODE DIFF ANALYSIS\n` +
      `// Target File: ${diffData.file_path}\n` +
      `// Component Type: ${categoryName}\n` +
      `// Reference Baseline: ${diffData.is_official_compared ? 'Official WordPress.org Release' : 'Local File Comparison'}\n` +
      `// Modification Stats: +${diffData.stats?.additions || 0} lines added, -${diffData.stats?.deletions || 0} lines removed\n\n` +
      `EXACT DIFF MODIFICATIONS:\n` +
      modifiedLines
    );
  };

  const getThreatTypeForAi = () => {
    if (!diffData) return 'Modified File / Integrity Violation';
    if (diffData.category === 'theme') return 'modified_theme_file';
    if (diffData.category === 'plugin') return 'modified_plugin_file';
    if (diffData.category === 'core') return 'modified_core_file';
    return 'integrity_modified_file';
  };

  const handleTriggerAiAnalysis = async () => {
    if (!diffData) return;
    const snippet = getDiffSnippetForAi();
    const threatType = getThreatTypeForAi();
    const path = diffData.file_path;

    if (onAiAnalyze) {
      onAiAnalyze(snippet, path, threatType);
      return;
    }

    setInternalAiModal({
      isOpen: true,
      loading: true,
      error: null,
      analysis: null,
      provider: null,
      model: null,
      filePath: path,
      threatType: threatType,
    });

    try {
      const res: any = await apiRequest({
        path: '/ai/analyze',
        method: 'POST',
        data: {
          code: snippet,
          file_path: path,
          threat_type: threatType,
        },
      });

      if (res && res.success) {
        setInternalAiModal({
          isOpen: true,
          loading: false,
          error: null,
          analysis: res.analysis,
          provider: res.provider,
          model: res.model,
          filePath: path,
          threatType: threatType,
        });
      } else {
        setInternalAiModal((prev) => ({
          ...prev,
          loading: false,
          error: res?.error || res?.message || 'AI analysis request failed.',
        }));
      }
    } catch (err: any) {
      setInternalAiModal((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Failed to communicate with AI provider. Please verify your API key in Settings.',
      }));
    }
  };

  const isCleanBaseline = Boolean(
    diffData &&
      diffData.is_official_compared &&
      (diffData.is_identical || (diffData.stats?.additions === 0 && diffData.stats?.deletions === 0))
  );

  if (!isOpen) return null;

  return (
    <div
      className="webcare-modal-backdrop"
      style={{ zIndex: 9999999 }}
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="webcare-modal-window"
        style={{
          maxWidth: '1100px',
          width: '92vw',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          background: '#0f172a',
          borderRadius: '12px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
          overflow: 'hidden',
          border: '1px solid #334155',
        }}
      >
        {/* Modal Header */}
        <div
          className="webcare-modal-header"
          style={{
            padding: '18px 24px',
            borderBottom: '1px solid #334155',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px',
            background: '#1e293b',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0, flex: 1 }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '8px',
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <FileCode size={20} />
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <h3
                  className="webcare-file-viewer-title"
                  style={{
                    margin: 0,
                    fontSize: '17px',
                    fontWeight: 700,
                    color: '#ffffff',
                    letterSpacing: '-0.2px',
                  }}
                >
                  {diffData?.filename || (diffData?.file_path ? diffData.file_path.split(/[\\/]/).pop() : (filePath ? filePath.split(/[\\/]/).pop() : 'Visual Code Diff'))}
                </h3>
                <span
                  style={{
                    fontSize: '11px',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: 'rgba(56, 189, 248, 0.15)',
                    color: '#38bdf8',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    fontWeight: 600,
                  }}
                >
                  Visual Code Diff (FIM)
                </span>
                {diffData && (
                  <span
                    style={{
                      fontSize: '11px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      background: diffData.is_official_compared
                        ? 'rgba(34, 197, 94, 0.2)'
                        : 'rgba(148, 163, 184, 0.2)',
                      color: diffData.is_official_compared ? '#4ade80' : '#94a3b8',
                      border: `1px solid ${
                        diffData.is_official_compared ? 'rgba(34, 197, 94, 0.4)' : '#475569'
                      }`,
                    }}
                  >
                    {diffData.is_official_compared ? 'Official WP.org Baseline' : 'Local File Inspection'}
                  </span>
                )}
              </div>
              <div
                style={{
                  fontSize: '12px',
                  color: '#94a3b8',
                  fontFamily: 'monospace',
                  marginTop: '3px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {diffData ? diffData.relative_path : (filePath || 'Target File')}
              </div>
            </div>
          </div>

          {/* Header Right Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {diffData && diffData.stats && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginRight: '6px' }}>
                <span
                  style={{
                    background: 'rgba(34, 197, 94, 0.15)',
                    color: '#4ade80',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 700,
                    fontFamily: 'monospace',
                  }}
                >
                  +{diffData.stats?.additions || 0} lines
                </span>
                <span
                  style={{
                    background: 'rgba(239, 68, 68, 0.15)',
                    color: '#f87171',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 700,
                    fontFamily: 'monospace',
                  }}
                >
                  -{diffData.stats?.deletions || 0} lines
                </span>
              </div>
            )}

            {diffData && (
              <button
                type="button"
                onClick={handleTriggerAiAnalysis}
                disabled={internalAiModal.loading}
                style={{
                  background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.35), rgba(99, 102, 241, 0.25))',
                  color: '#c4b5fd',
                  border: '1px solid rgba(139, 92, 246, 0.45)',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
                title="Perform AI forensic analysis on this diff"
              >
                <Sparkles size={13} className={internalAiModal.loading ? 'webcare-spin-icon' : ''} />
                <span>{internalAiModal.loading ? 'Analyzing...' : 'AI Analyze'}</span>
              </button>
            )}

            {/* Multi-Format Copy Dropdown */}
            <div style={{ position: 'relative' }} ref={copyDropdownRef}>
              <button
                type="button"
                onClick={() => setCopyDropdownOpen((prev) => !prev)}
                style={{
                  background: copiedFormat ? '#059669' : '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'background 0.15s ease',
                  boxShadow: '0 2px 8px rgba(2, 132, 199, 0.35)',
                }}
                title="Export or copy unified code diff & forensic metadata"
              >
                {copiedFormat ? <Check size={13} color="#ffffff" /> : <Copy size={13} />}
                <span>
                  {copiedFormat === 'forensic_text'
                    ? 'Report Copied!'
                    : copiedFormat === 'markdown'
                    ? 'Markdown Copied!'
                    : copiedFormat === 'html'
                    ? 'HTML Copied!'
                    : copiedFormat === 'csv'
                    ? 'CSV Copied!'
                    : copiedFormat === 'raw_patch'
                    ? 'Patch Copied!'
                    : 'Copy Diff...'}
                </span>
                <ChevronDown size={13} style={{ opacity: 0.8 }} />
              </button>

              {copyDropdownOpen && (
                <div
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 6px)',
                    right: 0,
                    zIndex: 10000010,
                    background: '#090d16',
                    border: '1px solid rgba(255, 255, 255, 0.15)',
                    borderRadius: '8px',
                    padding: '6px',
                    minWidth: '270px',
                    boxShadow: '0 12px 30px rgba(0, 0, 0, 0.65)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                    animation: 'webcareModalIn 0.15s ease-out',
                  }}
                >
                  <div
                    style={{
                      fontSize: '10.5px',
                      fontWeight: 800,
                      textTransform: 'uppercase',
                      color: '#94a3b8',
                      padding: '6px 10px 4px 10px',
                      letterSpacing: '0.5px',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                    }}
                  >
                    Copy Diff &amp; Forensics
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopyDiffBundle('forensic_text')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      color: '#f8fafc',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Terminal size={14} color="#38bdf8" />
                      <span>Forensic Report (Text + Diff)</span>
                    </span>
                    <span style={{ fontSize: '10.5px', color: '#38bdf8' }}>TXT</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleCopyDiffBundle('markdown')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      color: '#f8fafc',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <FileText size={14} color="#c084fc" />
                      <span>Markdown Copy (GitHub Table + Diff)</span>
                    </span>
                    <span style={{ fontSize: '10.5px', color: '#c084fc' }}>.MD</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleCopyDiffBundle('html')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      color: '#f8fafc',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Globe size={14} color="#f472b6" />
                      <span>HTML Copy (Styled Standalone Doc)</span>
                    </span>
                    <span style={{ fontSize: '10.5px', color: '#f472b6' }}>HTML</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleCopyDiffBundle('csv')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      color: '#f8fafc',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Database size={14} color="#34d399" />
                      <span>CSV Style Copy (Spreadsheet Export)</span>
                    </span>
                    <span style={{ fontSize: '10.5px', color: '#34d399' }}>CSV</span>
                  </button>

                  <div style={{ height: '1px', background: 'rgba(255, 255, 255, 0.08)', margin: '4px 0' }} />

                  <button
                    type="button"
                    onClick={() => handleCopyDiffBundle('raw_patch')}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'transparent',
                      border: 'none',
                      color: '#cbd5e1',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <FileCode size={14} color="#94a3b8" />
                      <span>Normal Copy (Raw Patch Only)</span>
                    </span>
                    <span style={{ fontSize: '10.5px', color: '#64748b' }}>Patch</span>
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => (diffData ? handleCopy(diffData.file_path) : filePath && handleCopy(filePath))}
              style={{
                background: '#334155',
                color: '#f8fafc',
                border: '1px solid #475569',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title="Copy absolute file path"
            >
              {copiedPath ? <Check size={13} color="#4ade80" /> : <Copy size={13} />}
              <span>{copiedPath ? 'Copied' : 'Copy Path'}</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'transparent',
                color: '#94a3b8',
                border: 'none',
                padding: '6px',
                borderRadius: '6px',
                cursor: 'pointer',
              }}
              title="Close Modal"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Modal Body / Diff Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '0', background: '#0b1120' }}>
          {diffLoading ? (
            <div style={{ padding: '80px 20px', textAlign: 'center', color: '#94a3b8' }}>
              <RefreshCw
                size={36}
                className="webcare-spin-icon"
                style={{ margin: '0 auto 14px auto', color: '#38bdf8' }}
              />
              <div style={{ fontSize: '15px', color: '#f8fafc' }}>
                Fetching official repository baseline and computing line diffs...
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
                Comparing against WordPress.org release mirrors
              </div>
            </div>
          ) : diffError ? (
            <div style={{ padding: '40px', textAlign: 'center' }}>
              <AlertTriangle size={42} color="#f87171" style={{ margin: '0 auto 12px auto' }} />
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                Diff Calculation Error
              </div>
              <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '6px' }}>{diffError}</div>
            </div>
          ) : diffData ? (
            <div>
              {/* Diff Info Bar */}
              <div
                style={{
                  padding: '10px 20px',
                  background: 'rgba(30, 41, 59, 0.6)',
                  borderBottom: '1px solid #1e293b',
                  fontSize: '12px',
                  color: '#94a3b8',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '8px',
                }}
              >
                <span>{diffData.message}</span>
                {diffData.official_source_url && (
                  <a
                    href={diffData.official_source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: '#38bdf8',
                      textDecoration: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    Official Reference Source <ExternalLink size={11} />
                  </a>
                )}
              </div>

              {/* Forensic Filesystem Deep-Dive Panel (ctime, mtime, perms, owner, symlink) */}
              {diffData.forensic_meta && (
                <div
                  style={{
                    margin: '14px 20px 6px 20px',
                    padding: '14px 18px',
                    background: 'rgba(15, 23, 42, 0.85)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '10px',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.25)',
                  }}
                >
                  {/* Forensic Header Bar */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '12px',
                      paddingBottom: '10px',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
                      flexWrap: 'wrap',
                      gap: '8px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Shield size={16} color="#38bdf8" />
                      <strong style={{ fontSize: '13px', color: '#f8fafc', letterSpacing: '0.2px' }}>
                        Forensic Inode & Filesystem Audit
                      </strong>
                      {diffData.forensic_meta.baseline ? (
                        <span className="webcare-smart-shield-pill-detected-emerald">
                          Vault Baseline Calibrated
                        </span>
                      ) : (
                        <span className="webcare-smart-shield-pill-empty">
                          No Vault Baseline Snapshot
                        </span>
                      )}
                    </div>

                    {/* Change Type Indicators */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                      {diffData.forensic_meta.change_types.length === 0 ? (
                        <span
                          className="webcare-badge-pill webcare-badge-clean"
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                          }}
                        >
                          ✓ No Inode / Permission Drift
                        </span>
                      ) : (
                        diffData.forensic_meta.change_types.map((type) => {
                          const labels: Record<string, { label: string; bg: string; color: string; border: string }> = {
                            code_modified: { label: 'Code Content Altered', bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.4)' },
                            permissions_drift: { label: 'Permissions Altered', bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.4)' },
                            owner_drift: { label: 'Owner / Group Drift', bg: 'rgba(192, 132, 252, 0.15)', color: '#c084fc', border: 'rgba(192, 132, 252, 0.4)' },
                            ctime_changed: { label: 'Inode Attribute Change (ctime)', bg: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: 'rgba(56, 189, 248, 0.4)' },
                            mtime_changed: { label: 'Modification Timestamp (mtime)', bg: 'rgba(148, 163, 184, 0.15)', color: '#cbd5e1', border: 'rgba(148, 163, 184, 0.3)' },
                            symlink_created: { label: 'Symlink Injected', bg: 'rgba(239, 68, 68, 0.25)', color: '#f87171', border: '#ef4444' },
                          };
                          const meta = labels[type] || { label: type, bg: 'rgba(255,255,255,0.1)', color: '#fff', border: 'rgba(255,255,255,0.2)' };
                          return (
                            <span
                              key={type}
                              style={{
                                fontSize: '11px',
                                fontWeight: 600,
                                padding: '2px 8px',
                                borderRadius: '4px',
                                background: meta.bg,
                                color: meta.color,
                                border: `1px solid ${meta.border}`,
                              }}
                            >
                              {meta.label}
                            </span>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* 4-Box Forensic Metrics Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px' }}>
                    {/* Box 1: Permissions */}
                    <div
                      style={{
                        background: 'rgba(30, 41, 59, 0.55)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#94a3b8', marginBottom: '6px' }}>
                        <Lock size={12} color="#38bdf8" />
                        <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>File Permissions</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <code
                          style={{
                            fontSize: '13px',
                            fontWeight: 700,
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: diffData.forensic_meta.live.perms === '0777' ? 'var(--webcare-status-critical-soft, rgba(239, 68, 68, 0.2))' : 'var(--webcare-status-clean-soft, rgba(16, 185, 129, 0.15))',
                            color: diffData.forensic_meta.live.perms === '0777' ? 'var(--webcare-status-critical, #f87171)' : 'var(--webcare-status-clean, #059669)',
                            border: `1px solid ${diffData.forensic_meta.live.perms === '0777' ? 'var(--webcare-status-critical-border, rgba(239, 68, 68, 0.4))' : 'var(--webcare-status-clean-border, rgba(16, 185, 129, 0.3))'}`,
                            fontFamily: 'monospace',
                          }}
                        >
                          {diffData.forensic_meta.live.perms}
                        </code>
                        {diffData.forensic_meta.baseline && (
                          <span style={{ fontSize: '11px', color: '#94a3b8', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <ArrowRight size={10} color="#64748b" />
                            Baseline: <strong style={{ color: '#cbd5e1' }}>{diffData.forensic_meta.baseline.perms}</strong>
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Box 2: Owner & Group */}
                    <div
                      style={{
                        background: 'rgba(30, 41, 59, 0.55)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#94a3b8', marginBottom: '6px' }}>
                        <User size={12} color="#c084fc" />
                        <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Owner & Group</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <code
                          style={{
                            fontSize: '12px',
                            fontWeight: 600,
                            color: '#e2e8f0',
                            fontFamily: 'monospace',
                            padding: '2px 6px',
                            background: 'rgba(0,0,0,0.25)',
                            borderRadius: '4px',
                          }}
                        >
                          {diffData.forensic_meta.live.owner}
                        </code>
                        {diffData.forensic_meta.baseline && diffData.forensic_meta.baseline.owner !== diffData.forensic_meta.live.owner && (
                          <span style={{ fontSize: '11px', color: '#f59e0b', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <ArrowRight size={10} />
                            Was: {diffData.forensic_meta.baseline.owner}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Box 3: Last Modified (mtime) */}
                    <div
                      style={{
                        background: 'rgba(30, 41, 59, 0.55)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#94a3b8', marginBottom: '4px' }}>
                        <Clock size={12} color="#34d399" />
                        <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Content Modified (mtime)</span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#f1f5f9', fontWeight: 600 }}>
                        {diffData.forensic_meta.live.mtime_human}
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                        {formatRelativeTime(diffData.forensic_meta.live.mtime_human)}
                        {diffData.forensic_meta.baseline && (
                          <span> • Calibrated: {diffData.forensic_meta.baseline.mtime_human}</span>
                        )}
                      </div>
                    </div>

                    {/* Box 4: Inode Change Time (ctime) */}
                    <div
                      style={{
                        background: 'rgba(30, 41, 59, 0.55)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#94a3b8', marginBottom: '4px' }}>
                        <GitBranch size={12} color="#fb923c" />
                        <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Inode Attribute (ctime)</span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#f1f5f9', fontWeight: 600 }}>
                        {diffData.forensic_meta.live.ctime_human}
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                        {formatRelativeTime(diffData.forensic_meta.live.ctime_human)}
                        {diffData.forensic_meta.live.is_symlink && (
                          <span style={{ color: '#ef4444', fontWeight: 700 }}>
                            {' '}• SYMLINK: {diffData.forensic_meta.live.symlink_target || 'Active'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic SHA-256 Footprint Row */}
                  <div
                    style={{
                      marginTop: '10px',
                      paddingTop: '8px',
                      borderTop: '1px solid rgba(255, 255, 255, 0.05)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '11px',
                      color: '#94a3b8',
                      flexWrap: 'wrap',
                      gap: '8px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ color: '#64748b' }}>SHA-256:</span>
                      <code style={{ fontFamily: 'monospace', color: '#38bdf8', fontSize: '11px' }}>
                        {diffData.forensic_meta.live.sha256}
                      </code>
                    </div>
                    {diffData.forensic_meta.baseline && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ color: '#64748b' }}>Baseline Hash:</span>
                        <code
                          style={{
                            fontFamily: 'monospace',
                            fontSize: '11px',
                            color: diffData.forensic_meta.baseline.sha256 === diffData.forensic_meta.live.sha256 ? 'var(--webcare-status-clean, #059669)' : 'var(--webcare-status-critical, #f87171)',
                          }}
                        >
                          {diffData.forensic_meta.baseline.sha256 === diffData.forensic_meta.live.sha256
                            ? 'Matches Sealed Vault (Pristine)'
                            : diffData.forensic_meta.baseline.sha256}
                        </code>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Clean Baseline Advisory Banner */}
              {isCleanBaseline && (
                <div
                  style={{
                    margin: '16px 20px',
                    padding: '14px 18px',
                    background: 'rgba(34, 197, 94, 0.12)',
                    border: '1px solid rgba(34, 197, 94, 0.35)',
                    borderRadius: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '12px',
                    flexWrap: 'wrap',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <CheckCircle2 size={24} color="#4ade80" style={{ flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#4ade80' }}>
                        File Content Matches Official Baseline (0 Modifications)
                      </div>
                      <div style={{ fontSize: '12.5px', color: '#cbd5e1', marginTop: '2px', lineHeight: 1.5 }}>
                        Every line of code in this server file is 100% identical to the official WordPress.org release (+0 lines, -0 lines). No malicious edits or tampering detected.
                      </div>
                    </div>
                  </div>
                  {issueId && (
                    <button
                      type="button"
                      className="webcare-btn"
                      disabled={remediating}
                      style={{
                        background: '#22c55e',
                        color: '#ffffff',
                        border: 'none',
                        padding: '7px 16px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 700,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        cursor: 'pointer',
                      }}
                      onClick={() => handleMarkResolved(diffData.file_path)}
                    >
                      <Check size={14} /> Dismiss &amp; Mark as Resolved
                    </button>
                  )}
                </div>
              )}

              {/* Diff Lines Viewport */}
              <div
                style={{
                  fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace',
                  fontSize: '12.5px',
                  lineHeight: '1.6',
                }}
              >
                {(!diffData.diff_lines || diffData.diff_lines.length === 0) ? (
                  <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                    No differences detected. File is bit-for-bit identical to official reference.
                  </div>
                ) : (
                  (diffData.diff_lines || []).map((line, idx) => {
                    let lineBg = 'transparent';
                    let lineNumColor = '#475569';
                    let textPrefix = ' ';
                    let textColor = '#cbd5e1';

                    if (line.type === 'added') {
                      lineBg = 'rgba(34, 197, 94, 0.12)';
                      lineNumColor = '#22c55e';
                      textPrefix = '+';
                      textColor = '#86efac';
                    } else if (line.type === 'removed') {
                      lineBg = 'rgba(239, 68, 68, 0.15)';
                      lineNumColor = '#ef4444';
                      textPrefix = '-';
                      textColor = '#fca5a5';
                    }

                    return (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          background: lineBg,
                          borderLeft:
                            line.type === 'added'
                              ? '3px solid #22c55e'
                              : line.type === 'removed'
                              ? '3px solid #ef4444'
                              : '3px solid transparent',
                        }}
                      >
                        {/* Old Line Number */}
                        <span
                          style={{
                            width: '48px',
                            paddingRight: '8px',
                            textAlign: 'right',
                            color: lineNumColor,
                            userSelect: 'none',
                            flexShrink: 0,
                            opacity: 0.6,
                          }}
                        >
                          {line.old_line || ''}
                        </span>

                        {/* New Line Number */}
                        <span
                          style={{
                            width: '48px',
                            paddingRight: '12px',
                            textAlign: 'right',
                            color: lineNumColor,
                            userSelect: 'none',
                            flexShrink: 0,
                            opacity: 0.8,
                          }}
                        >
                          {line.new_line || ''}
                        </span>

                        {/* Prefix (+ / - / space) */}
                        <span
                          style={{
                            width: '18px',
                            textAlign: 'center',
                            color: lineNumColor,
                            fontWeight: 700,
                            userSelect: 'none',
                            flexShrink: 0,
                          }}
                        >
                          {textPrefix}
                        </span>

                        {/* Content */}
                        <span
                          style={{
                            flex: 1,
                            color: textColor,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            paddingRight: '14px',
                          }}
                        >
                          {line.content}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ) : null}
        </div>

        {/* Modal Footer with One-Click Auto-Cure Actions */}
        <div
          style={{
            padding: '14px 24px',
            borderTop: '1px solid #334155',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px',
            background: '#1e293b',
          }}
        >
          {/* Left Action Buttons (Auto-Cure) */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {isCleanBaseline ? (
              <button
                type="button"
                className="webcare-btn"
                disabled={remediating}
                onClick={() => handleMarkResolved(diffData.file_path)}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 16px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Check size={14} />
                {remediating ? 'Resolving...' : (issueId ? 'Verified Clean: Mark as Resolved' : 'File is Clean & Identical')}
              </button>
            ) : null}

            {!isCleanBaseline && diffData && diffData.is_official_compared && diffData.category === 'plugin' && (
              <button
                type="button"
                className="webcare-btn"
                disabled={remediating}
                onClick={() => handleAutoCurePlugin(diffData.file_path)}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <RotateCcw size={14} className={remediating ? 'webcare-spin-icon' : ''} />
                {remediating ? 'Restoring...' : 'Auto-Cure: Restore Official WP.org Release'}
              </button>
            )}

            {!isCleanBaseline && diffData && diffData.is_official_compared && diffData.category === 'theme' && (
              <button
                type="button"
                className="webcare-btn"
                disabled={remediating}
                onClick={() => handleAutoCureTheme(diffData.file_path)}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <RotateCcw size={14} className={remediating ? 'webcare-spin-icon' : ''} />
                {remediating ? 'Restoring...' : 'Auto-Cure: Restore Official WP.org Theme'}
              </button>
            )}

            {!isCleanBaseline && diffData && diffData.is_official_compared && diffData.category === 'core' && !diffData.file_path.endsWith('wp-config.php') && (
              <button
                type="button"
                className="webcare-btn"
                disabled={remediating}
                onClick={() => handleAutoCureCore(diffData.file_path)}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <RotateCcw size={14} className={remediating ? 'webcare-spin-icon' : ''} />
                {remediating ? 'Restoring...' : 'Auto-Cure: Restore Official WP.org Core File'}
              </button>
            )}

            {diffData && diffData.stats.additions > 0 && (
              <button
                type="button"
                className="webcare-btn"
                disabled={remediating}
                onClick={() => handleAutoCureStrip(diffData.file_path)}
                style={{
                  background: '#9333ea',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Wand2 size={14} className={remediating ? 'webcare-spin-icon' : ''} />
                {remediating ? 'Stripping...' : 'Auto-Cure: Strip Injected Malware'}
              </button>
            )}

            {diffData && (
              <button
                type="button"
                className="webcare-btn"
                disabled={internalAiModal.loading}
                onClick={handleTriggerAiAnalysis}
                style={{
                  background: 'linear-gradient(135deg, #7c3aed 0%, #6366f1 100%)',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 16px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: '0 2px 8px rgba(124, 58, 237, 0.35)',
                }}
                title="Perform forensic code analysis with AI on these diff modifications"
              >
                <Sparkles size={14} className={internalAiModal.loading ? 'webcare-spin-icon' : ''} />
                {internalAiModal.loading ? 'AI Analyzing...' : 'AI Analyze Diff'}
              </button>
            )}
          </div>

          {/* Right: Close Button */}
          <button
            type="button"
            className="webcare-btn"
            onClick={onClose}
            style={{
              background: '#334155',
              color: '#ffffff',
              border: '1px solid #475569',
              padding: '7px 16px',
              borderRadius: '6px',
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            Close Diff Viewer
          </button>
        </div>
      </div>

      {/* Embedded AI Forensic Analysis Modal Overlay */}
      {internalAiModal.isOpen && (
        <div
          className="webcare-modal-backdrop"
          style={{ zIndex: 10000005 }}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setInternalAiModal((prev) => ({ ...prev, isOpen: false }));
            }
          }}
        >
          <div className="webcare-modal-window webcare-modal-window-light" style={{ maxWidth: '850px', maxHeight: '90vh', overflowY: 'auto' }}>
            <div className="webcare-post-modal-header" style={{ borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
                <div className="webcare-modal-icon-badge" style={{ background: 'linear-gradient(135deg, #7c3aed, #6366f1)', padding: '8px', borderRadius: '8px', display: 'flex' }}>
                  <Sparkles size={22} color="#ffffff" />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                      AI Threat &amp; Forensic Code Analysis
                    </h3>
                    <span className="webcare-badge" style={{ background: '#f5f3ff', color: '#7c3aed', border: '1px solid #ddd6fe' }}>
                      {internalAiModal.provider ? `${internalAiModal.provider.toUpperCase()} (${internalAiModal.model})` : 'AI Engine'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', fontFamily: 'monospace' }}>
                    Target: {internalAiModal.filePath} &bull; Vector: {internalAiModal.threatType}
                  </div>
                </div>
              </div>

              <button
                type="button"
                className="webcare-modal-close-btn-light"
                onClick={() => setInternalAiModal((prev) => ({ ...prev, isOpen: false }))}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: '6px' }}
              >
                <X size={20} color="#64748b" />
              </button>
            </div>

            <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
              {internalAiModal.loading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 20px', gap: '14px', color: '#64748b' }}>
                  <Loader2 size={38} className="webcare-spin-icon" color="#7c3aed" />
                  <div style={{ fontSize: '16px', fontWeight: 600, color: '#1e293b' }}>
                    AI Cyber Forensic Engine Analyzing Diff Modifications...
                  </div>
                  <p style={{ margin: 0, fontSize: '13px', color: '#64748b', textAlign: 'center', maxWidth: '420px' }}>
                    Evaluating modified lines against official baseline, detecting malicious payloads or benign build discrepancies.
                  </p>
                </div>
              )}

              {!internalAiModal.loading && internalAiModal.error && (
                <div style={{ padding: '30px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '10px', textAlign: 'center' }}>
                  <AlertTriangle size={36} color="#ef4444" style={{ margin: '0 auto 12px auto' }} />
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '16px', color: '#991b1b' }}>AI Analysis Unavailable</h4>
                  <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#7f1d1d', maxWidth: '520px', marginInline: 'auto' }}>
                    {internalAiModal.error}
                  </p>
                </div>
              )}

              {!internalAiModal.loading && !internalAiModal.error && internalAiModal.analysis && (
                <AiForensicReportView
                  analysis={internalAiModal.analysis}
                  provider={internalAiModal.provider}
                  model={internalAiModal.model}
                  filePath={internalAiModal.filePath}
                  threatType={internalAiModal.threatType}
                />
              )}
            </div>

            <div style={{ background: 'var(--webcare-bg-elevated, #f8fafc)', padding: '14px 24px', borderTop: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                💡 You can change AI provider &amp; models anytime in <strong>Settings &amp; Automation</strong>.
              </div>
              <button
                type="button"
                className="webcare-btn"
                style={{ background: 'var(--webcare-border, #e2e8f0)', color: 'var(--webcare-text-primary, #334155)', padding: '6px 16px', fontSize: '13px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                onClick={() => setInternalAiModal((prev) => ({ ...prev, isOpen: false }))}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={diffConfirmDialog.isOpen}
        title={diffConfirmDialog.title}
        message={diffConfirmDialog.message}
        targetItem={diffConfirmDialog.targetItem}
        confirmLabel={diffConfirmDialog.confirmLabel}
        variant={diffConfirmDialog.variant}
        isLoading={diffConfirmDialog.isLoading}
        onConfirm={diffConfirmDialog.onConfirm || (() => {})}
        onClose={() => setDiffConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
}
