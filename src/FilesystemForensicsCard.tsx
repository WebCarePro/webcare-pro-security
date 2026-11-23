import { Fragment, useState } from '@wordpress/element';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  Calendar,
  Eye,
  HardDrive,
  Lock,
  Unlock,
  CheckCircle2,
  AlertTriangle,
  Folder,
  FileText,
  Copy,
  Check,
  Terminal,
  RotateCcw,
  Sparkles,
  Server,
  User,
  Users,
  Archive,
  Trash2,
  Info,
} from 'lucide-react';
import { IssueData } from './App';

interface FilesystemForensicsCardProps {
  issue: IssueData;
  onFixPermissions: (issue: IssueData, targetPerm?: string) => Promise<void> | void;
  onOpenFileViewer?: (issue: IssueData) => void;
  onQuarantine?: (issue: IssueData) => Promise<void> | void;
  onDeleteFile?: (issue: IssueData) => Promise<void> | void;
  onAutoCure?: (issue: IssueData) => Promise<void> | void;
  onDisableWpDebug?: (issue: IssueData) => Promise<void> | void;
  remediating?: boolean;
}

export const FilesystemForensicsCard = ({
  issue,
  onFixPermissions,
  onOpenFileViewer,
  onQuarantine,
  onDeleteFile,
  onAutoCure,
  onDisableWpDebug,
  remediating = false,
}: FilesystemForensicsCardProps) => {
  const fs = issue.fs_forensics || {};
  const isRepaired = issue.status === 'repaired';
  const isDir = Boolean(fs.is_dir || issue.is_dir || (issue.file_path && issue.file_path.endsWith('/')));
  const isWpConfig = Boolean(issue.file_path && /(?:^|[\\/])wp-config\.php$/i.test(issue.file_path));
  const isHtaccess = Boolean(issue.file_path && /(?:^|[\\/])\.htaccess$/i.test(issue.file_path));
  
  const currentPerms = fs.current_permissions || (issue.description?.match(/0\d{3}/)?.[0] || '0777');
  const symbolicPerms = fs.symbolic_permissions || (currentPerms === '0777' ? '-rwxrwxrwx' : (currentPerms === '0600' ? '-rw-------' : '-rw-r--r--'));
  const recommendedPerms = fs.recommended_perms || (isWpConfig ? '0600' : (isDir ? '0755' : '0644'));
  const recommendedSymbolic = fs.recommended_symbolic || (isWpConfig ? '-rw-------' : (isDir ? 'drwxr-xr-x' : '-rw-r--r--'));

  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [selectedPerm, setSelectedPerm] = useState<string>(isWpConfig ? '0600' : (isDir ? '0755' : '0644'));

  const isHardenedConfig = (isWpConfig || isHtaccess) && ['0600', '0640', '0400', '0440'].includes(currentPerms);
  const isStandardClean = !isDir && !isWpConfig && !isHtaccess && ['0644', '0640', '0600', '0444', '0400'].includes(currentPerms);
  const isDirectoryClean = isDir && ['0755', '0750', '0700'].includes(currentPerms);
  const isOptimalSecurity = isHardenedConfig || isStandardClean || isDirectoryClean;
  
  const createdTime = fs.created_time || 'N/A';
  const createdHuman = fs.created_time_human || '';
  const modifiedTime = fs.modified_time || 'N/A';
  const modifiedHuman = fs.modified_time_human || '';
  const accessedTime = fs.accessed_time || 'N/A';
  const accessedHuman = fs.accessed_time_human || '';
  const fileSize = fs.file_size_formatted || (fs.file_size != null ? `${fs.file_size} B` : 'Unknown');
  const fileSizeBytes = fs.file_size != null ? `${Number(fs.file_size).toLocaleString()} bytes` : '';
  const owner = fs.owner ? `${fs.owner} (UID: ${fs.owner_uid ?? '?'})` : (fs.owner_uid != null ? `UID: ${fs.owner_uid}` : 'www-data');
  const group = fs.group ? `${fs.group} (GID: ${fs.group_gid ?? '?'})` : (fs.group_gid != null ? `GID: ${fs.group_gid}` : 'www-data');
  const parentDir = fs.parent_dir || (issue.file_path ? issue.file_path.substring(0, issue.file_path.lastIndexOf('/')) : 'N/A');
  const parentPerms = fs.parent_perms || '0755';
  const mimeType = fs.mime_type || 'text/x-php';
  const isWorldWritable = currentPerms === '0777' || currentPerms.endsWith('7') || currentPerms.endsWith('6');

  const handleCopy = (text: string, label: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedField(label);
      setTimeout(() => setCopiedField(null), 2000);
    }
  };

  const isPermissionIssue = issue.type === 'unsafe_permissions';
  const isQuarantined = issue.status === 'quarantined';
  const filePath = issue.file_path || '';
  const isCorePath = Boolean((filePath.includes('/wp-admin/') || filePath.includes('/wp-includes/') || issue.type?.includes('core')) && !filePath.endsWith('wp-config.php') && !filePath.endsWith('.htaccess'));
  const isPluginPath = Boolean(filePath.includes('/plugins/'));
  const isThemePath = Boolean(filePath.includes('/themes/') || issue.type?.includes('theme'));

  // Informational advisory for unmanaged/premium/custom plugins that have no WordPress.org checksums available
  const isChecksumsUnavailable = issue.type === 'plugin_checksums_unavailable' ||
    issue.type === 'theme_checksums_unavailable' ||
    issue.type === 'core_checksums_unavailable' ||
    (issue.severity === 'info' && Boolean(issue.description?.toLowerCase().includes('checksums unavailable')));

  const isModifiedFile = !isPermissionIssue && !isChecksumsUnavailable && (isCorePath || isPluginPath || isThemePath) && (
    Boolean(issue.type?.includes('modified')) ||
    Boolean(issue.type?.includes('missing_core_file')) ||
    Boolean(issue.description?.toLowerCase().includes('modified')) ||
    Boolean(issue.description?.toLowerCase().includes('checksum mismatch')) ||
    Boolean(issue.description?.toLowerCase().includes('mismatch'))
  ) && !issue.type?.includes('unknown') && !issue.type?.includes('unrecognized');

  const isUnknownOrRogue = !isPermissionIssue && !isModifiedFile && !isChecksumsUnavailable && (
    Boolean(issue.type?.includes('unknown')) ||
    Boolean(issue.type?.includes('unrecognized')) ||
    Boolean(issue.type?.includes('malware')) ||
    Boolean(issue.type?.includes('webshell')) ||
    Boolean(issue.type?.includes('backdoor')) ||
    Boolean(issue.type?.includes('suspicious')) ||
    issue.engine === 'malware-signatures' ||
    issue.engine === 'heuristics'
  );

  const cardBorder = (isRepaired || isQuarantined || isHardenedConfig)
    ? '1px solid #86efac'
    : isModifiedFile
    ? '1px solid #fde68a'
    : isUnknownOrRogue
    ? '1px solid #fecaca'
    : isStandardClean || isDirectoryClean
    ? '1px solid #e2e8f0'
    : isWorldWritable
    ? '1px solid #fca5a5'
    : '1px solid #fde68a';

  return (
    <div className="webcare-filesystem-card" style={{ border: cardBorder }}>
      {/* Top Header & Fast Fix Action */}
      <div className="webcare-filesystem-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              width: '38px',
              height: '38px',
              borderRadius: '8px',
              background: (isRepaired || isQuarantined || isHardenedConfig)
                ? 'rgba(16, 185, 129, 0.15)'
                : isModifiedFile
                ? 'rgba(245, 158, 11, 0.15)'
                : isUnknownOrRogue
                ? 'rgba(239, 68, 68, 0.15)'
                : isOptimalSecurity
                ? 'rgba(56, 189, 248, 0.15)'
                : 'rgba(239, 68, 68, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: (isRepaired || isQuarantined || isHardenedConfig)
                ? '1px solid rgba(16, 185, 129, 0.35)'
                : isModifiedFile
                ? '1px solid rgba(245, 158, 11, 0.35)'
                : isUnknownOrRogue
                ? '1px solid rgba(239, 68, 68, 0.35)'
                : isOptimalSecurity
                ? '1px solid rgba(56, 189, 248, 0.35)'
                : '1px solid rgba(239, 68, 68, 0.35)',
            }}
          >
            {(isRepaired || isQuarantined || isHardenedConfig) ? (
              <ShieldCheck size={20} color="#10b981" />
            ) : isModifiedFile ? (
              <AlertTriangle size={20} color="#f59e0b" />
            ) : issue.type === 'wp_debug_enabled' ? (
              <AlertTriangle size={20} color="#f59e0b" />
            ) : isUnknownOrRogue ? (
              <ShieldAlert size={20} color="#ef4444" />
            ) : isOptimalSecurity ? (
              <CheckCircle2 size={20} color="#38bdf8" />
            ) : (
              <ShieldAlert size={20} color="#f87171" />
            )}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className="webcare-filesystem-title">
                {isModifiedFile
                  ? 'Filesystem Forensics & Integrity Auto-Cure'
                  : isUnknownOrRogue
                  ? 'Filesystem Forensics & Rogue File Containment'
                  : isChecksumsUnavailable
                  ? 'Filesystem Forensics & Proprietary Plugin Advisory'
                  : 'Filesystem Permissions & Security Forensics'}
              </span>

              {isQuarantined ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#ecfdf5',
                    color: '#047857',
                    border: '1px solid #a7f3d0',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <Archive size={12} color="#10b981" /> Quarantined in Vault
                </span>
              ) : isRepaired ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#ecfdf5',
                    color: '#047857',
                    border: '1px solid #a7f3d0',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <CheckCircle2 size={12} color="#10b981" /> {isModifiedFile ? 'Restored Pristine Official Copy' : isUnknownOrRogue ? 'File Resolved & Removed' : 'Hardened & Resolved'}
                </span>
              ) : isChecksumsUnavailable ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#eff6ff',
                    color: '#1d4ed8',
                    border: '1px solid #bfdbfe',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <Info size={12} color="#2563eb" /> Unmanaged / Proprietary Component
                </span>
              ) : isModifiedFile ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#fffbeb',
                    color: '#b45309',
                    border: '1px solid #fde68a',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <AlertTriangle size={12} color="#d97706" /> Modified Official File (Integrity Mismatch)
                </span>
              ) : isUnknownOrRogue ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#fef2f2',
                    color: '#b91c1c',
                    border: '1px solid #fecaca',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <ShieldAlert size={12} color="#dc2626" /> {issue.type === 'unknown_core_file' ? 'Unrecognized Core File' : 'Rogue / Unknown File'}
                </span>
              ) : isHardenedConfig ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#ecfdf5',
                    color: '#047857',
                    border: '1px solid #a7f3d0',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                  title="Optimal owner-restricted permissions benchmark for sensitive configuration files"
                >
                  <ShieldCheck size={12} color="#10b981" /> Secure & Hardened ({currentPerms})
                </span>
              ) : isWorldWritable ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#fef2f2',
                    color: '#b91c1c',
                    border: '1px solid #fecaca',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <Unlock size={12} color="#dc2626" /> Critical: World-Writable ({currentPerms})
                </span>
              ) : isOptimalSecurity ? (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#f0fdf4',
                    color: '#15803d',
                    border: '1px solid #bbf7d0',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <CheckCircle2 size={12} color="#16a34a" /> Standard Secure Mode ({currentPerms})
                </span>
              ) : (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#fffbeb',
                    color: '#b45309',
                    border: '1px solid #fde68a',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  <AlertTriangle size={12} color="#d97706" /> Permissions Risk ({currentPerms})
                </span>
              )}
              {fs.is_safe_directory_index && (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: '#f0fdf4',
                    color: '#15803d',
                    border: '1px solid #bbf7d0',
                    padding: '2px 8px',
                    borderRadius: '9999px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                  title="Verified benign directory listing prevention placeholder (Silence is golden / WP Staging / Elementor / Safe index)"
                >
                  <ShieldCheck size={12} color="#16a34a" /> Benign Directory Protection Index
                </span>
              )}
            </div>
            <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
              {isUnknownOrRogue
                ? 'Deep filesystem metadata, inode timestamps, privilege boundary analysis and rogue file containment.'
                : 'Deep filesystem metadata, inode timestamps, privilege boundary analysis and 1-click hardening.'}
            </div>
          </div>
        </div>

        {/* Header Right Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {issue.type === 'wp_debug_enabled' ? (
            isRepaired ? (
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#f0fdf4',
                  color: '#15803d',
                  border: '1px solid #bbf7d0',
                  padding: '6px 14px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 700,
                }}
              >
                <CheckCircle2 size={16} color="#16a34a" />
                <span>Debugging Disabled & Hardened</span>
              </div>
            ) : (
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                {onDisableWpDebug && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{
                      background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                      color: '#ffffff',
                      border: '1px solid #047857',
                      padding: '7px 16px',
                      borderRadius: '7px',
                      fontSize: '13px',
                      fontWeight: 700,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      cursor: remediating ? 'not-allowed' : 'pointer',
                      boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                      transition: 'all 0.15s ease',
                    }}
                    disabled={remediating}
                    onClick={() => onDisableWpDebug(issue)}
                    title="1-Click Fix: Intelligently comment out debugging and disable WP_DEBUG in wp-config.php"
                  >
                    <ShieldCheck size={14} />
                    <span>1-Click Fix: Disable Debugging</span>
                  </button>
                )}

                {onOpenFileViewer && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{
                      background: '#f8fafc',
                      color: '#334155',
                      border: '1px solid #cbd5e1',
                      padding: '6px 12px',
                      borderRadius: '7px',
                      fontSize: '12px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                    }}
                    onClick={() => onOpenFileViewer(issue)}
                    title="Inspect raw file content"
                  >
                    <Eye size={13} />
                    <span>Inspect File</span>
                  </button>
                )}
              </div>
            )
          ) : isQuarantined ? (
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: '#f0fdf4',
                color: '#15803d',
                border: '1px solid #bbf7d0',
                padding: '6px 14px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 700,
              }}
            >
              <Archive size={15} color="#16a34a" />
              <span>Safely Quarantined in Vault</span>
            </div>
          ) : isRepaired ? (
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: '#f0fdf4',
                color: '#15803d',
                border: '1px solid #bbf7d0',
                padding: '6px 14px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 700,
              }}
            >
              <CheckCircle2 size={16} color="#16a34a" />
              <span>{isModifiedFile ? 'Official Code Restored' : isUnknownOrRogue ? 'Rogue File Deleted & Removed' : `Permissions Hardened to ${currentPerms}`}</span>
            </div>
          ) : isModifiedFile ? (
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {onAutoCure && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                    color: '#ffffff',
                    border: '1px solid #047857',
                    padding: '7px 15px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                    boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                  }}
                  disabled={remediating}
                  onClick={() => onAutoCure(issue)}
                  title="Auto-Cure: Restore bit-for-bit clean copy from official WordPress.org release with automatic 14-day Vault backup"
                >
                  <RotateCcw size={14} />
                  <span>Auto-Cure: Restore Official WP.org</span>
                </button>
              )}



                            {onOpenFileViewer && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#f8fafc',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    padding: '6px 12px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                  }}
                  onClick={() => onOpenFileViewer(issue)}
                  title="Inspect raw file content and threat lines"
                >
                  <Eye size={13} />
                  <span>View File</span>
                </button>
              )}
            </div>
          ) : isUnknownOrRogue ? (
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {onQuarantine && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#059669',
                    color: '#ffffff',
                    border: '1px solid #047857',
                    padding: '7px 15px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                    boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                  }}
                  disabled={remediating}
                  onClick={() => onQuarantine(issue)}
                  title="Safely isolate this rogue file in protected Quarantine Vault with 1-click restore"
                >
                  <Archive size={14} />
                  <span>Quarantine</span>
                </button>
              )}

              {onDeleteFile && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#fef2f2',
                    color: '#dc2626',
                    border: '1px solid #fca5a5',
                    padding: '7px 14px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                  }}
                  disabled={remediating}
                  onClick={() => onDeleteFile(issue)}
                  title="Permanently delete this rogue file from server disk"
                >
                  <Trash2 size={14} />
                  <span>Delete File</span>
                </button>
              )}

              {onOpenFileViewer && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#f8fafc',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    padding: '6px 12px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                  }}
                  onClick={() => onOpenFileViewer(issue)}
                  title="Inspect raw file content and threat lines"
                >
                  <Eye size={13} />
                  <span>Inspect File</span>
                </button>
              )}
            </div>
          ) : (
            <Fragment>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <select
                  value={selectedPerm}
                  onChange={(e) => setSelectedPerm(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid #cbd5e1',
                    fontSize: '12px',
                    fontWeight: 600,
                    background: '#ffffff',
                    color: '#334155',
                    cursor: 'pointer',
                  }}
                  title="Select desired target permission"
                >
                  <option value="0644">0644 (Owner RW, Others Read - Recommended for Files)</option>
                  <option value="0755">0755 (Owner RWX, Others Read/Exec - Recommended for Dirs)</option>
                  <option value="0600">0600 (Strict Owner Read/Write Only - Sensitive)</option>
                  <option value="0444">0444 (Read-Only Immutable)</option>
                </select>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#059669',
                    color: '#ffffff',
                    border: '1px solid #047857',
                    padding: '7px 16px',
                    borderRadius: '7px',
                    fontSize: '13px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                    boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                    transition: 'all 0.15s ease',
                  }}
                  disabled={remediating}
                  onClick={() => onFixPermissions(issue, selectedPerm)}
                  title={`1-Click Fix: Immediately harden file permissions to ${selectedPerm}`}
                >
                  <Lock size={14} />
                  <span>{remediating ? 'Hardening...' : `1-Click Fix: Set ${selectedPerm}`}</span>
                </button>
              </div>

              {onOpenFileViewer && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#f8fafc',
                    color: '#334155',
                    border: '1px solid #cbd5e1',
                    padding: '6px 12px',
                    borderRadius: '7px',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                  }}
                  onClick={() => onOpenFileViewer(issue)}
                  title="Inspect raw file content and threat lines"
                >
                  <Eye size={13} />
                  <span>Inspect File</span>
                </button>
              )}
            </Fragment>
          )}
        </div>
      </div>

      {/* 4 Forensic Key Metrics (Created, Modified, Accessed, Size) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        {/* Metric 1: Created Time */}
        <div className="webcare-component-metric-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span className="webcare-component-metric-label">
              Created Time (ctime)
            </span>
            <Calendar size={14} color="#38bdf8" />
          </div>
          <div className="webcare-component-metric-val" style={{ fontFamily: 'monospace', fontSize: '13px' }}>
            {createdTime}
          </div>
          <div className="webcare-component-metric-sub">
            {createdHuman ? `${createdHuman} • Inode creation/meta` : 'Filesystem creation timestamp'}
          </div>
        </div>

        {/* Metric 2: Last Modified Time */}
        <div className="webcare-component-metric-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span className="webcare-component-metric-label">
              Last Edited (mtime)
            </span>
            <Clock size={14} color="#fbbf24" />
          </div>
          <div className="webcare-component-metric-val" style={{ fontFamily: 'monospace', fontSize: '13px' }}>
            {modifiedTime}
          </div>
          <div className="webcare-component-metric-sub">
            {modifiedHuman ? `${modifiedHuman} • Data modification` : 'Last content edit timestamp'}
          </div>
        </div>

        {/* Metric 3: Last Accessed Time */}
        <div className="webcare-component-metric-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span className="webcare-component-metric-label">
              Last Accessed (atime)
            </span>
            <Eye size={14} color="#a855f7" />
          </div>
          <div className="webcare-component-metric-val" style={{ fontFamily: 'monospace', fontSize: '13px' }}>
            {accessedTime}
          </div>
          <div className="webcare-component-metric-sub">
            {accessedHuman ? `${accessedHuman} • Read access` : 'Last read/execution by web process'}
          </div>
        </div>

        {/* Metric 4: File Size */}
        <div className="webcare-component-metric-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span className="webcare-component-metric-label">
              File Size &amp; Storage
            </span>
            <HardDrive size={14} color="#34d399" />
          </div>
          <div className="webcare-component-metric-val">
            {fileSize}
          </div>
          <div className="webcare-component-metric-sub">
            {fileSizeBytes || 'Storage on disk'}
          </div>
        </div>
      </div>

      {/* Permissions Breakdown & Forensic Deep Dive */}
      <div className="webcare-filesystem-inode-box">
        <div className="webcare-filesystem-inode-title">
          <Terminal size={14} color="#38bdf8" />
          <span>Detailed Inode &amp; Privilege Boundary Attributes:</span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
            gap: '12px',
            fontSize: '12px',
          }}
        >
          {/* Item 1: Permissions Comparison */}
          <div className="webcare-filesystem-inner-item">
            <div className="webcare-item-label">
              Current Mode vs. Recommended Mode:
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className={(isRepaired || isOptimalSecurity) ? 'webcare-fs-perm-pill-clean' : 'webcare-fs-perm-pill-warn'}>
                {currentPerms} ({symbolicPerms})
              </span>
              <span style={{ color: '#94a3b8' }}>➔</span>
              <span className="webcare-fs-perm-pill-clean">
                {recommendedPerms} ({recommendedSymbolic})
              </span>
              {isOptimalSecurity && (
                <span className="webcare-fs-optimal-tag">
                  ✓ Optimal Posture
                </span>
              )}
            </div>
          </div>

          {/* Item 2: Ownership */}
          <div className="webcare-filesystem-inner-item">
            <div className="webcare-item-label">
              File Ownership &amp; Group:
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
              <User size={13} color="#94a3b8" />
              <span>Owner: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{owner}</strong></span>
              <span style={{ color: '#94a3b8' }}>|</span>
              <Users size={13} color="#94a3b8" />
              <span>Group: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{group}</strong></span>
            </div>
          </div>

          {/* Item 3: Parent Directory & Permissions */}
          <div className="webcare-filesystem-inner-item">
            <div className="webcare-item-label">
              Parent Directory &amp; Container Perms:
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Folder size={13} color="#f59e0b" />
              <span
                style={{
                  fontFamily: 'monospace',
                  fontWeight: 600,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '220px',
                  color: 'var(--webcare-text-primary, #0f172a)',
                }}
                title={parentDir}
              >
                {parentDir}
              </span>
              <span className="webcare-parent-perms-pill">
                {parentPerms}
              </span>
            </div>
          </div>

          {/* Item 4: MIME Type & Execution Flags */}
          <div className="webcare-filesystem-inner-item">
            <div className="webcare-item-label">
              MIME Type &amp; Execution Security:
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileText size={13} color="#0284c7" />
              <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>{mimeType}</span>
              <span className={isWorldWritable ? 'webcare-fs-exec-pill-danger' : 'webcare-fs-exec-pill-safe'}>
                {isWorldWritable ? 'PUBLIC WRITE: PERMITTED' : 'PUBLIC WRITE: RESTRICTED'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Advisory for Site Owner & Developer */}
      <div
        className={`webcare-fs-advisory-box ${(isRepaired || isQuarantined || isOptimalSecurity)
          ? 'webcare-fs-advisory-clean'
          : (isWorldWritable || isUnknownOrRogue)
          ? 'webcare-fs-advisory-danger'
          : 'webcare-fs-advisory-warn'
        }`}
      >
        <div style={{ marginTop: '2px', flexShrink: 0 }}>
          {(isRepaired || isQuarantined || isOptimalSecurity) ? (
            <ShieldCheck size={16} />
          ) : (
            <AlertTriangle size={16} />
          )}
        </div>
        <div style={{ fontSize: '12px', lineHeight: 1.5 }}>
          <strong>
            {isModifiedFile
              ? 'Modified Official File (Integrity Mismatch):'
              : isUnknownOrRogue ? (
                isQuarantined
                  ? 'Threat Safely Isolated in Quarantine Vault:'
                  : isRepaired
                  ? 'Rogue File Removed & Solved:'
                  : 'Rogue / Unrecognized File Notice:'
              ) : isHardenedConfig ? (
                'Hardened Security Best Practice (wp-config.php / .htaccess):'
              ) : (isRepaired || isOptimalSecurity) ? (
                'Security Compliant Permissions:'
              ) : isWorldWritable ? (
                'Why are 0777 / World-Writable permissions a critical vulnerability?'
              ) : (
                'Filesystem Permissions Notice:'
              )}
          </strong>{' '}
          {isChecksumsUnavailable ? (
            <span>
              This component is an unmanaged, proprietary, or custom plugin/theme that is not hosted on the public WordPress.org repository. As a result, official remote checksums cannot be downloaded.
              <br />
              • <strong>Mark Safe / Ignore:</strong> If you recognize this plugin or custom folder, click "Mark Safe / Ignore" to acknowledge it and exclude it from future integrity warnings.
              <br />
              • <strong>View File:</strong> Inspect the code to ensure it was provided by an authorized vendor.
            </span>
          ) : isModifiedFile ? (
            isRepaired ? (
              <span>
                This modified official file has been restored to the exact pristine version from WordPress.org. An automatic safety snapshot of your previous version is saved in WebCare Vault for emergency rollback.
              </span>
            ) : (
              <span>
                This file is an official WordPress Core, Plugin, or Theme file whose contents differ from the official WordPress.org cryptographic release manifest. This frequently indicates malicious code injection, backdoors, webshell infection, or unauthorized manual file tampering.
                <br />
                • <strong>Auto-Cure: Restore Official WP.org (Recommended):</strong> Automatically downloads and replaces this file with the authentic, bit-for-bit pristine version from WordPress.org, while archiving an emergency snapshot to WebCare Vault.
                <br />
                • <strong>View File:</strong> Inspect the current file contents and examine detected modifications or injected lines before taking action.
              </span>
            )
          ) : isUnknownOrRogue ? (
            isQuarantined ? (
              <span>
                This file has been safely moved out of your live WordPress directory into the protected WebCare Quarantine Vault (<code>.quarantine</code>) with execution disabled. You can restore it anytime with 1-click from the Vault tab.
              </span>
            ) : isRepaired ? (
              <span>
                This unrecognized file was permanently unlinked and deleted from your web server filesystem. An automatic safety snapshot is preserved in WebCare Vault for emergency recovery.
              </span>
            ) : (
              <span>
                This file is not part of the official WordPress release manifest or integrity index. Unrecognized scripts inside WordPress directories are commonly malicious webshells, trojans, or persistence vectors.
                <br />
                • <strong>Quarantine File (Recommended):</strong> Safely isolates this file in the protected Quarantine Vault (<code>.quarantine</code>) with execution stripped, allowing instant 1-click rollback if needed.
                <br />
                • <strong>Delete File:</strong> Permanently unlinks and deletes this file from your web server.
              </span>
            )
          ) : isHardenedConfig ? (
            <span>
              This sensitive configuration file is securely restricted to <strong>{currentPerms}</strong> ({symbolicPerms}). WordPress.org security benchmarks recommend <strong>0600</strong> or <strong>0640</strong> for <code>wp-config.php</code> to strictly prevent other server users and unauthorized processes from reading database credentials, table prefixes, and authentication salts.
            </span>
          ) : (isRepaired || isOptimalSecurity) ? (
            <span>
              This path is restricted to <strong>{currentPerms}</strong>. World-writable privileges are revoked, ensuring other local system users and web-facing processes cannot tamper with or replace this file.
            </span>
          ) : isWorldWritable ? (
            <span>
              Permissions <code>{currentPerms}</code> give <strong>unrestricted read, write, and execute privileges to all users on the server</strong> (Owner, Group, and Public World). If any other site or process on this hosting environment is compromised, attackers can silently overwrite this file with PHP webshells or ransomware without root access. WordPress security standards require <strong>0644</strong> for files and <strong>0755</strong> for directories.
            </span>
          ) : (
            <span>
              Permissions are currently set to <code>{currentPerms}</code>. WordPress security standards recommend <strong>{recommendedPerms}</strong> ({isDir ? 'directories' : isWpConfig ? 'wp-config.php' : 'files'}).
            </span>
          )}
          {fs.is_safe_directory_index && (
            <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px dashed rgba(255, 255, 255, 0.1)', fontSize: '11.5px', color: '#34d399', lineHeight: 1.5 }}>
              <strong>🛡️ Directory Browsing Prevention Placeholder:</strong> This <code>index.php</code> file is a standard security guard intentionally created by developers or plugins (such as WP Staging, Elementor, Wordfence, or WordPress Core) to block public web visitors from browsing sensitive folder contents when server directory listing is enabled. It contains only benign silence comments/docblocks with zero executable backdoor code.
            </div>
          )}
        </div>
      </div>

      {/* Quick Action Footer */}
      <div
        style={{
          marginTop: '14px',
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          gap: '8px',
          flexWrap: 'wrap',
        }}
      >
        <button
          type="button"
          className="webcare-btn"
          style={{
            background: 'var(--webcare-bg-elevated, #f8fafc)',
            color: 'var(--webcare-text-primary, #0f172a)',
            border: '1px solid var(--webcare-border-strong, #cbd5e1)',
            padding: '6px 12px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
          onClick={() => handleCopy(issue.file_path || '', 'path')}
        >
          {copiedField === 'path' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
          <span>{copiedField === 'path' ? 'Path Copied!' : 'Copy Path'}</span>
        </button>

        {isModifiedFile ? (
          isRepaired ? (
            <div
              className="webcare-badge-pill webcare-badge-clean"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 700,
              }}
            >
              <Check size={13} color="currentColor" />
              <span>Official Version Restored</span>
            </div>
          ) : (
            <Fragment>
              {onOpenFileViewer && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-elevated, #f8fafc)',
                    color: 'var(--webcare-text-primary, #0f172a)',
                    border: '1px solid var(--webcare-border-strong, #cbd5e1)',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                  }}
                  onClick={() => onOpenFileViewer(issue)}
                  title="Inspect file contents and modified lines"
                >
                  <Eye size={13} />
                  <span>View File</span>
                </button>
              )}

              {onAutoCure && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                    color: '#ffffff',
                    border: '1px solid #047857',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                    boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                  }}
                  disabled={remediating}
                  onClick={() => onAutoCure(issue)}
                  title="Auto-Cure: Restore bit-for-bit clean copy from official WordPress.org release with automatic 14-day Vault backup"
                >
                  <RotateCcw size={13} />
                  <span>Auto-Cure: Restore Official WP.org</span>
                </button>
              )}
            </Fragment>
          )
        ) : isUnknownOrRogue ? (
          isQuarantined ? (
            <div
              className="webcare-badge-pill webcare-badge-clean"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 700,
              }}
            >
              <Archive size={13} color="currentColor" />
              <span>Quarantined in Vault</span>
            </div>
          ) : isRepaired ? (
            <div
              className="webcare-badge-pill webcare-badge-clean"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 700,
              }}
            >
              <Check size={13} color="currentColor" />
              <span>Rogue File Deleted</span>
            </div>
          ) : (
            <Fragment>
              {onQuarantine && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#059669',
                    color: '#ffffff',
                    border: '1px solid #047857',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                  }}
                  disabled={remediating}
                  onClick={() => onQuarantine(issue)}
                  title="Safely isolate in Quarantine Vault with 1-click restore"
                >
                  <Archive size={13} />
                  <span>Quarantine File</span>
                </button>
              )}
              {onDeleteFile && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: '#fef2f2',
                    color: '#dc2626',
                    border: '1px solid #fca5a5',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: remediating ? 'not-allowed' : 'pointer',
                  }}
                  disabled={remediating}
                  onClick={() => onDeleteFile(issue)}
                  title="Permanently delete this rogue file from server disk"
                >
                  <Trash2 size={13} />
                  <span>Delete File</span>
                </button>
              )}
            </Fragment>
          )
        ) : issue.type === 'wp_debug_enabled' ? (
          !isRepaired && onDisableWpDebug && (
            <button
              type="button"
              className="webcare-btn"
              style={{
                background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                color: '#ffffff',
                border: '1px solid #047857',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                cursor: remediating ? 'not-allowed' : 'pointer',
                boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
              }}
              disabled={remediating}
              onClick={() => onDisableWpDebug(issue)}
              title="1-Click Fix: Intelligently comment out debugging and disable WP_DEBUG in wp-config.php"
            >
              <ShieldCheck size={13} color="#ffffff" />
              <span>Disable Debugging & Lock Down wp-config.php</span>
            </button>
          )
        ) : !isRepaired && (
          isOptimalSecurity ? (
            <div className="webcare-fs-footer-optimal-chip">
              <Check size={13} color="#059669" />
              <span>Optimal {recommendedPerms} Permissions Active</span>
            </div>
          ) : (
            <button
              type="button"
              className="webcare-btn webcare-action-btn-clean"
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
              }}
              disabled={remediating}
              onClick={() => onFixPermissions(issue, recommendedPerms)}
              title={`Immediately harden permissions to ${recommendedPerms}`}
            >
              <ShieldCheck size={13} color="currentColor" />
              <span>Apply Recommended {recommendedPerms} Hardening</span>
            </button>
          )
        )}
      </div>
    </div>
  );
};
