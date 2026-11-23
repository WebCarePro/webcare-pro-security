import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  ShieldAlert,
  ShieldCheck,
  FolderLock,
  FileCode,
  Folder,
  RefreshCw,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  Lock,
  Unlock,
  Server,
  UserCheck,
  Layers,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Wand2,
  CheckCircle2,
  XCircle,
  Clock
} from 'lucide-react';

interface ServerInfo {
  user: string;
  uid: number;
  group: string;
  gid: number;
}

interface InsecureItem {
  path: string;
  relative_path: string;
  current_perm: string;
  target_perm: string;
  owner: string;
  group: string;
  unfixable?: boolean;
}

interface ConflictItem {
  path: string;
  relative_path: string;
  type: 'directory' | 'file';
  current_perm: string;
  target_perm: string;
  owner_name: string;
  owner_uid: number;
  group_name: string;
  group_gid: number;
  expected_owner: string;
  expected_group: string;
  reason: string;
}

interface AuditData {
  success: boolean;
  root_path: string;
  server_info: ServerInfo;
  total_directories_scanned: number;
  total_files_scanned: number;
  insecure_directories_count: number;
  insecure_files_count: number;
  conflicts_count: number;
  is_healthy: boolean;
  insecure_directories: InsecureItem[];
  insecure_files: InsecureItem[];
  conflicts: ConflictItem[];
  cli_commands: string;
}

interface FilesystemPermissionHardeningCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onPermissionsFixed?: () => void;
}

export function FilesystemPermissionHardeningCard({ apiRequest, onPermissionsFixed }: FilesystemPermissionHardeningCardProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [fixing, setFixing] = useState<boolean>(false);
  const [auditData, setAuditData] = useState<AuditData | null>(null);
  const [copiedCli, setCopiedCli] = useState<boolean>(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<'conflicts' | 'dirs' | 'files' | 'cli' | null>('conflicts');

  // Load audit preview on initial render
  const runAudit = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const res: AuditData = await apiRequest({
        path: '/webcare-pro-security/v1/permissions/audit',
        method: 'GET',
      });
      if (res && res.success) {
        setAuditData(res);
        if (res.conflicts_count > 0) {
          setExpandedSection('conflicts');
        } else if (res.insecure_directories_count > 0) {
          setExpandedSection('dirs');
        } else if (res.insecure_files_count > 0) {
          setExpandedSection('files');
        }
      }
    } catch (err: any) {
      console.error('Failed to audit permissions', err);
      setErrorMessage(err.message || 'Failed to complete permission audit.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runAudit();
  }, []);

  // Execute 1-Click Fix All
  const handleFixAll = async () => {
    const confirmed = await showConfirm({
      title: 'Standardize Permissions',
      message: 'Standardize all directory permissions to 0755 and file permissions to 0644 across the WordPress tree?',
      confirmLabel: 'Standardize All Permissions',
      variant: 'info',
    });
    if (!confirmed) {
      return;
    }

    setFixing(true);
    setSuccessMessage(null);
    setErrorMessage(null);

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/permissions/fix-all',
        method: 'POST',
      });

      if (res && res.success) {
        setSuccessMessage(res.message);
        if (onPermissionsFixed) {
          onPermissionsFixed();
        }
        // Refresh audit data
        await runAudit();
      } else {
        setErrorMessage(res.message || 'Permission hardening encountered an unexpected error.');
      }
    } catch (err: any) {
      console.error('Failed to execute fix-all', err);
      setErrorMessage(err.message || 'Permission hardening failed.');
    } finally {
      setFixing(false);
    }
  };

  const copyCliCommands = () => {
    if (!auditData?.cli_commands) return;
    navigator.clipboard.writeText(auditData.cli_commands);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2500);
  };

  return (
    <div className="webcare-card webcare-perm-card" style={{ marginBottom: '24px' }}>
      {/* Header Strip */}
      <div className="webcare-perm-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
            <span className="webcare-perm-icon-wrap">
              <Lock size={20} />
            </span>
            <h3 className="webcare-perm-title">
              Filesystem Permissions & Ownership Auditor
            </h3>
            <span className="webcare-badge" style={{ background: auditData?.is_healthy ? '#ecfdf5' : '#fef2f2', color: auditData?.is_healthy ? '#059669' : '#dc2626', border: `1px solid ${auditData?.is_healthy ? '#a7f3d0' : '#fecaca'}` }}>
              {loading ? 'Auditing...' : auditData?.is_healthy ? '● All Permissions Secure' : `● ${((auditData?.insecure_directories_count || 0) + (auditData?.insecure_files_count || 0))} Needs Hardening`}
            </span>
          </div>
          <p className="webcare-perm-desc">
            Automated compliance engine to enforce WordPress standard directory permissions (<code className="webcare-perm-inline-code">0755</code> / <code className="webcare-perm-inline-code">0750</code>) and file permissions (<code className="webcare-perm-inline-code">0644</code>). Identifies foreign-owned files and generates copy-paste SysAdmin shell scripts.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary webcare-perm-btn-reanalyze"
            onClick={runAudit}
            disabled={loading || fixing}
          >
            <RefreshCw size={14} className={loading ? 'webcare-spin-icon' : ''} />
            {loading ? 'Analyzing...' : 'Re-Analyze'}
          </button>

          <button
            type="button"
            className="webcare-btn webcare-btn-primary webcare-perm-btn-fix"
            onClick={handleFixAll}
            disabled={loading || fixing || (auditData?.insecure_directories_count === 0 && auditData?.insecure_files_count === 0)}
            style={{
              cursor: (auditData?.insecure_directories_count === 0 && auditData?.insecure_files_count === 0) ? 'not-allowed' : 'pointer'
            }}
          >
            <Wand2 size={15} />
            {fixing ? 'Hardening Permissions...' : '1-Click Harden All Permissions'}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {successMessage && (
        <div className="webcare-perm-notice success">
          <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
          <span style={{ fontSize: '13px', fontWeight: 600 }}>{successMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div className="webcare-perm-notice error">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span style={{ fontSize: '13px', fontWeight: 600 }}>{errorMessage}</span>
        </div>
      )}

      {/* KPI Tiles Strip */}
      <div className="webcare-perm-kpi-grid">
        <div className="webcare-perm-kpi-tile">
          <div className="webcare-perm-kpi-label">
            Scanned Trees
          </div>
          <div className="webcare-perm-kpi-val">
            {loading ? '...' : `${auditData?.total_directories_scanned || 0} Dirs / ${auditData?.total_files_scanned || 0} Files`}
          </div>
          <div className="webcare-perm-kpi-sub">
            Target: ABSPATH root
          </div>
        </div>

        <div className={`webcare-perm-kpi-tile ${(auditData?.insecure_directories_count || 0) > 0 ? 'warning' : ''}`}>
          <div className="webcare-perm-kpi-label">
            Unsafe Folders (0777)
          </div>
          <div className={`webcare-perm-kpi-val ${(auditData?.insecure_directories_count || 0) > 0 ? 'val-warning' : 'val-clean'}`}>
            {loading ? '...' : auditData?.insecure_directories_count || 0}
          </div>
          <div className="webcare-perm-kpi-sub">
            Target: 0755 / 0750 standard
          </div>
        </div>

        <div className={`webcare-perm-kpi-tile ${(auditData?.insecure_files_count || 0) > 0 ? 'warning' : ''}`}>
          <div className="webcare-perm-kpi-label">
            Unsafe Files (0777/0666)
          </div>
          <div className={`webcare-perm-kpi-val ${(auditData?.insecure_files_count || 0) > 0 ? 'val-warning' : 'val-clean'}`}>
            {loading ? '...' : auditData?.insecure_files_count || 0}
          </div>
          <div className="webcare-perm-kpi-sub">
            Target: 0644 (0600 wp-config)
          </div>
        </div>

        <div className={`webcare-perm-kpi-tile ${(auditData?.conflicts_count || 0) > 0 ? 'danger' : ''}`}>
          <div className="webcare-perm-kpi-label">
            Ownership Conflicts
          </div>
          <div className={`webcare-perm-kpi-val ${(auditData?.conflicts_count || 0) > 0 ? 'val-danger' : 'val-clean'}`}>
            {loading ? '...' : auditData?.conflicts_count || 0}
          </div>
          <div className="webcare-perm-kpi-sub">
            Requires root / SSH chmod
          </div>
        </div>

        <div className="webcare-perm-kpi-tile">
          <div className="webcare-perm-kpi-label">
            Active Web Server User
          </div>
          <div className="webcare-perm-kpi-val server-user">
            {auditData?.server_info ? `${auditData.server_info.user}:${auditData.server_info.group}` : 'Detecting...'}
          </div>
          <div className="webcare-perm-kpi-sub">
            UID: {auditData?.server_info?.uid ?? 0} • GID: {auditData?.server_info?.gid ?? 0}
          </div>
        </div>
      </div>

      {/* Ownership Conflicts Alert & Table (Crucial Requirement) */}
      {(auditData?.conflicts_count || 0) > 0 && (
        <div className="webcare-perm-conflict-banner">
          <div 
            onClick={() => setExpandedSection(expandedSection === 'conflicts' ? null : 'conflicts')}
            className="webcare-perm-conflict-header"
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <AlertTriangle size={18} color="#e11d48" />
              <div>
                <strong className="webcare-perm-conflict-title">
                  {auditData?.conflicts_count} Foreign-Owned Files / Folders (Permission Change Blocked by Linux OS)
                </strong>
                <p className="webcare-perm-conflict-subtitle">
                  These items are owned by another user (e.g. root) while PHP executes as <code className="webcare-perm-conflict-user">{auditData?.server_info?.user}</code>. Web server cannot chmod foreign files without root privileges.
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="webcare-badge webcare-perm-conflict-badge">
                {auditData?.conflicts_count} Unfixable via PHP
              </span>
              {expandedSection === 'conflicts' ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
            </div>
          </div>

          {expandedSection === 'conflicts' && (
            <div style={{ padding: '16px' }}>
              <div style={{ overflowX: 'auto', maxHeight: '320px', overflowY: 'auto' }}>
                <table className="webcare-table webcare-perm-table" style={{ width: '100%', fontSize: '12px' }}>
                  <thead>
                    <tr>
                      <th style={{ padding: '8px 12px' }}>Type</th>
                      <th style={{ padding: '8px 12px' }}>Path</th>
                      <th style={{ padding: '8px 12px' }}>Current Perm</th>
                      <th style={{ padding: '8px 12px' }}>Current Owner</th>
                      <th style={{ padding: '8px 12px' }}>Expected Server Owner</th>
                      <th style={{ padding: '8px 12px' }}>Diagnostic Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditData?.conflicts.map((item, idx) => (
                      <tr key={idx} className="webcare-perm-row">
                        <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                          <span className={`webcare-perm-type-badge ${item.type}`}>
                            {item.type === 'directory' ? <Folder size={12} /> : <FileCode size={12} />}
                            {item.type}
                          </span>
                        </td>
                        <td className="webcare-perm-path" style={{ padding: '8px 12px' }}>
                          {item.relative_path || item.path}
                        </td>
                        <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                          <span className="webcare-perm-code-bad">{item.current_perm}</span>
                          <span style={{ color: '#94a3b8', margin: '0 4px' }}>➔</span>
                          <span className="webcare-perm-code-good">{item.target_perm}</span>
                        </td>
                        <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                          <span className="webcare-perm-owner-bad">{item.owner_name}</span> (UID: {item.owner_uid})
                        </td>
                        <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                          <span className="webcare-perm-owner-good">{item.expected_owner}</span> (UID: {auditData?.server_info?.uid})
                        </td>
                        <td className="webcare-perm-reason" style={{ padding: '8px 12px' }}>
                          {item.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SysAdmin Terminal Script Generator Box */}
      <div className="webcare-perm-terminal-box">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={17} color="#0284c7" />
            <span className="webcare-perm-terminal-title" style={{ fontWeight: 700, fontSize: '13px', letterSpacing: '0.3px' }}>
              SysAdmin SSH / Terminal Recovery Script
            </span>
            <span className="webcare-perm-terminal-badge" style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '12px' }}>
              Root Privileges
            </span>
          </div>
          <button
            type="button"
            className="webcare-btn webcare-perm-btn-copy"
            onClick={copyCliCommands}
          >
            {copiedCli ? <Check size={14} /> : <Copy size={14} />}
            {copiedCli ? 'Copied to Clipboard!' : 'Copy Script'}
          </button>
        </div>
        <p style={{ margin: '0 0 10px 0', fontSize: '12px', color: '#94a3b8', lineHeight: 1.4 }}>
          Run this tailored script in SSH or container terminal to normalize owner to <strong style={{ color: '#38bdf8' }}>{auditData?.server_info?.user || 'www-data'}</strong> and enforce recursive <strong style={{ color: '#38bdf8' }}>755</strong> directories & <strong style={{ color: '#38bdf8' }}>644</strong> files without permission errors.
        </p>
        <pre className="webcare-perm-cli-pre">
          {auditData?.cli_commands || '# Loading generated commands...'}
        </pre>
      </div>

      {/* Insecure Directories Collapsible Table */}
      {(auditData?.insecure_directories_count || 0) > 0 && (
        <div className="webcare-perm-accordion-wrap">
          <div 
            onClick={() => setExpandedSection(expandedSection === 'dirs' ? null : 'dirs')}
            className="webcare-perm-accordion-header"
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FolderLock size={16} color="#e11d48" />
              <strong className="webcare-perm-accordion-title">
                Unsafe Folders Requiring Reset to 0755 ({auditData?.insecure_directories_count})
              </strong>
            </div>
            {expandedSection === 'dirs' ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </div>
          {expandedSection === 'dirs' && (
            <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
              <table className="webcare-table webcare-perm-table" style={{ width: '100%', fontSize: '12px' }}>
                <thead>
                  <tr>
                    <th style={{ padding: '8px 12px' }}>Folder Path</th>
                    <th style={{ padding: '8px 12px' }}>Current Perm</th>
                    <th style={{ padding: '8px 12px' }}>Target Perm</th>
                    <th style={{ padding: '8px 12px' }}>Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {auditData?.insecure_directories.map((dir, idx) => (
                    <tr key={idx} className="webcare-perm-row">
                      <td className="webcare-perm-path" style={{ padding: '8px 12px' }}>{dir.relative_path || dir.path}</td>
                      <td style={{ padding: '8px 12px', color: '#dc2626', fontWeight: 700, fontFamily: 'monospace' }}>{dir.current_perm}</td>
                      <td style={{ padding: '8px 12px', color: '#16a34a', fontWeight: 700, fontFamily: 'monospace' }}>{dir.target_perm}</td>
                      <td className="webcare-perm-owner-info" style={{ padding: '8px 12px' }}>{dir.owner}:{dir.group}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Insecure Files Collapsible Table */}
      {(auditData?.insecure_files_count || 0) > 0 && (
        <div className="webcare-perm-accordion-wrap">
          <div 
            onClick={() => setExpandedSection(expandedSection === 'files' ? null : 'files')}
            className="webcare-perm-accordion-header"
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCode size={16} color="#ea580c" />
              <strong className="webcare-perm-accordion-title">
                Unsafe Files Requiring Reset to 0644 ({auditData?.insecure_files_count})
              </strong>
            </div>
            {expandedSection === 'files' ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </div>
          {expandedSection === 'files' && (
            <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
              <table className="webcare-table webcare-perm-table" style={{ width: '100%', fontSize: '12px' }}>
                <thead>
                  <tr>
                    <th style={{ padding: '8px 12px' }}>File Path</th>
                    <th style={{ padding: '8px 12px' }}>Current Perm</th>
                    <th style={{ padding: '8px 12px' }}>Target Perm</th>
                    <th style={{ padding: '8px 12px' }}>Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {auditData?.insecure_files.map((file, idx) => (
                    <tr key={idx} className="webcare-perm-row">
                      <td className="webcare-perm-path" style={{ padding: '8px 12px' }}>{file.relative_path || file.path}</td>
                      <td style={{ padding: '8px 12px', color: '#ea580c', fontWeight: 700, fontFamily: 'monospace' }}>{file.current_perm}</td>
                      <td style={{ padding: '8px 12px', color: '#16a34a', fontWeight: 700, fontFamily: 'monospace' }}>{file.target_perm}</td>
                      <td className="webcare-perm-owner-info" style={{ padding: '8px 12px' }}>{file.owner}:{file.group}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default FilesystemPermissionHardeningCard;
