import React, { useState, useEffect } from 'react';
import { showConfirm } from '../utils/dialog';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  FileCheck,
  FileX,
  FileCode,
  FileQuestion,
  CheckCircle2,
  Lock,
  Download,
  Mail,
  Bell,
  Cpu,
  Info,
  ExternalLink,
  ChevronRight,
  Search
} from 'lucide-react';

interface PluginSelfDefenseCardProps {
  apiRequest: (options: any) => Promise<any>;
}

export const PluginSelfDefenseCard: React.FC<PluginSelfDefenseCardProps> = ({ apiRequest }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [audit, setAudit] = useState<any>(null);
  const [settings, setSettings] = useState<any>({
    watchdog_enabled: true,
    notify_email: true,
    admin_email: '',
  });
  const [filterType, setFilterType] = useState<'all' | 'missing' | 'modified' | 'untracked'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusMessage, setStatusMessage] = useState<string>('');

  const loadStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/self-defense/status',
        method: 'GET',
      });
      if (res && res.success) {
        setAudit(res.audit);
        if (res.settings) {
          setSettings(res.settings);
        }
      }
    } catch (err: any) {
      console.error('Failed to load plugin self-defense status:', err);
    } finally {
      setLoading(false);
    }
  };

  const [verifyingGithub, setVerifyingGithub] = useState<boolean>(false);
  const [restoringPath, setRestoringPath] = useState<string | null>(null);

  const handleVerify = async () => {
    setVerifying(true);
    setStatusMessage('');
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/self-defense/verify',
        method: 'POST',
      });
      if (res && res.success) {
        setAudit(res.audit);
        setStatusMessage(res.message || 'Verification complete.');
      }
    } catch (err: any) {
      console.error('Failed to run self-defense audit:', err);
      setStatusMessage('Verification failed. Check server logs.');
    } finally {
      setVerifying(false);
    }
  };

  const handleVerifyGithub = async () => {
    setVerifyingGithub(true);
    setStatusMessage('');
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/self-defense/audit-github',
        method: 'POST',
      });
      if (res && res.success) {
        setAudit((prev: any) => ({
          ...prev,
          missing_files: res.missing_files || [],
          modified_files: res.modified_files || [],
          missing_count: res.missing_count || 0,
          modified_count: res.modified_count || 0,
          total_tracked: res.total_remote || prev?.total_tracked,
          verified_count: res.verified_count || 0,
          has_issues: (res.missing_count > 0 || res.modified_count > 0 || !res.manifest_intact),
          checked_at: res.checked_at,
          github_verified: true,
          github_version: res.github_version,
        }));
        setStatusMessage(
          res.missing_count === 0 && res.modified_count === 0
            ? `✓ 100% Verified against official GitHub release (${res.github_version}). All ${res.total_remote} files intact!`
            : `⚠️ GitHub Zero-Trust Audit detected ${res.modified_count} modified and ${res.missing_count} missing files.`
        );
      } else {
        setStatusMessage(res?.message || 'Failed to verify against GitHub.');
      }
    } catch (err: any) {
      console.error('Failed to audit against GitHub:', err);
      setStatusMessage('Failed to connect to GitHub. Please check server internet connectivity.');
    } finally {
      setVerifyingGithub(false);
    }
  };

  const handleRestoreFile = async (filePath: string) => {
    const confirmed = await showConfirm({
      title: 'Restore File from GitHub',
      message: `Are you sure you want to restore "${filePath}" directly from the official GitHub repository? This will overwrite the local file with the pristine author copy.`,
      confirmLabel: 'Restore File',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setRestoringPath(filePath);
    setStatusMessage('');
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/self-defense/restore-file',
        method: 'POST',
        data: { path: filePath }
      });
      if (res && res.success) {
        setStatusMessage(res.message);
        loadStatus();
      } else {
        setStatusMessage(res?.message || 'File restoration failed.');
      }
    } catch (err: any) {
      console.error('File restoration failed:', err);
      setStatusMessage('File restoration failed. Check server logs and folder permissions.');
    } finally {
      setRestoringPath(null);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const hasIssues = audit?.has_issues;
  const isPristine = audit && !hasIssues;

  // Build unified items list
  const missingFiles = audit?.missing_files || [];
  const modifiedFiles = audit?.modified_files || [];
  const untrackedFiles = audit?.untracked_files || [];

  const combinedItems = [
    ...missingFiles.map((f: any) => ({ ...f, category: 'missing' })),
    ...modifiedFiles.map((f: any) => ({ ...f, category: 'modified' })),
    ...untrackedFiles.map((f: any) => ({ ...f, category: 'untracked' })),
  ];

  const filteredItems = combinedItems.filter((item: any) => {
    if (filterType !== 'all' && item.category !== filterType) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return item.path.toLowerCase().includes(q) || (item.detail && item.detail.toLowerCase().includes(q));
    }
    return true;
  });

  return (
    <div className="webcare-card webcare-self-defense-card">
      {/* Header Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '4px 10px',
            borderRadius: '6px',
            background: isPristine ? 'var(--webcare-status-clean-soft, #f0fdf4)' : 'var(--webcare-status-critical-soft, #fef2f2)',
            border: isPristine ? '1px solid var(--webcare-status-clean-border, #86efac)' : '1px solid var(--webcare-status-critical-border, #fca5a5)',
            marginBottom: '8px'
          }}>
            <Lock size={13} color={isPristine ? 'var(--webcare-status-clean, #15803d)' : 'var(--webcare-status-critical, #dc2626)'} />
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: isPristine ? 'var(--webcare-status-clean, #15803d)' : 'var(--webcare-status-critical, #dc2626)'
            }}>
              Cryptographic Self-Defense &amp; Immunity
            </span>
          </div>
          <h2 className="webcare-self-defense-title">
            Plugin Self-Integrity &amp; Anti-Tamper Attestation
          </h2>
          <p className="webcare-self-defense-desc">
            Automated internal defense system that continuously verifies every PHP and asset file of WebCare Pro Security & Firewall against its official cryptographic SHA-256 release signature. Detects files quarantined by shared host scanners (e.g. cPanel Imunify360 or ModSecurity), partial zip extractions, and malware tampering.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="webcare-btn"
            onClick={handleVerifyGithub}
            disabled={verifyingGithub || verifying}
            style={{
              background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              padding: '10px 18px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: verifyingGithub ? 'not-allowed' : 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 4px 14px rgba(79, 70, 229, 0.25)',
              opacity: verifyingGithub ? 0.7 : 1,
            }}
          >
            <RefreshCw size={14} className={verifyingGithub ? 'webcare-spin' : ''} />
            <span>{verifyingGithub ? 'Querying GitHub...' : 'Verify Against GitHub (Zero-Trust)'}</span>
          </button>

          <button
            type="button"
            className="webcare-btn"
            onClick={handleVerify}
            disabled={verifying || verifyingGithub}
            style={{
              background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              padding: '10px 18px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: verifying ? 'not-allowed' : 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 4px 14px rgba(16, 185, 129, 0.3)',
              opacity: verifying ? 0.7 : 1,
            }}
          >
            <CheckCircle2 size={14} className={verifying ? 'webcare-spin' : ''} />
            <span>{verifying ? 'Verifying Local Hashes...' : 'Local Manifest Audit'}</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div style={{
          marginBottom: '20px',
          padding: '12px 16px',
          borderRadius: '8px',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          background: hasIssues ? 'var(--webcare-status-critical-soft, #fef2f2)' : 'var(--webcare-status-clean-soft, #f0fdf4)',
          border: hasIssues ? '1px solid var(--webcare-status-critical-border, #fca5a5)' : '1px solid var(--webcare-status-clean-border, #86efac)',
          color: hasIssues ? 'var(--webcare-status-critical, #dc2626)' : 'var(--webcare-status-clean, #15803d)',
        }}>
          {hasIssues ? <ShieldAlert size={16} /> : <CheckCircle2 size={16} />}
          <span>{statusMessage}</span>
        </div>
      )}

      {/* KPI Ribbon */}
      <div className="webcare-self-defense-kpi-grid">
        <div className="webcare-self-defense-kpi-card">
          <div className="webcare-self-defense-kpi-label">
            <FileCode size={14} color="#0284c7" />
            <span>Tracked Core Files</span>
          </div>
          <div className="webcare-self-defense-kpi-val">
            {audit?.total_tracked || 0}
          </div>
          <div className="webcare-self-defense-kpi-sub">
            Cryptographically signed
          </div>
        </div>

        <div className="webcare-self-defense-kpi-card">
          <div className="webcare-self-defense-kpi-label">
            <FileCheck size={14} color="#10b981" />
            <span>100% Intact &amp; Verified</span>
          </div>
          <div className="webcare-self-defense-kpi-val" style={{ color: '#10b981' }}>
            {audit?.verified_count || 0}
          </div>
          <div className="webcare-self-defense-kpi-sub">
            SHA-256 bit-for-bit match
          </div>
        </div>

        <div className={`webcare-self-defense-kpi-card ${(audit?.missing_count || 0) > 0 ? 'is-missing' : ''}`}>
          <div className="webcare-self-defense-kpi-label" style={{ color: (audit?.missing_count || 0) > 0 ? '#ef4444' : undefined }}>
            <FileX size={14} color={(audit?.missing_count || 0) > 0 ? '#ef4444' : '#64748b'} />
            <span>Missing Files (Host Dropped)</span>
          </div>
          <div className="webcare-self-defense-kpi-val" style={{ color: (audit?.missing_count || 0) > 0 ? '#ef4444' : undefined }}>
            {audit?.missing_count || 0}
          </div>
          <div className="webcare-self-defense-kpi-sub" style={{ color: (audit?.missing_count || 0) > 0 ? '#dc2626' : undefined }}>
            Deleted by host scanners
          </div>
        </div>

        <div className={`webcare-self-defense-kpi-card ${(audit?.modified_count || 0) > 0 ? 'is-modified' : ''}`}>
          <div className="webcare-self-defense-kpi-label" style={{ color: (audit?.modified_count || 0) > 0 ? '#d97706' : undefined }}>
            <AlertTriangle size={14} color={(audit?.modified_count || 0) > 0 ? '#f59e0b' : '#64748b'} />
            <span>Modified / Tampered</span>
          </div>
          <div className="webcare-self-defense-kpi-val" style={{ color: (audit?.modified_count || 0) > 0 ? '#d97706' : undefined }}>
            {audit?.modified_count || 0}
          </div>
          <div className="webcare-self-defense-kpi-sub" style={{ color: (audit?.modified_count || 0) > 0 ? '#b45309' : undefined }}>
            Hash signature mismatch
          </div>
        </div>
      </div>

      {/* Main Status Callout */}
      {isPristine ? (
        <div className="webcare-self-defense-banner-pristine">
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '50%',
            background: 'var(--webcare-status-clean-soft, #dcfce7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <ShieldCheck size={24} color="#10b981" />
          </div>
          <div>
            <div className="webcare-self-defense-banner-title-pristine">
              All Plugin Files are 100% Authentic &amp; Unmodified
            </div>
            <div className="webcare-self-defense-banner-desc-pristine">
              Every core module, REST controller, firewall engine, and asset matches the official release signature (v{audit?.plugin_version || '1.20.0'}). No files have been deleted by cPanel mod_security or altered by attackers.
            </div>
          </div>
        </div>
      ) : (
        <div className="webcare-self-defense-banner-alert">
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '50%',
            background: 'var(--webcare-status-critical-soft, #fee2e2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            marginTop: '2px'
          }}>
            <ShieldAlert size={24} color="#ef4444" />
          </div>
          <div style={{ flex: 1 }}>
            <div className="webcare-self-defense-banner-title-alert">
              Critical Self-Defense Alert: Plugin File Anomalies Detected!
            </div>
            <div className="webcare-self-defense-banner-desc-alert">
              One or more core security plugin files have been removed or tampered with on your server. When a shared hosting auto-scanner (like Imunify360 or ClamAV) deletes files, key features like Cloudflare WAF, REST APIs, or malware cleanup can fail silently.
            </div>
            <div className="webcare-self-defense-solution-box">
              <strong>Immediate Solution:</strong> Re-upload or replace the plugin zip via WordPress Admin (<strong>Plugins &gt; Add New &gt; Upload Plugin</strong>) to instantly restore all deleted core files.
            </div>
          </div>
        </div>
      )}

      {/* Watchdog Background Protection Card */}
      <div className="webcare-self-defense-watchdog-strip">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Bell size={18} color="#0284c7" />
          <div>
            <div className="webcare-self-defense-watchdog-title">
              Automated Twice-Daily Self-Defense Watchdog
            </div>
            <div className="webcare-self-defense-watchdog-desc">
              Runs automatically in the background via WP-Cron. Alerts the administrator via email (<code>{settings.admin_email || 'admin'}</code>) and top admin banner if host scanners delete or modify any plugin files.
            </div>
          </div>
        </div>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 10px',
          borderRadius: '6px',
          background: 'var(--webcare-status-clean-soft, #ecfdf5)',
          border: '1px solid var(--webcare-status-clean-border, #a7f3d0)',
          color: 'var(--webcare-status-clean, #047857)',
          fontSize: '12px',
          fontWeight: 700
        }}>
          <CheckCircle2 size={13} />
          <span>Active Watchdog</span>
        </div>
      </div>

      {/* Anomalies / Files Table */}
      {combinedItems.length > 0 && (
        <div style={{ marginTop: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => setFilterType('all')}
                style={{
                  padding: '6px 14px',
                  borderRadius: '6px',
                  border: filterType === 'all' ? '1px solid #0284c7' : '1px solid var(--webcare-border, #cbd5e1)',
                  background: filterType === 'all' ? 'var(--webcare-status-cyan-soft, #eff6ff)' : 'transparent',
                  color: filterType === 'all' ? 'var(--webcare-status-cyan, #0284c7)' : 'var(--webcare-text-muted, #64748b)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                All Anomalies ({combinedItems.length})
              </button>
              {missingFiles.length > 0 && (
                <button
                  type="button"
                  onClick={() => setFilterType('missing')}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: filterType === 'missing' ? '1px solid #ef4444' : '1px solid var(--webcare-border, #cbd5e1)',
                    background: filterType === 'missing' ? 'var(--webcare-status-critical-soft, #fef2f2)' : 'transparent',
                    color: filterType === 'missing' ? 'var(--webcare-status-critical, #dc2626)' : 'var(--webcare-text-muted, #64748b)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Missing ({missingFiles.length})
                </button>
              )}
              {modifiedFiles.length > 0 && (
                <button
                  type="button"
                  onClick={() => setFilterType('modified')}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: filterType === 'modified' ? '1px solid #f59e0b' : '1px solid var(--webcare-border, #cbd5e1)',
                    background: filterType === 'modified' ? 'var(--webcare-status-warn-soft, #fffbeb)' : 'transparent',
                    color: filterType === 'modified' ? 'var(--webcare-status-warn, #d97706)' : 'var(--webcare-text-muted, #64748b)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Modified ({modifiedFiles.length})
                </button>
              )}
              {untrackedFiles.length > 0 && (
                <button
                  type="button"
                  onClick={() => setFilterType('untracked')}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: filterType === 'untracked' ? '1px solid #7c3aed' : '1px solid var(--webcare-border, #cbd5e1)',
                    background: filterType === 'untracked' ? 'var(--webcare-status-purple-soft, #f5f3ff)' : 'transparent',
                    color: filterType === 'untracked' ? 'var(--webcare-status-purple, #7c3aed)' : 'var(--webcare-text-muted, #64748b)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Untracked ({untrackedFiles.length})
                </button>
              )}
            </div>

            {/* Search */}
            <div style={{ position: 'relative', width: '240px' }}>
              <Search size={14} color="#64748b" style={{ position: 'absolute', left: '10px', top: '10px' }} />
              <input
                type="text"
                placeholder="Filter file path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="webcare-self-defense-search-input"
              />
            </div>
          </div>

          {/* Table */}
          <div className="webcare-self-defense-table-box">
            <table className="webcare-self-defense-table">
              <thead>
                <tr>
                  <th>STATUS</th>
                  <th>PLUGIN RELATIVE PATH</th>
                  <th>SEVERITY</th>
                  <th>DIAGNOSTIC DETAIL</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item: any, idx: number) => {
                  const isMissing = item.category === 'missing';
                  const isMod = item.category === 'modified';
                  const isUntracked = item.category === 'untracked';
                  const isRestoring = restoringPath === item.path;

                  return (
                    <tr
                      key={idx}
                      className={idx % 2 === 0 ? 'is-even' : 'is-odd'}
                    >
                      <td>
                        {isMissing && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '3px 8px', borderRadius: '4px', background: 'var(--webcare-status-critical-soft, #fef2f2)', color: 'var(--webcare-status-critical, #dc2626)', fontSize: '11px', fontWeight: 700 }}>
                            <FileX size={12} /> MISSING
                          </span>
                        )}
                        {isMod && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '3px 8px', borderRadius: '4px', background: 'var(--webcare-status-warn-soft, #fffbeb)', color: 'var(--webcare-status-warn, #d97706)', fontSize: '11px', fontWeight: 700 }}>
                            <AlertTriangle size={12} /> MODIFIED
                          </span>
                        )}
                        {isUntracked && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '3px 8px', borderRadius: '4px', background: 'var(--webcare-status-purple-soft, #f5f3ff)', color: 'var(--webcare-status-purple, #7c3aed)', fontSize: '11px', fontWeight: 700 }}>
                            <FileQuestion size={12} /> UNTRACKED
                          </span>
                        )}
                      </td>
                      <td>
                        <code className="webcare-self-defense-path-code">
                          {item.path}
                        </code>
                        {item.expected_hash && (
                          <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'var(--font-mono, monospace)', marginTop: '4px' }}>
                            Expected SHA: {item.expected_hash.substring(0, 16)}...
                          </div>
                        )}
                      </td>
                      <td>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          background: item.severity === 'critical' ? 'var(--webcare-status-critical-soft, #fef2f2)' : 'var(--webcare-status-warn-soft, #fffbeb)',
                          color: item.severity === 'critical' ? 'var(--webcare-status-critical, #dc2626)' : 'var(--webcare-status-warn, #d97706)',
                          border: item.severity === 'critical' ? '1px solid var(--webcare-status-critical-border, #fca5a5)' : '1px solid var(--webcare-status-warn-border, #fde68a)'
                        }}>
                          {item.severity}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px' }}>
                        {item.detail}
                      </td>
                      <td>
                        {(isMissing || isMod) ? (
                          <button
                            type="button"
                            onClick={() => handleRestoreFile(item.path)}
                            disabled={isRestoring}
                            className="webcare-btn"
                            style={{
                              background: '#10b981',
                              color: '#ffffff',
                              border: 'none',
                              padding: '4px 10px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 700,
                              cursor: isRestoring ? 'not-allowed' : 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <Download size={11} className={isRestoring ? 'webcare-spin' : ''} />
                            {isRestoring ? 'Restoring...' : 'Restore from GitHub'}
                          </button>
                        ) : (
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>-</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
