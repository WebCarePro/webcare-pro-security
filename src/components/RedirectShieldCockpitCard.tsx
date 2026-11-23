import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Lock,
  Unlock,
  FileCode,
  History,
  RotateCcw,
  Globe,
  Smartphone,
  Bot,
  Search,
  Zap,
  Check,
  ExternalLink,
  Info,
  Layers,
  Database,
  ArrowRight
} from 'lucide-react';
import { showConfirm } from '../utils/dialog';

interface RedirectShieldCockpitProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const RedirectShieldCockpitCard: React.FC<RedirectShieldCockpitProps> = ({ apiRequest }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [probing, setProbing] = useState<boolean>(false);
  const [restoringVersion, setRestoringVersion] = useState<number | null>(null);
  const [togglingLock, setTogglingLock] = useState<boolean>(false);
  const [togglingAutoHeal, setTogglingAutoHeal] = useState<boolean>(false);
  const [healingUrls, setHealingUrls] = useState<boolean>(false);
  const [creatingSnapshot, setCreatingSnapshot] = useState<boolean>(false);
  const [status, setStatus] = useState<any | null>(null);
  const [probeReport, setProbeReport] = useState<any | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error' | 'warning'; message: string } | null>(null);
  const [viewingSnapshot, setViewingSnapshot] = useState<any | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await apiRequest({ path: '/firewall/redirect-shield/status' });
      if (res && res.success) {
        setStatus(res);
        if (res.canary_state && res.canary_state.last_report) {
          setProbeReport(res.canary_state.last_report);
        }
      }
    } catch (e: any) {
      console.error('Failed to fetch redirect shield status', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRunCanary = async () => {
    setProbing(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/probe',
        method: 'POST'
      });
      if (res && res.success) {
        setProbeReport(res.report);
        if (res.report.is_hostile) {
          setFeedback({
            type: 'error',
            message: `Hostile Redirect Incident Detected! Attack Vector: ${res.report.attack_vector || 'External Cloaking'}. Target: ${res.report.hijacked_location || 'Foreign Host'}`
          });
        } else {
          setFeedback({
            type: 'success',
            message: 'All 5 canary probes passed cleanly. No search engine cloaking, mobile redirects, or DOM hijacking detected.'
          });
        }
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Canary probe execution failed.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Canary probe network request error.' });
    } finally {
      setProbing(false);
    }
  };

  const handleRestoreSnapshot = async (version: number) => {
    const confirmed = await showConfirm({
      title: `Restore .htaccess from Snapshot #${version}?`,
      message: `Are you sure you want to rollback root .htaccess to Vault Snapshot #${version}? This will overwrite the live .htaccess file and automatically flush WP Rocket, LiteSpeed, W3TC, and object caches.`,
      confirmLabel: 'Rollback & Flush Caches',
      variant: 'warning'
    });

    if (!confirmed) return;

    setRestoringVersion(version);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/restore',
        method: 'POST',
        data: { version }
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || `Root .htaccess successfully restored from Snapshot #${version} and all page caches purged.`
        });
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Snapshot restoration failed.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Restoration request error.' });
    } finally {
      setRestoringVersion(null);
    }
  };

  const handleToggleLock = async () => {
    const nextLocked = !status?.is_read_only_locked;
    setTogglingLock(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/lock',
        method: 'POST',
        data: { locked: nextLocked }
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message
        });
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to toggle .htaccess lock.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Lock toggle error.' });
    } finally {
      setTogglingLock(false);
    }
  };

  const handleToggleAutoHeal = async () => {
    const nextAutoHeal = !status?.auto_heal_enabled;
    setTogglingAutoHeal(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/lock',
        method: 'POST',
        data: { auto_heal: nextAutoHeal }
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: nextAutoHeal
            ? 'Strict 3-Condition Auto-Heal enabled. Tampered .htaccess will automatically self-heal from the vault if confirmed by out-of-band canaries.'
            : 'Auto-Heal set to Alert-Only mode. Threats will trigger real-time notifications with 1-click restore buttons.'
        });
        await fetchStatus();
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Auto-heal toggle error.' });
    } finally {
      setTogglingAutoHeal(false);
    }
  };

  const handleHealUrls = async () => {
    const confirmed = await showConfirm({
      title: 'Restore Database Core URLs?',
      message: 'Restore siteurl and home in wp_options to the cryptographically signed baseline? This eliminates database URL hijacking immediately.',
      confirmLabel: 'Restore Baseline URLs',
      variant: 'danger'
    });

    if (!confirmed) return;

    setHealingUrls(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/heal-urls',
        method: 'POST'
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Core WordPress siteurl and home restored to verified baseline.'
        });
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Database URL recovery failed.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Database URL recovery error.' });
    } finally {
      setHealingUrls(false);
    }
  };

  const handleGenerateStandardHtaccess = async () => {
    setRestoringVersion(1);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/restore',
        method: 'POST',
        data: { version: 1 }
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: 'Standard WordPress .htaccess successfully generated and active!'
        });
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to generate standard .htaccess.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Generation error.' });
    } finally {
      setRestoringVersion(null);
    }
  };

  const handleCreateSnapshot = async () => {
    if (status && !status.is_htaccess_active) {
      setFeedback({
        type: 'warning',
        message: 'No .htaccess file present in root directory. Click "Generate Standard .htaccess" to create one first.'
      });
      return;
    }
    setCreatingSnapshot(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/redirect-shield/snapshot',
        method: 'POST'
      });
      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Current clean .htaccess backed up to dual-medium vault.'
        });
        await fetchStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Vault snapshot failed.'
        });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Snapshot error.' });
    } finally {
      setCreatingSnapshot(false);
    }
  };

  const isHostile = probeReport?.is_hostile || (status?.analysis?.hostile_count > 0) || (status?.database_urls && !status.database_urls.clean);

  const getProbeStatus = (probeKey: string) => {
    const probe = probeReport?.probes?.[probeKey] || status?.canary_state?.last_report?.probes?.[probeKey];
    if (!probe) {
      return { code: 200, isClean: true, latency: 0, label: 'Clean' };
    }
    const findingsList = probeReport?.findings || status?.canary_state?.last_report?.findings || [];
    const hasFinding = findingsList.some((f: any) => f.probe === probeKey);
    const isClean = !hasFinding && !probe.error && (!probe.is_redirect || probeKey === 'probe_d');
    return {
      code: probe.status_code || 200,
      isClean,
      latency: probe.latency_ms || 0,
      label: isClean ? 'Clean' : 'Threat'
    };
  };

  const probeA = getProbeStatus('probe_a');
  const probeB = getProbeStatus('probe_b');
  const probeC = getProbeStatus('probe_c');
  const probeD = getProbeStatus('probe_d');
  const probeE = getProbeStatus('probe_e');

  return (
    <div className="webcare-redirect-shield-card">
      {/* Hero Header */}
      <div className="webcare-microwaf-header">
        <div className="webcare-microwaf-header-info">
          <div className="webcare-microwaf-icon-box" style={{ background: isHostile ? 'linear-gradient(135deg, #ea580c 0%, #dc2626 100%)' : 'linear-gradient(135deg, #059669 0%, #0d9488 100%)' }}>
            {isHostile ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
          </div>
          <div>
            <div className="webcare-microwaf-title-row">
              <h3 className="webcare-microwaf-title">Zero-Day Redirect Hack Defense &amp; .htaccess Armor</h3>
              <div className="webcare-microwaf-status-badges">
                {!status?.is_htaccess_active ? (
                  <span className="webcare-badge-pill webcare-badge-warning">
                    <AlertTriangle size={12} />
                    File Missing (.htaccess)
                  </span>
                ) : isHostile ? (
                  <span className="webcare-badge-pill webcare-badge-danger">
                    <ShieldAlert size={12} />
                    Redirect Threat Active
                  </span>
                ) : (
                  <span className="webcare-badge-pill webcare-badge-clean">
                    <CheckCircle2 size={12} />
                    All Probes Clean
                  </span>
                )}

                <span className={`webcare-badge-pill ${status?.is_read_only_locked ? 'webcare-badge-info' : 'webcare-badge-warning'}`}>
                  {status?.is_read_only_locked ? <Lock size={12} /> : <Unlock size={12} />}
                  Permissions: {status?.is_read_only_locked ? '0444 (Read-Only Locked)' : '0644 (Writable)'}
                </span>

                <span className={`webcare-badge-pill ${status?.auto_heal_enabled ? 'webcare-badge-clean' : 'webcare-badge-muted'}`}>
                  <Zap size={12} />
                  Auto-Heal: {status?.auto_heal_enabled ? 'Active (Self-Defense)' : 'Alert-Only'}
                </span>

                {status?.database_urls && !status.database_urls.clean && (
                  <span className="webcare-badge-pill webcare-badge-danger">
                    <Database size={12} />
                    Database URLs Tampered!
                  </span>
                )}
              </div>
            </div>
            <p className="webcare-microwaf-desc">
              Protects WordPress against Balada Injector, search engine cloaking, mobile redirect malware, and rogue .htaccess rules.
              Features out-of-band synthetic canaries, a 5-version rolling cryptographic vault, and strict compatibility with caching plugins (WP Rocket, LiteSpeed, W3TC, Yoast).
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {!status?.is_htaccess_active && (
            <button
              type="button"
              className="webcare-btn"
              style={{
                fontSize: '12px',
                padding: '6px 14px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                color: '#ffffff',
                border: '1px solid #059669',
                fontWeight: 700,
                boxShadow: '0 2px 6px rgba(16, 185, 129, 0.3)',
              }}
              onClick={handleGenerateStandardHtaccess}
              disabled={restoringVersion !== null}
            >
              <RotateCcw size={14} className={restoringVersion === 1 ? 'webcare-spin' : ''} />
              <span>{restoringVersion === 1 ? 'Generating...' : '⚡ Generate Standard .htaccess'}</span>
            </button>
          )}

          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            style={{ fontSize: '12px', padding: '6px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            onClick={handleRunCanary}
            disabled={probing}
          >
            <RefreshCw size={14} className={probing ? 'webcare-spin' : ''} />
            <span>{probing ? 'Simulating 5 Probes...' : 'Run Canary Probes Now'}</span>
          </button>

          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            onClick={handleCreateSnapshot}
            disabled={creatingSnapshot}
          >
            <History size={14} />
            <span>{creatingSnapshot ? 'Backing up...' : 'Snapshot .htaccess to Vault'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className={`webcare-notice-banner ${feedback.type === 'success' ? 'is-success' : (feedback.type === 'warning' ? 'is-warning' : 'is-error')}`} style={{ margin: '8px 0' }}>
          {feedback.type === 'success' ? <Check size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Database URL Tampering Alert Banner */}
      {status?.database_urls && !status.database_urls.clean && (
        <div className="webcare-notice-banner is-error" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Database size={18} color="#dc2626" />
            <div>
              <strong>Database Core URL Hijacking Detected: </strong>
              <span>{status.database_urls.message}</span>
            </div>
          </div>
          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            style={{ background: '#dc2626', borderColor: '#b91c1c', fontSize: '11.5px', padding: '4px 12px' }}
            onClick={handleHealUrls}
            disabled={healingUrls}
          >
            <RotateCcw size={13} />
            <span>{healingUrls ? 'Healing...' : '1-Click Restore Core URLs'}</span>
          </button>
        </div>
      )}

      {/* Grid: Telemetry & Status Cards */}
      <div className="webcare-microwaf-grid">
        <div className="webcare-microwaf-metric-tile">
          <span className="webcare-microwaf-metric-label">Live .htaccess Integrity</span>
          <div className="webcare-microwaf-metric-val">
            {!status?.is_htaccess_active ? (
              <>
                <AlertTriangle size={16} color="#f59e0b" />
                <span style={{ color: '#f59e0b' }}>File Missing</span>
              </>
            ) : status?.analysis?.hostile_count > 0 ? (
              <>
                <ShieldAlert size={16} color="#dc2626" />
                <span style={{ color: '#dc2626' }}>Score: {status.analysis.score} (Hostile)</span>
              </>
            ) : (
              <>
                <ShieldCheck size={16} color="#16a34a" />
                <span style={{ color: '#16a34a' }}>Clean (Score: 0)</span>
              </>
            )}
          </div>
          <span className="webcare-microwaf-metric-sub">
            {!status?.is_htaccess_active
              ? 'Root .htaccess not found on disk. Click Generate to restore canonical WordPress routing.'
              : (status?.analysis?.summary || 'Standard WordPress permalink structure')}
          </span>
        </div>

        <div className="webcare-microwaf-metric-tile">
          <span className="webcare-microwaf-metric-label">Out-of-Band Canary Sentinel</span>
          <div className="webcare-microwaf-metric-val">
            {probeReport?.is_hostile ? (
              <span style={{ color: '#dc2626' }}>Redirection Detected!</span>
            ) : (
              <span>5 / 5 Vectors Passing</span>
            )}
          </div>
          <span className="webcare-microwaf-metric-sub">
            Next cron inspection: {status?.next_canary_human || 'Every 15 minutes'}
          </span>
        </div>

        <div className="webcare-microwaf-metric-tile">
          <span className="webcare-microwaf-metric-label">Armor Lock &amp; Permissions</span>
          <div className="webcare-microwaf-metric-val" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>{status?.is_read_only_locked ? '0444 Read-Only' : '0644 Standard'}</span>
            <button
              type="button"
              className="webcare-btn-micro"
              style={{ fontSize: '11px', padding: '3px 8px' }}
              onClick={handleToggleLock}
              disabled={togglingLock}
            >
              {status?.is_read_only_locked ? 'Unlock for Plugins' : 'Lock (0444)'}
            </button>
          </div>
          <span className="webcare-microwaf-metric-sub">
            {status?.is_read_only_locked ? 'Processes cannot edit .htaccess' : 'Permits WP Rocket / Yoast updates'}
          </span>
        </div>

        <div className="webcare-microwaf-metric-tile">
          <span className="webcare-microwaf-metric-label">3-Condition Auto-Heal</span>
          <div className="webcare-microwaf-metric-val" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: status?.auto_heal_enabled ? '#16a34a' : 'inherit' }}>
              {status?.auto_heal_enabled ? 'Auto-Restore Active' : 'Alert Only'}
            </span>
            <button
              type="button"
              className="webcare-btn-micro"
              style={{ fontSize: '11px', padding: '3px 8px' }}
              onClick={handleToggleAutoHeal}
              disabled={togglingAutoHeal}
            >
              {status?.auto_heal_enabled ? 'Disable' : 'Enable'}
            </button>
          </div>
          <span className="webcare-microwaf-metric-sub">
            Auto-reverts only on verified external cloaking
          </span>
        </div>
      </div>

      {/* Interactive 5-Vector Canary Simulator */}
      <div style={{ marginTop: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <h4 style={{ margin: 0, fontSize: '13.5px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Globe size={15} color="#0284c7" />
            Out-of-Band Synthetic Canary Simulation (Search Cloaking, Mobile &amp; AI Vector Probes)
          </h4>
          <span style={{ fontSize: '11px', color: '#64748b' }}>
            Probes site with residential simulation &amp; DOM diffing
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
          {/* Probe A: Desktop Direct */}
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', margin: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Globe size={14} color="#64748b" /> Probe A: Desktop Direct
              </span>
              <span className={`webcare-badge-pill ${probeA.isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                {probeA.code} {probeA.label}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              Direct browser visit. Baseline DOM and script inventory snapshot ({probeA.latency}ms).
            </div>
          </div>

          {/* Probe B: Googlebot & Search Referer */}
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', margin: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Search size={14} color="#0284c7" /> Probe B: Google Search
              </span>
              <span className={`webcare-badge-pill ${probeB.isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                {probeB.code} {probeB.label}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              Referer: google.com. Catches SEO spam cloaking &amp; Google visitor diversion ({probeB.latency}ms).
            </div>
          </div>

          {/* Probe C: Mobile Device & Search Referer */}
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', margin: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Smartphone size={14} color="#7c3aed" /> Probe C: Mobile Safari
              </span>
              <span className={`webcare-badge-pill ${probeC.isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                {probeC.code} {probeC.label}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              iPhone Safari UA + Google Referer. Detects mobile-only TDS redirections ({probeC.latency}ms).
            </div>
          </div>

          {/* Probe D: Admin Gatekeeper */}
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', margin: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Lock size={14} color="#d97706" /> Probe D: Admin Gatekeeper
              </span>
              <span className={`webcare-badge-pill ${probeD.isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                {probeD.code} {probeD.isClean ? 'Clean (Local)' : 'External Redirect!'}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              Probes /wp-admin/. Ensures local wp-login.php auth is not diverted to foreign phishing gates.
            </div>
          </div>

          {/* Probe E: AI Search Discovery */}
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', margin: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Bot size={14} color="#059669" /> Probe E: AI Search
              </span>
              <span className={`webcare-badge-pill ${probeE.isClean ? 'webcare-badge-clean' : 'webcare-badge-danger'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                {probeE.code} {probeE.label}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              Referer: chatgpt.com &amp; perplexity.ai. Prevents AI crawler cloaking hijacks ({probeE.latency}ms).
            </div>
          </div>
        </div>
      </div>

      {/* 5-Version Rolling Vault Snapshots */}
      <div style={{ marginTop: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <h4 style={{ margin: 0, fontSize: '13.5px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <History size={15} color="#4f46e5" />
            .htaccess Cryptographic Vault (Dual-Medium: Disk .vault/ + Encrypted Database Mirror)
          </h4>
          <span style={{ fontSize: '11px', color: '#64748b' }}>
            Rolling 5 versions with automatic cache invalidation
          </span>
        </div>

        {status?.snapshots && status.snapshots.length > 0 ? (
          <div className="webcare-waf-table-card" style={{ overflowX: 'auto', border: '1px solid var(--webcare-border-table)' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--webcare-border-table)' }}>
                  <th style={{ padding: '8px 12px' }}>Snapshot Version</th>
                  <th style={{ padding: '8px 12px' }}>Timestamp</th>
                  <th style={{ padding: '8px 12px' }}>Trigger Reason</th>
                  <th style={{ padding: '8px 12px' }}>Size</th>
                  <th style={{ padding: '8px 12px' }}>Fingerprint (SHA-256)</th>
                  <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {status.snapshots.map((snap: any) => (
                  <tr key={snap.version} style={{ borderBottom: '1px solid var(--webcare-border-table)' }}>
                    <td style={{ padding: '8px 12px', fontWeight: 600 }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                        <FileCode size={13} color="#4f46e5" />
                        Version #{snap.version} {snap.version === 1 && <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '9.5px', padding: '0 5px' }}>Latest</span>}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', color: '#64748b' }}>
                      {snap.created_at_human || snap.created_at || 'Just now'}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span className="webcare-badge-pill webcare-badge-muted" style={{ fontSize: '10px' }}>
                        {snap.reason || 'Auto Baseline'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      {snap.size_bytes ? `${snap.size_bytes} B` : 'Standard'}
                    </td>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: '11px', color: '#0284c7' }}>
                      {snap.hash ? `${snap.hash.substring(0, 12)}...` : 'N/A'}
                    </td>
                    <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="webcare-btn-micro"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#ecfdf5', color: '#059669', borderColor: '#a7f3d0' }}
                        onClick={() => handleRestoreSnapshot(snap.version)}
                        disabled={restoringVersion !== null}
                      >
                        <RotateCcw size={12} />
                        <span>{restoringVersion === snap.version ? 'Restoring...' : 'Rollback & Purge Caches'}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="webcare-firewall-rule-card" style={{ padding: '16px', textAlign: 'center', color: '#64748b' }}>
            <Info size={16} style={{ display: 'inline', marginRight: '6px' }} />
            No previous snapshots in vault. Click <strong>Snapshot .htaccess to Vault</strong> to create your first protected backup.
          </div>
        )}
      </div>

      {/* Legitimate Plugin Harmony Reassurance */}
      <div style={{ marginTop: '14px', padding: '10px 14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border-table)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Layers size={16} color="#059669" />
          <span style={{ fontSize: '11.5px', color: '#475569' }}>
            <strong>Legitimate Plugin Harmony: </strong>
            WP Rocket, LiteSpeed Cache, W3 Total Cache, Yoast SEO, and Rank Math rewrite blocks are audited inside vendor markers and safely preserved without false alarms or permission lock conflicts.
          </span>
        </div>
        <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px' }}>
          100% Coexistence
        </span>
      </div>
    </div>
  );
};
