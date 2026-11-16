import React, { useState, useEffect } from 'react';
import {
  X,
  SlidersHorizontal,
  Sliders,
  Clock,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Server,
  Filter,
  Database,
  Save,
  Play,
  RotateCcw,
  Info,
  HelpCircle,
  FolderTree,
  Cpu,
  Layers,
  Lock,
  Check,
  Loader2,
  Gauge,
  Sparkles,
  Workflow,
  Terminal,
  ShoppingBag,
  Rocket
} from 'lucide-react';

export interface ScanOptionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onStartScan?: (target?: 'plugins_themes' | 'full' | 'custom', options?: Record<string, boolean>) => Promise<void>;
  showGlobalToast?: (type: 'success' | 'error' | 'warning' | 'info', message: string) => void;
  isScanning?: boolean;
}

interface ScanSettingsState {
  // Performance & Visitor Safety
  scan_batch_size: number;
  scan_memory_safety_envelope: string;
  scan_adaptive_throttling: boolean;
  scan_batch_delay_ms: number;
  memory_limit_override: string;
  max_file_size_kb: number;
  scan_uploads_mode: string;
  auto_quarantine_critical: boolean;

  // Scheduled Scans & Automation
  schedule_enabled: boolean;
  schedule_frequency: string;
  schedule_time: string;
  schedule_scan_type: string;
  scan_execution_strategy: string;

  // Exclusions & Traversal
  excluded_paths: string;
  scan_excluded_tables: string;
  scan_db_batch_size: number;
  scan_symlink_policy: string;
  scan_skip_vcs: boolean;
  scan_skip_vendor: boolean;
  scan_skip_cache: boolean;

  // Developer & Staging
  scan_dry_run_mode: boolean;
  scan_profiling_enabled: boolean;
}

const DEFAULT_SCAN_SETTINGS: ScanSettingsState = {
  scan_batch_size: 50,
  scan_memory_safety_envelope: 'balanced',
  scan_adaptive_throttling: true,
  scan_batch_delay_ms: 0,
  memory_limit_override: '512M',
  max_file_size_kb: 1024,
  scan_uploads_mode: 'smart_executable',
  auto_quarantine_critical: false,

  schedule_enabled: true,
  schedule_frequency: 'daily',
  schedule_time: '02:00',
  schedule_scan_type: 'plugins_themes',
  scan_execution_strategy: 'ajax_client',

  excluded_paths: 'wp-content/cache/*\nnode_modules/*\n*.log\n.hidden-custom-dir/*',
  scan_excluded_tables: 'wp_actionscheduler_logs\nwp_redirection_logs\n*_wfhits',
  scan_db_batch_size: 500,
  scan_symlink_policy: 'ignore',
  scan_skip_vcs: true,
  scan_skip_vendor: true,
  scan_skip_cache: true,

  scan_dry_run_mode: false,
  scan_profiling_enabled: false,
};

export const ScanOptionsModal: React.FC<ScanOptionsModalProps> = ({
  isOpen,
  onClose,
  apiRequest,
  onStartScan,
  showGlobalToast,
  isScanning = false,
}) => {
  const [activeTab, setActiveTab] = useState<'performance' | 'schedule' | 'exclusions' | 'developer'>('performance');
  const [settings, setSettings] = useState<ScanSettingsState>(DEFAULT_SCAN_SETTINGS);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [startingScan, setStartingScan] = useState<boolean>(false);
  const [scheduleTimeInfo, setScheduleTimeInfo] = useState<{ timezone?: string; current_wp_time?: string } | null>(null);
  const [activePreset, setActivePreset] = useState<'recommended' | 'shared_woocommerce' | 'turbo_vps' | 'custom'>('recommended');
  const [serverMemoryLimit, setServerMemoryLimit] = useState<string>('256M');

  // Load settings on open
  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    setLoading(true);

    apiRequest({ path: '/webcare-pro-security/v1/settings' })
      .then((res: any) => {
        if (!isMounted) return;
        if (res && res.settings) {
          const s = res.settings;
          const loaded: ScanSettingsState = {
            scan_batch_size: parseInt(s.scan_batch_size) || DEFAULT_SCAN_SETTINGS.scan_batch_size,
            scan_memory_safety_envelope: s.scan_memory_safety_envelope || DEFAULT_SCAN_SETTINGS.scan_memory_safety_envelope,
            scan_adaptive_throttling: s.scan_adaptive_throttling !== false,
            scan_batch_delay_ms: s.scan_batch_delay_ms !== undefined ? parseInt(s.scan_batch_delay_ms) : DEFAULT_SCAN_SETTINGS.scan_batch_delay_ms,
            memory_limit_override: s.memory_limit_override || DEFAULT_SCAN_SETTINGS.memory_limit_override,
            max_file_size_kb: parseInt(s.max_file_size_kb) || DEFAULT_SCAN_SETTINGS.max_file_size_kb,
            scan_uploads_mode: s.scan_uploads_mode || DEFAULT_SCAN_SETTINGS.scan_uploads_mode,
            auto_quarantine_critical: Boolean(s.auto_quarantine_critical),

            schedule_enabled: s.schedule_enabled !== false,
            schedule_frequency: s.schedule_frequency || DEFAULT_SCAN_SETTINGS.schedule_frequency,
            schedule_time: s.schedule_time || DEFAULT_SCAN_SETTINGS.schedule_time,
            schedule_scan_type: s.schedule_scan_type || DEFAULT_SCAN_SETTINGS.schedule_scan_type,
            scan_execution_strategy: s.scan_execution_strategy || DEFAULT_SCAN_SETTINGS.scan_execution_strategy,

            excluded_paths: s.excluded_paths !== undefined ? s.excluded_paths : DEFAULT_SCAN_SETTINGS.excluded_paths,
            scan_excluded_tables: s.scan_excluded_tables !== undefined ? s.scan_excluded_tables : DEFAULT_SCAN_SETTINGS.scan_excluded_tables,
            scan_db_batch_size: parseInt(s.scan_db_batch_size) || DEFAULT_SCAN_SETTINGS.scan_db_batch_size,
            scan_symlink_policy: s.scan_symlink_policy || DEFAULT_SCAN_SETTINGS.scan_symlink_policy,
            scan_skip_vcs: s.scan_skip_vcs !== false,
            scan_skip_vendor: s.scan_skip_vendor !== false,
            scan_skip_cache: s.scan_skip_cache !== false,

            scan_dry_run_mode: Boolean(s.scan_dry_run_mode),
            scan_profiling_enabled: Boolean(s.scan_profiling_enabled),
          };

          setSettings(loaded);
          detectPreset(loaded);

          if (res.schedule_time_info) {
            setScheduleTimeInfo(res.schedule_time_info);
          }
          if (res.server_environment?.memory_limit) {
            setServerMemoryLimit(res.server_environment.memory_limit);
          }
        }
      })
      .catch((err: any) => {
        console.error('Failed to load scan options:', err);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !saving && !startingScan) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, saving, startingScan, onClose]);

  const detectPreset = (s: ScanSettingsState) => {
    if (
      s.scan_batch_size === 50 &&
      s.scan_memory_safety_envelope === 'balanced' &&
      s.scan_adaptive_throttling === true &&
      s.scan_batch_delay_ms === 0
    ) {
      setActivePreset('recommended');
    } else if (
      s.scan_batch_size === 25 &&
      s.scan_memory_safety_envelope === 'strict' &&
      s.scan_batch_delay_ms >= 100
    ) {
      setActivePreset('shared_woocommerce');
    } else if (
      s.scan_batch_size >= 100 &&
      s.scan_memory_safety_envelope === 'performance' &&
      s.scan_batch_delay_ms === 0
    ) {
      setActivePreset('turbo_vps');
    } else {
      setActivePreset('custom');
    }
  };

  const applyPreset = (preset: 'recommended' | 'shared_woocommerce' | 'turbo_vps') => {
    setActivePreset(preset);
    if (preset === 'recommended') {
      setSettings((prev) => ({
        ...prev,
        scan_batch_size: 50,
        scan_memory_safety_envelope: 'balanced',
        scan_adaptive_throttling: true,
        scan_batch_delay_ms: 0,
        memory_limit_override: '512M',
        max_file_size_kb: 1024,
        scan_uploads_mode: 'smart_executable',
        scan_symlink_policy: 'ignore',
        scan_skip_vcs: true,
        scan_skip_vendor: true,
        scan_skip_cache: true,
        scan_db_batch_size: 500,
      }));
    } else if (preset === 'shared_woocommerce') {
      setSettings((prev) => ({
        ...prev,
        scan_batch_size: 25,
        scan_memory_safety_envelope: 'strict',
        scan_adaptive_throttling: true,
        scan_batch_delay_ms: 150,
        memory_limit_override: '256M',
        max_file_size_kb: 512,
        scan_uploads_mode: 'smart_executable',
        scan_symlink_policy: 'ignore',
        scan_skip_vcs: true,
        scan_skip_vendor: true,
        scan_skip_cache: true,
        scan_db_batch_size: 250,
      }));
    } else if (preset === 'turbo_vps') {
      setSettings((prev) => ({
        ...prev,
        scan_batch_size: 100,
        scan_memory_safety_envelope: 'performance',
        scan_adaptive_throttling: false,
        scan_batch_delay_ms: 0,
        memory_limit_override: '1024M',
        max_file_size_kb: 2048,
        scan_uploads_mode: 'deep_raster',
        scan_symlink_policy: 'follow_intree',
        scan_skip_vcs: true,
        scan_skip_vendor: true,
        scan_skip_cache: true,
        scan_db_batch_size: 1000,
      }));
    }
  };

  const handleResetDefaults = () => {
    if (window.confirm('Reset all scan options to factory-recommended defaults?')) {
      setSettings(DEFAULT_SCAN_SETTINGS);
      setActivePreset('recommended');
    }
  };

  const handleSave = async (andStartScan = false) => {
    if (andStartScan) {
      setStartingScan(true);
    } else {
      setSaving(true);
    }

    try {
      await apiRequest({
        path: '/webcare-pro-security/v1/settings',
        method: 'POST',
        data: settings,
      });

      if (showGlobalToast) {
        showGlobalToast('success', 'Scan options saved successfully.');
      }

      if (andStartScan && onStartScan) {
        onClose();
        await onStartScan();
      } else {
        onClose();
      }
    } catch (err: any) {
      console.error('Failed to save scan options:', err);
      if (showGlobalToast) {
        showGlobalToast('error', err?.message || 'Failed to save scan options.');
      }
    } finally {
      setSaving(false);
      setStartingScan(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="webcare-modal-backdrop webcare-scan-options-backdrop"
      style={{
        zIndex: 9999999,
        position: 'fixed',
        inset: 0,
        background: 'rgba(9, 13, 22, 0.85)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        overflowY: 'auto',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !saving && !startingScan) {
          onClose();
        }
      }}
    >
      <div
        className="webcare-modal-window webcare-scan-options-window"
        style={{
          width: '100%',
          maxWidth: '880px',
          maxHeight: '92vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'webcareFadeIn 0.2s ease-out',
        }}
      >
        {/* Header */}
        <div
          className="webcare-scan-options-header"
          style={{
            padding: '20px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '16px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              className="webcare-scan-options-iconbox"
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <SlidersHorizontal size={22} color="#0284c7" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <h2 className="webcare-scan-options-title" style={{ margin: 0, fontSize: '18px', fontWeight: 800, letterSpacing: '-0.3px' }}>
                  Scan Options &amp; Governor Settings
                </h2>
                <span className="webcare-scan-options-pill">
                  {activePreset === 'recommended' ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Sparkles size={11} /> Recommended Profile
                    </span>
                  ) : activePreset === 'shared_woocommerce' ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <ShoppingBag size={11} /> Store &amp; Shared Profile
                    </span>
                  ) : activePreset === 'turbo_vps' ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Zap size={11} /> Turbo VPS Profile
                    </span>
                  ) : (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Sliders size={11} /> Custom Tuning
                    </span>
                  )}
                </span>
                {settings.scan_adaptive_throttling && (
                  <span className="webcare-scan-options-pill-shield">
                    <ShieldCheck size={11} /> Visitor Shield Active
                  </span>
                )}
              </div>
              <p className="webcare-scan-options-subtitle" style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                Configure memory envelopes, pacing micro-sleeps, background scheduling, and path exclusions without leaving the scanner.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={saving || startingScan}
            className="webcare-scan-options-close-btn"
            style={{
              borderRadius: '8px',
              padding: '6px',
              cursor: saving || startingScan ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Quick Presets Strip (Ideal for Non-Tech Owners & Developers) */}
        <div className="webcare-scan-options-preset-bar">
          <div className="webcare-scan-options-preset-label">
            <Sparkles size={13} color="#0284c7" />
            <span>Quick Optimization Profiles:</span>
          </div>
          <div className="webcare-scan-options-preset-grid">
            <button
              type="button"
              className={`webcare-scan-options-preset-chip ${activePreset === 'recommended' ? 'is-active' : ''}`}
              onClick={() => applyPreset('recommended')}
              title="Balanced 70% memory envelope, 50 files/batch, 0ms delay. Ideal for 90% of sites."
            >
              <Rocket size={13} />
              <span>Recommended (Balanced)</span>
              {activePreset === 'recommended' && <Check size={12} strokeWidth={3} />}
            </button>

            <button
              type="button"
              className={`webcare-scan-options-preset-chip ${activePreset === 'shared_woocommerce' ? 'is-active' : ''}`}
              onClick={() => applyPreset('shared_woocommerce')}
              title="Strict 60% memory, 25 files/batch, 150ms micro-pause. Preserves 40% RAM for active shoppers, zero 500 errors."
            >
              <ShoppingBag size={13} />
              <span>Shared Host / WooCommerce</span>
              {activePreset === 'shared_woocommerce' && <Check size={12} strokeWidth={3} />}
            </button>

            <button
              type="button"
              className={`webcare-scan-options-preset-chip ${activePreset === 'turbo_vps' ? 'is-active' : ''}`}
              onClick={() => applyPreset('turbo_vps')}
              title="Turbo scan 100 files/batch, 80% RAM budget, 0ms delay. High-speed audit for Dedicated & Cloud VPS."
            >
              <Zap size={13} />
              <span>Turbo VPS / Dedicated</span>
              {activePreset === 'turbo_vps' && <Check size={12} strokeWidth={3} />}
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="webcare-scan-options-tabs">
          <button
            type="button"
            className={`webcare-scan-options-tab-btn ${activeTab === 'performance' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('performance')}
          >
            <Gauge size={14} />
            <span>Performance &amp; Visitor Uptime</span>
          </button>

          <button
            type="button"
            className={`webcare-scan-options-tab-btn ${activeTab === 'schedule' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('schedule')}
          >
            <Clock size={14} />
            <span>Scheduled Scans &amp; Automation</span>
          </button>

          <button
            type="button"
            className={`webcare-scan-options-tab-btn ${activeTab === 'exclusions' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('exclusions')}
          >
            <Filter size={14} />
            <span>Exclusions &amp; Paths</span>
          </button>

          <button
            type="button"
            className={`webcare-scan-options-tab-btn ${activeTab === 'developer' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('developer')}
          >
            <Terminal size={14} />
            <span>Developer Diagnostics</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="webcare-scan-options-body webcare-custom-scan-scroll">
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 20px', gap: '12px' }}>
              <Loader2 size={32} className="webcare-spin-icon" color="#0284c7" />
              <span style={{ fontSize: '14px', color: 'var(--webcare-text-secondary, #64748b)' }}>Loading scan options...</span>
            </div>
          ) : (
            <>
              {/* ==============================================================
                  TAB 1: PERFORMANCE & VISITOR UPTIME
                  ============================================================== */}
              {activeTab === 'performance' && (
                <div className="webcare-scan-options-section-grid">
                  {/* Visitor Uptime Notice */}
                  <div className="webcare-scan-options-callout">
                    <ShieldCheck size={18} color="#059669" />
                    <div>
                      <strong>Visitor Uptime &amp; Zero 500 Error Guarantee</strong>
                      <p>
                        The scanner dynamically monitors server RAM. By reserving 20% to 40% of memory for web visitors, your site remains 100% responsive and checkout-ready even during deep malware scans.
                      </p>
                    </div>
                  </div>

                  {/* Batch Size & Memory Envelope */}
                  <div className="webcare-scan-options-field-row">
                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Scan Batch Size (Files per request)</span>
                        <span className="webcare-scan-options-hint">Controls chunk size processed per REST step</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_batch_size}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_batch_size: parseInt(e.target.value) || 50 });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="25">25 files / batch (Recommended for shared/low-memory hosting)</option>
                        <option value="50">50 files / batch (Standard, Balanced - Default)</option>
                        <option value="100">100 files / batch (High Performance VPS/Dedicated)</option>
                        <option value="200">200 files / batch (Turbo scan - High RAM)</option>
                      </select>
                    </div>

                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Dynamic Memory Safety Envelope</span>
                        <span className="webcare-scan-options-hint">Permanently reserves RAM for visitors</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_memory_safety_envelope || 'balanced'}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_memory_safety_envelope: e.target.value });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="strict">Strict Safety (60% Max Memory - Best for busy WooCommerce stores &amp; shared hosting)</option>
                        <option value="balanced">Balanced Protection (70% Max Memory - Recommended, dynamically scales batch size)</option>
                        <option value="performance">High Performance (80% Max Memory - Dedicated servers &amp; high RAM environments)</option>
                      </select>
                    </div>
                  </div>

                  {/* Adaptive Throttling Toggle */}
                  <div className="webcare-scan-options-toggle-card">
                    <div className="webcare-scan-options-toggle-info">
                      <div className="webcare-scan-options-toggle-title">
                        <span>Real-Time Visitor Traffic Throttling (Micro-Sleeps &amp; Downscaling)</span>
                        <span className="webcare-badge-pill webcare-badge-clean">Uptime Shield</span>
                      </div>
                      <p className="webcare-scan-options-toggle-desc">
                        Automatically scales down batch size and injects micro-sleep pauses when visitor traffic spikes or server RAM is tight, resuming turbo speed once memory frees.
                      </p>
                    </div>
                    <label className="webcare-toggle-switch">
                      <input
                        type="checkbox"
                        checked={settings.scan_adaptive_throttling}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_adaptive_throttling: e.target.checked });
                          setActivePreset('custom');
                        }}
                      />
                      <span className="webcare-toggle-slider" />
                    </label>
                  </div>

                  {/* CPU Throttle Delay & Memory Override */}
                  <div className="webcare-scan-options-field-row">
                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Inter-Batch CPU Throttle Delay (Micro-Pause)</span>
                        <span className="webcare-scan-options-hint">Prevents hosting provider CPU limit alerts</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_batch_delay_ms ?? 0}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_batch_delay_ms: parseInt(e.target.value) || 0 });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="0">0 ms (Full Turbo Speed - Cloud VPS &amp; Dedicated)</option>
                        <option value="50">50 ms (Mild Breathing Room - Standard Cloud)</option>
                        <option value="150">150 ms (Balanced - Shared Hosting / cPanel CloudLinux)</option>
                        <option value="300">300 ms (Strict CPU Throttling - Low vCPU / Budget Hosts)</option>
                        <option value="500">500 ms (Maximum Resource Preservation)</option>
                      </select>
                    </div>

                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Temporary PHP Memory Limit Override</span>
                        <span className="webcare-scan-options-hint">Active during scan execution only</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.memory_limit_override}
                        onChange={(e) => {
                          setSettings({ ...settings, memory_limit_override: e.target.value });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="256M">256 MB (Standard)</option>
                        <option value="512M">512 MB (Recommended)</option>
                        <option value="1024M">1024 MB (1 GB - Heavy Sites / Deep Full-Tree)</option>
                      </select>
                    </div>
                  </div>

                  {/* Uploads Scan Depth & Max File Size */}
                  <div className="webcare-scan-options-field-row">
                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Media Uploads Library Scan Depth</span>
                        <span className="webcare-scan-options-hint">Smart mode skips millions of benign images</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_uploads_mode || 'smart_executable'}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_uploads_mode: e.target.value });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="smart_executable">Smart Executable &amp; Stager Inspection (Recommended - 10x faster, inspects scripts &amp; disguised icons)</option>
                        <option value="deep_raster">Deep Raster &amp; EXIF Polyglot Audit (Thorough, inspects raw image headers &amp; trailing bytes)</option>
                      </select>
                    </div>

                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Max File Size for Heuristic Parsing (KB)</span>
                        <span className="webcare-scan-options-hint">Files larger than this limit skip regex heuristics</span>
                      </label>
                      <input
                        type="number"
                        className="webcare-scan-options-input"
                        value={settings.max_file_size_kb}
                        onChange={(e) => {
                          setSettings({ ...settings, max_file_size_kb: parseInt(e.target.value) || 1024 });
                          setActivePreset('custom');
                        }}
                      />
                    </div>
                  </div>

                  {/* Auto-Quarantine Critical Threats */}
                  <div className="webcare-scan-options-toggle-card">
                    <div className="webcare-scan-options-toggle-info">
                      <div className="webcare-scan-options-toggle-title">
                        <span>Automatic 1-Click Vault Quarantine on High-Confidence Malware</span>
                        <span className="webcare-badge-pill webcare-badge-warn">Optional Guard</span>
                      </div>
                      <p className="webcare-scan-options-toggle-desc">
                        When enabled, verified webshells and backdoors with 95%+ confidence are automatically neutralized and placed into the tamper-sealed quarantine vault immediately upon detection.
                      </p>
                    </div>
                    <label className="webcare-toggle-switch">
                      <input
                        type="checkbox"
                        checked={settings.auto_quarantine_critical}
                        onChange={(e) => {
                          setSettings({ ...settings, auto_quarantine_critical: e.target.checked });
                          setActivePreset('custom');
                        }}
                      />
                      <span className="webcare-toggle-slider" />
                    </label>
                  </div>
                </div>
              )}

              {/* ==============================================================
                  TAB 2: SCHEDULED SCANS & AUTOMATION
                  ============================================================== */}
              {activeTab === 'schedule' && (
                <div className="webcare-scan-options-section-grid">
                  {/* Enable Schedule Master Switch */}
                  <div className="webcare-scan-options-toggle-card is-highlighted">
                    <div className="webcare-scan-options-toggle-info">
                      <div className="webcare-scan-options-toggle-title">
                        <span>Automated Background Scheduled Scanning</span>
                        {settings.schedule_enabled ? (
                          <span className="webcare-badge-pill webcare-badge-clean">Active (WP-Cron)</span>
                        ) : (
                          <span className="webcare-badge-pill">Disabled</span>
                        )}
                      </div>
                      <p className="webcare-scan-options-toggle-desc">
                        Runs recurring security audits automatically in the background via WordPress Cron without requiring an open browser tab.
                      </p>
                    </div>
                    <label className="webcare-toggle-switch">
                      <input
                        type="checkbox"
                        checked={settings.schedule_enabled}
                        onChange={(e) => setSettings({ ...settings, schedule_enabled: e.target.checked })}
                      />
                      <span className="webcare-toggle-slider" />
                    </label>
                  </div>

                  {settings.schedule_enabled && (
                    <div className="webcare-scan-options-subcard">
                      <div className="webcare-scan-options-field-row">
                        <div className="webcare-scan-options-field">
                          <label className="webcare-scan-options-label">
                            <span>Scan Frequency</span>
                            <span className="webcare-scan-options-hint">How often background scans run</span>
                          </label>
                          <select
                            className="webcare-scan-options-select"
                            value={settings.schedule_frequency}
                            onChange={(e) => setSettings({ ...settings, schedule_frequency: e.target.value })}
                          >
                            <option value="hourly">Hourly (Intensive Security Watch)</option>
                            <option value="twicedaily">Twice Daily (Every 12 hours)</option>
                            <option value="daily">Daily (Recommended for Most Sites)</option>
                            <option value="weekly">Once Weekly</option>
                          </select>
                        </div>

                        <div className="webcare-scan-options-field">
                          <label className="webcare-scan-options-label">
                            <span>Scheduled Execution Time ({scheduleTimeInfo?.timezone || 'WordPress Time'})</span>
                            <span className="webcare-scan-options-hint">Current Site Time: {scheduleTimeInfo?.current_wp_time?.split(' ')[1] || 'Current Time'}</span>
                          </label>
                          <input
                            type="time"
                            className="webcare-scan-options-input"
                            value={settings.schedule_time}
                            onChange={(e) => setSettings({ ...settings, schedule_time: e.target.value })}
                          />
                        </div>
                      </div>

                      <div className="webcare-scan-options-field-row">
                        <div className="webcare-scan-options-field">
                          <label className="webcare-scan-options-label">
                            <span>Audit Scope (Target Profile)</span>
                            <span className="webcare-scan-options-hint">Targeted directories during scheduled runs</span>
                          </label>
                          <select
                            className="webcare-scan-options-select"
                            value={settings.schedule_scan_type}
                            onChange={(e) => setSettings({ ...settings, schedule_scan_type: e.target.value })}
                          >
                            <option value="plugins_themes">Plugins &amp; Themes (Fast, Recommended - 90% of threats)</option>
                            <option value="full">Full WordPress Installation (Deep Full-Tree Audit)</option>
                            <option value="core_integrity">WordPress Core Integrity &amp; Checksums Only</option>
                            <option value="suspicious_uploads">Uploads Folder Executables Only</option>
                          </select>
                        </div>

                        <div className="webcare-scan-options-field">
                          <label className="webcare-scan-options-label">
                            <span>Background Execution Strategy</span>
                            <span className="webcare-scan-options-hint">Dispatch mechanism for unattended processing</span>
                          </label>
                          <select
                            className="webcare-scan-options-select"
                            value={settings.scan_execution_strategy || 'ajax_client'}
                            onChange={(e) => setSettings({ ...settings, scan_execution_strategy: e.target.value })}
                          >
                            <option value="ajax_client">Interactive Client-Side Polling (Default, resilient against timeouts)</option>
                            <option value="wp_cli_cron">Autonomous WP-Cron Loop (Runs purely in background)</option>
                            <option value="background_worker">Non-Blocking Async Worker (Spawns detached worker loop)</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ==============================================================
                  TAB 3: EXCLUSIONS & PATHS
                  ============================================================== */}
              {activeTab === 'exclusions' && (
                <div className="webcare-scan-options-section-grid">
                  {/* File & Directory Exclusions */}
                  <div className="webcare-scan-options-field">
                    <label className="webcare-scan-options-label">
                      <span>Excluded Paths &amp; Ignore Patterns (One per line)</span>
                      <span className="webcare-scan-options-hint">Skips specific folders or patterns from all scans</span>
                    </label>
                    <textarea
                      rows={3}
                      className="webcare-scan-options-textarea"
                      value={settings.excluded_paths}
                      onChange={(e) => {
                        setSettings({ ...settings, excluded_paths: e.target.value });
                        setActivePreset('custom');
                      }}
                      placeholder={'wp-content/cache/*\nnode_modules/*\n*.log\ncustom-dir/*'}
                    />
                    <small className="webcare-scan-options-field-note">
                      Example: <code>wp-content/cache/*</code>, <code>custom-backup/*</code>, <code>*.log</code>
                    </small>
                  </div>

                  {/* Database Table Exclusions */}
                  <div className="webcare-scan-options-field">
                    <label className="webcare-scan-options-label">
                      <span>Database Table Exclusions (One table per line)</span>
                      <span className="webcare-scan-options-hint">Excludes bulky analytics or third-party log tables</span>
                    </label>
                    <textarea
                      rows={3}
                      className="webcare-scan-options-textarea"
                      value={settings.scan_excluded_tables || ''}
                      onChange={(e) => {
                        setSettings({ ...settings, scan_excluded_tables: e.target.value });
                        setActivePreset('custom');
                      }}
                      placeholder={'wp_actionscheduler_logs\nwp_redirection_logs\n*_wfhits'}
                    />
                  </div>

                  {/* Database Batch Size & Symlink Policy */}
                  <div className="webcare-scan-options-field-row">
                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Database Table Scan Batch Size</span>
                        <span className="webcare-scan-options-hint">Rows inspected per chunk without SQL lockups</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_db_batch_size || 500}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_db_batch_size: parseInt(e.target.value) || 500 });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="100">100 rows / chunk (Conservative - Low RAM MySQL)</option>
                        <option value="250">250 rows / chunk (Balanced)</option>
                        <option value="500">500 rows / chunk (Default - Fast)</option>
                        <option value="1000">1000 rows / chunk (Turbo - Dedicated MySQL/MariaDB)</option>
                      </select>
                    </div>

                    <div className="webcare-scan-options-field">
                      <label className="webcare-scan-options-label">
                        <span>Filesystem Symlink Traversal Policy</span>
                        <span className="webcare-scan-options-hint">Handles symbolic links &amp; composer trees</span>
                      </label>
                      <select
                        className="webcare-scan-options-select"
                        value={settings.scan_symlink_policy || 'ignore'}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_symlink_policy: e.target.value });
                          setActivePreset('custom');
                        }}
                      >
                        <option value="ignore">Ignore Symlinks (Safest - Prevents recursive loops)</option>
                        <option value="follow_intree">Follow In-Tree Symlinks (Resolving inside WordPress root)</option>
                        <option value="follow_all">Follow All Symlinks (Alerts on out-of-tree escapes)</option>
                      </select>
                    </div>
                  </div>

                  {/* Fast Skip Switches */}
                  <div className="webcare-scan-options-switches-strip">
                    <label className="webcare-scan-options-checkbox-row">
                      <input
                        type="checkbox"
                        checked={settings.scan_skip_vcs !== false}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_skip_vcs: e.target.checked });
                          setActivePreset('custom');
                        }}
                      />
                      <div className="webcare-scan-options-checkbox-text">
                        <strong>Fast-Skip VCS Repositories (<code>.git</code>, <code>.svn</code>, <code>.hg</code>)</strong>
                        <span>Bypasses deep inspection into internal git object trees to conserve scan time.</span>
                      </div>
                    </label>

                    <label className="webcare-scan-options-checkbox-row">
                      <input
                        type="checkbox"
                        checked={settings.scan_skip_vendor !== false}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_skip_vendor: e.target.checked });
                          setActivePreset('custom');
                        }}
                      />
                      <div className="webcare-scan-options-checkbox-text">
                        <strong>Skip Node.js &amp; Package Manager Dirs (<code>node_modules</code>, <code>bower_components</code>)</strong>
                        <span>Automatically skips massive nested node_modules hierarchies from scanning.</span>
                      </div>
                    </label>

                    <label className="webcare-scan-options-checkbox-row">
                      <input
                        type="checkbox"
                        checked={settings.scan_skip_cache !== false}
                        onChange={(e) => {
                          setSettings({ ...settings, scan_skip_cache: e.target.checked });
                          setActivePreset('custom');
                        }}
                      />
                      <div className="webcare-scan-options-checkbox-text">
                        <strong>Skip Static Page Builder &amp; Minification Caches</strong>
                        <span>Bypasses regular ephemeral cache folders (e.g. <code>wp-content/cache/*</code>, <code>elementor/css/*</code>).</span>
                      </div>
                    </label>
                  </div>
                </div>
              )}

              {/* ==============================================================
                  TAB 4: DEVELOPER DIAGNOSTICS & STAGING
                  ============================================================== */}
              {activeTab === 'developer' && (
                <div className="webcare-scan-options-section-grid">
                  {/* Dry Run Mode Toggle */}
                  <div className="webcare-scan-options-toggle-card">
                    <div className="webcare-scan-options-toggle-info">
                      <div className="webcare-scan-options-toggle-title">
                        <span>Developer Dry-Run Audit Mode (Testing &amp; CI/CD)</span>
                        {settings.scan_dry_run_mode && <span className="webcare-badge-pill webcare-badge-warn">Active Test Mode</span>}
                      </div>
                      <p className="webcare-scan-options-toggle-desc">
                        Runs full security scanners without updating risk scores or altering quarantine records, useful for staging environments and automated validation.
                      </p>
                    </div>
                    <label className="webcare-toggle-switch">
                      <input
                        type="checkbox"
                        checked={settings.scan_dry_run_mode}
                        onChange={(e) => setSettings({ ...settings, scan_dry_run_mode: e.target.checked })}
                      />
                      <span className="webcare-toggle-slider" />
                    </label>
                  </div>

                  {/* Profiling Toggle */}
                  <div className="webcare-scan-options-toggle-card">
                    <div className="webcare-scan-options-toggle-info">
                      <div className="webcare-scan-options-toggle-title">
                        <span>Enable Developer Scan Benchmarking &amp; Engine Profiling</span>
                        {settings.scan_profiling_enabled && <span className="webcare-badge-pill webcare-badge-info">Profiling Active</span>}
                      </div>
                      <p className="webcare-scan-options-toggle-desc">
                        Logs millisecond execution timing breakdowns per file and engine in scan diagnostics to identify performance bottlenecks.
                      </p>
                    </div>
                    <label className="webcare-toggle-switch">
                      <input
                        type="checkbox"
                        checked={settings.scan_profiling_enabled}
                        onChange={(e) => setSettings({ ...settings, scan_profiling_enabled: e.target.checked })}
                      />
                      <span className="webcare-toggle-slider" />
                    </label>
                  </div>

                  {/* Server Environment Telemetry Card */}
                  <div className="webcare-scan-options-telemetry-box">
                    <div className="webcare-scan-options-telemetry-title">
                      <Server size={15} color="#0284c7" />
                      <span>Host Environment Limits</span>
                    </div>
                    <div className="webcare-scan-options-telemetry-grid">
                      <div className="webcare-scan-options-telemetry-item">
                        <span className="webcare-telemetry-k">PHP Memory Limit:</span>
                        <strong className="webcare-telemetry-v">{serverMemoryLimit}</strong>
                      </div>
                      <div className="webcare-scan-options-telemetry-item">
                        <span className="webcare-telemetry-k">Active Override:</span>
                        <strong className="webcare-telemetry-v">{settings.memory_limit_override || 'None'}</strong>
                      </div>
                      <div className="webcare-scan-options-telemetry-item">
                        <span className="webcare-telemetry-k">Configured Safety Envelope:</span>
                        <strong className="webcare-telemetry-v" style={{ textTransform: 'capitalize' }}>
                          {settings.scan_memory_safety_envelope} (Max {settings.scan_memory_safety_envelope === 'strict' ? '60%' : settings.scan_memory_safety_envelope === 'balanced' ? '70%' : '80%'} RAM)
                        </strong>
                      </div>
                      <div className="webcare-scan-options-telemetry-item">
                        <span className="webcare-telemetry-k">Inter-Batch Delay:</span>
                        <strong className="webcare-telemetry-v">{settings.scan_batch_delay_ms} ms</strong>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="webcare-scan-options-footer">
          <div className="webcare-scan-options-footer-left">
            <button
              type="button"
              className="webcare-scan-options-reset-btn"
              onClick={handleResetDefaults}
              disabled={loading || saving || startingScan}
              title="Reset all settings to recommended defaults"
            >
              <RotateCcw size={13} />
              <span>Reset Defaults</span>
            </button>
          </div>

          <div className="webcare-scan-options-footer-right">
            <button
              type="button"
              className="webcare-scan-options-cancel-btn"
              onClick={onClose}
              disabled={saving || startingScan}
            >
              Cancel
            </button>

            <button
              type="button"
              className="webcare-scan-options-save-btn"
              onClick={() => handleSave(false)}
              disabled={loading || saving || startingScan}
            >
              {saving ? <Loader2 size={13} className="webcare-spin-icon" /> : <Save size={13} />}
              <span>{saving ? 'Saving...' : 'Save Scan Options'}</span>
            </button>

            {onStartScan && (
              <button
                type="button"
                className="webcare-scan-options-run-btn"
                onClick={() => handleSave(true)}
                disabled={loading || saving || startingScan || isScanning}
                title="Save current scan options and launch security scan immediately"
              >
                {startingScan ? <Loader2 size={13} className="webcare-spin-icon" /> : <Play size={13} fill="currentColor" />}
                <span>{startingScan ? 'Launching...' : 'Save & Start Scan'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
