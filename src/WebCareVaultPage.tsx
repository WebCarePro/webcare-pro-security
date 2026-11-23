import { useState, useEffect } from '@wordpress/element';
import {
  Archive,
  Database,
  RotateCcw,
  Key,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  FolderLock,
  HardDrive,
  Copy,
  Check,
  ArrowLeft,
  Sparkles,
  Layers,
  Clock,
  Terminal,
  Cpu
} from 'lucide-react';
import { QuarantinePage } from './QuarantinePage';
import DatabaseBackupVault from './components/DatabaseBackupVault';
import { RemediationTransactionsCard } from './components/RemediationTransactionsCard';
import { ConfirmDialog } from './components/ConfirmDialog';
import ServerTelemetryPage from './ServerTelemetryPage';
import { ForensicsPage, FORENSICS_TABS, type ForensicsSubTab } from './ForensicsPage';

export type VaultSubTab = 'quarantine' | 'database' | 'rollback' | 'secrets' | 'forensics' | 'server';

interface VaultStatusData {
  quarantine: {
    total_records: number;
    active_threats: number;
    restored_files: number;
  };
  database: {
    count: number;
    total_mb: number;
  };
  rollback: {
    transactions_count: number;
    missing_users_count: number;
    missing_users: Array<{ user_id: number; user_login: string; user_email: string }>;
  };
  secrets: {
    cipher: string;
    key_source: 'env' | 'constant' | 'wp_salt' | string;
    key_fingerprint?: string;
    is_constant_defined?: boolean;
    is_hex_256?: boolean;
    openssl_available: boolean;
    gcm_available: boolean;
    encrypted_count: number;
    fields: Array<{
      key: string;
      label: string;
      is_configured: boolean;
      is_encrypted: boolean;
    }>;
    rotation_state: any;
  };
}

interface WebCareVaultPageProps {
  apiRequest: (options: any) => Promise<any>;
  initialTab?: VaultSubTab;
  onNavigateToDashboard?: () => void;
}

export const WebCareVaultPage = ({
  apiRequest,
  initialTab = 'quarantine',
  onNavigateToDashboard,
}: WebCareVaultPageProps) => {
  // Read initial tab from URL param ?tab= if present, else fallback to initialTab prop
  const getStartingTab = (): VaultSubTab => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get('tab') as VaultSubTab;
      if (tabParam === ('backup' as any)) {
        return 'database';
      }
      if (tabParam === ('diagnostics' as any)) {
        return 'forensics';
      }
      if (tabParam && ['quarantine', 'database', 'rollback', 'secrets', 'forensics', 'server'].includes(tabParam)) {
        return tabParam;
      }
      if (tabParam && (FORENSICS_TABS as readonly string[]).includes(tabParam)) {
        return 'forensics';
      }
    } catch (e) {}
    if (initialTab && ((initialTab as string) === 'diagnostics' || (FORENSICS_TABS as readonly string[]).includes(initialTab as string))) {
      return 'forensics';
    }
    return initialTab;
  };

  const getStartingForensicsSubTab = (): ForensicsSubTab => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sectionParam = (urlParams.get('section') || urlParams.get('subtab')) as ForensicsSubTab;
      if (sectionParam && (FORENSICS_TABS as readonly string[]).includes(sectionParam)) {
        return sectionParam;
      }
      const tabParam = urlParams.get('tab') as ForensicsSubTab;
      if (tabParam && (FORENSICS_TABS as readonly string[]).includes(tabParam)) {
        return tabParam;
      }
    } catch (e) {}
    return 'persistence';
  };

  const [activeTab, setActiveTab] = useState<VaultSubTab>(getStartingTab);
  const [forensicsSubTab, setForensicsSubTab] = useState<ForensicsSubTab>(getStartingForensicsSubTab);
  const [vaultStatus, setVaultStatus] = useState<VaultStatusData | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Key Rotator state
  const [rotatingKey, setRotatingKey] = useState<boolean>(false);
  const [customKeyInput, setCustomKeyInput] = useState<string>('');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);

  const [vaultRefreshNonce, setVaultRefreshNonce] = useState<number>(0);

  const fetchVaultStatus = async () => {
    setLoadingStatus(true);
    setVaultRefreshNonce((n) => n + 1);
    try {
      let res: any = null;
      try {
        res = await apiRequest({ path: '/vault/status' });
      } catch (err1) {
        // Fallback with explicit full namespace if route prefix differs
        res = await apiRequest({ path: '/webcare-pro-security/v1/vault/status' });
      }
      if (res && (res.success || res.quarantine || res.secrets)) {
        setVaultStatus(res);
      }
    } catch (err) {
      console.error('Failed to load vault status', err);
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchVaultStatus();
  }, []);

  // Update browser URL query param & history when tab changes
  const handleTabChange = (newTab: VaultSubTab) => {
    setActiveTab(newTab);
    try {
      const url = new URL(window.location.href);
      const canonicalTab = newTab === 'forensics' ? 'diagnostics' : newTab;
      url.searchParams.set('tab', canonicalTab);
      if (newTab === 'forensics' && forensicsSubTab) {
        url.searchParams.set('section', forensicsSubTab);
      } else {
        url.searchParams.delete('section');
      }
      url.searchParams.delete('subtab');
      window.history.pushState({ vaultTab: canonicalTab, section: forensicsSubTab }, '', url.toString());
    } catch (e) {}
  };

  // In-App Confirm Dialog State
  const [vaultConfirmDialog, setVaultConfirmDialog] = useState<{
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

  const requestVaultConfirm = ({
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
    setVaultConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setVaultConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setVaultConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setVaultConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  // Listen to browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const tabParam = urlParams.get('tab') as VaultSubTab;
        const subtabParam = urlParams.get('subtab') as ForensicsSubTab;
        if (tabParam && ['quarantine', 'database', 'rollback', 'secrets', 'forensics', 'server'].includes(tabParam)) {
          setActiveTab(tabParam);
          if (tabParam === 'forensics' && subtabParam && (FORENSICS_TABS as readonly string[]).includes(subtabParam)) {
            setForensicsSubTab(subtabParam);
          }
        } else if (tabParam && (FORENSICS_TABS as readonly string[]).includes(tabParam)) {
          setActiveTab('forensics');
          setForensicsSubTab(tabParam as unknown as ForensicsSubTab);
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleGenerateKey = () => {
    const arr = new Uint8Array(32);
    window.crypto.getRandomValues(arr);
    const hex = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
    setCustomKeyInput(hex);
    setGeneratedKey(hex);
  };

  const handleCopyKey = (keyText: string) => {
    navigator.clipboard.writeText(keyText);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 3000);
  };

  const handleExecuteKeyRotation = async () => {
    const isConst = vaultStatus?.secrets?.is_constant_defined;
    const msg = isConst
      ? 'Execute zero-downtime AES-256-GCM Vault Key Rotation? All existing credentials (AI keys, Cloudflare tokens, Webhook URLs) will be securely re-encrypted under the new cryptographic key material. IMPORTANT: Because WEBCARE_VAULT_KEY is defined in wp-config.php, you will need to update wp-config.php with the new key shown on screen. A safety backup will be created automatically before rotation.'
      : 'Execute zero-downtime AES-256-GCM Vault Key Rotation? All existing credentials (AI keys, Cloudflare tokens, Webhook URLs) will be securely re-encrypted under the new cryptographic key material. A safety backup will be created automatically before rotation.';

    requestVaultConfirm({
      title: 'Rotate Vault Master Key',
      message: msg,
      confirmLabel: 'Rotate Master Key',
      variant: 'warning',
      onConfirm: async () => {
        setRotatingKey(true);
        setFeedback(null);

        try {
          const res = await apiRequest({
            path: '/webcare-pro-security/v1/vault/rotate-key',
            method: 'POST',
            data: customKeyInput ? { new_key: customKeyInput } : {},
          });

          if (res && res.success) {
            setFeedback({
              type: 'success',
              message: res.message || 'Vault encryption keys rotated and credentials verified successfully!',
            });
            if (res.new_key_material) {
              setGeneratedKey(res.new_key_material);
            }
            fetchVaultStatus();
          } else {
            setFeedback({
              type: 'error',
              message: res?.message || 'Key rotation failed. Pre-rotation backup remains active.',
            });
          }
        } catch (err: any) {
          setFeedback({
            type: 'error',
            message: err?.message || 'Error occurred while rotating master key.',
          });
        } finally {
          setRotatingKey(false);
        }
      },
    });
  };

  const [resettingRotation, setResettingRotation] = useState<boolean>(false);

  const handleResetRotationState = async () => {
    setResettingRotation(true);
    setFeedback(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/vault/reset-rotation',
        method: 'POST',
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: 'Rotation state and locks cleared successfully. You may now perform a fresh key rotation.',
        });
        fetchVaultStatus();
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to reset rotation lock.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error occurred while clearing rotation lock.',
      });
    } finally {
      setResettingRotation(false);
    }
  };

  const getKeySourceLabel = (src?: string) => {
    if (loadingStatus && !vaultStatus) {
      return {
        label: 'Detecting Master Key...',
        sublabel: 'Querying cryptographic derivation source',
        color: '#94a3b8',
        bg: 'rgba(148, 163, 184, 0.15)',
      };
    }
    switch (src) {
      case 'env':
        return {
          label: 'Server Environment (WEBCARE_VAULT_KEY)',
          sublabel: 'Dedicated OS Environment Variable Active',
          color: '#10b981',
          bg: 'rgba(16, 185, 129, 0.15)',
        };
      case 'constant':
        return {
          label: 'wp-config.php (WEBCARE_VAULT_KEY)',
          sublabel: 'Active 256-Bit Master Key Defined in wp-config.php',
          color: '#38bdf8',
          bg: 'rgba(56, 189, 248, 0.15)',
        };
      case 'wp_salt':
      default:
        return {
          label: 'WordPress Core Salts (SHA-256 Seed)',
          sublabel: 'Derived from AUTH_KEY & WP Salts',
          color: '#f59e0b',
          bg: 'rgba(245, 158, 11, 0.15)',
        };
    }
  };

  const keySourceInfo = getKeySourceLabel(vaultStatus?.secrets?.key_source);

  return (
    <div className="webcare-container" style={{ width: '100%', maxWidth: '100%', margin: '0', paddingBottom: '70px' }}>
      {/* =========================================================================
          1. UNIFIED VAULT HERO HEADER
          ========================================================================= */}
      <div
        className="webcare-card webcare-vault-hero-card"
        style={{
          marginBottom: '22px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div style={{ padding: '24px 28px', position: 'relative', zIndex: 2 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
            <div style={{ maxWidth: '850px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '12px' }}>
                <div
                  style={{
                    background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                    padding: '12px',
                    borderRadius: '14px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 4px 14px rgba(16, 185, 129, 0.25)',
                  }}
                >
                  <Lock size={28} color="#ffffff" />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, letterSpacing: '-0.02em' }}>
                      WebCare Vault & Safety Recoveries
                    </h1>
                    <span className="webcare-badge-clean">
                      Unified Vault Suite
                    </span>
                  </div>
                  <p style={{ margin: '5px 0 0 0', fontSize: '13.5px', lineHeight: 1.5, opacity: 0.85 }}>
                    Centralized command center for cryptographic malware quarantine, zero-downtime database backups, atomic remediation rollbacks, and AES-256-GCM credential vaulting.
                  </p>
                </div>
              </div>

              {/* Status Tags */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginTop: '14px' }}>
                <span className="webcare-badge-neutral">
                  <Key size={13} color="#059669" />
                  Master Key: {keySourceInfo.label}
                </span>

                <span className="webcare-badge-clean">
                  <ShieldCheck size={13} />
                  AEAD Cipher: AES-256-GCM
                </span>

                <span className="webcare-badge-info">
                  <FolderLock size={13} />
                  Execution Defanged Isolation
                </span>
              </div>
            </div>

            {/* Right Controls */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {onNavigateToDashboard && (
                <button
                  type="button"
                  className="webcare-btn-secondary"
                  onClick={onNavigateToDashboard}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <ArrowLeft size={15} />
                  Dashboard
                </button>
              )}
              <button
                type="button"
                className="webcare-btn-primary"
                onClick={fetchVaultStatus}
                disabled={loadingStatus}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                }}
              >
                <RefreshCw size={15} className={loadingStatus ? 'webcare-spin-icon' : ''} />
                {loadingStatus ? 'Refreshing Vaults...' : 'Refresh Vaults'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          2. METRIC SUMMARY CARDS
          ========================================================================= */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        {/* Card 1: Quarantine Threats */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'quarantine' ? 'is-active is-quarantine' : ''}`}
          onClick={() => handleTabChange('quarantine')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Quarantine Vault</span>
            <div style={{ background: 'rgba(2, 132, 199, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <Archive size={17} color="#0284c7" />
            </div>
          </div>
          <div className="metric-val">
            {vaultStatus?.quarantine?.active_threats ?? '...'}
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>threats isolated</span>
          </div>
          <div className="metric-sub">
            {vaultStatus?.quarantine?.restored_files ?? 0} restored &bull; Defanged storage
          </div>
        </div>

        {/* Card 2: Database Backup Vault */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'database' ? 'is-active is-database' : ''}`}
          onClick={() => handleTabChange('database')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Database Vault</span>
            <div style={{ background: 'rgba(16, 185, 129, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <Database size={17} color="#10b981" />
            </div>
          </div>
          <div className="metric-val">
            {vaultStatus?.database?.count ?? '...'}
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>snapshots</span>
          </div>
          <div className="metric-sub">
            {vaultStatus?.database?.total_mb ?? 0} MB compressed Gzip dumps
          </div>
        </div>

        {/* Card 3: Rollback & Transaction Vault */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'rollback' ? 'is-active is-rollback' : ''}`}
          onClick={() => handleTabChange('rollback')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Rollback & Recovery Vault</span>
            <div style={{ background: 'rgba(245, 158, 11, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <RotateCcw size={17} color="#d97706" />
            </div>
          </div>
          <div className="metric-val">
            {vaultStatus?.rollback?.transactions_count ?? '...'}
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>atomic txs</span>
          </div>
          <div className="metric-sub">
            {(vaultStatus?.rollback?.missing_users_count ?? 0) > 0 ? (
              <span style={{ color: '#f59e0b', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <AlertTriangle size={13} /> {vaultStatus?.rollback?.missing_users_count} Admin Account(s) Ready to Restore!
              </span>
            ) : (
              <span style={{ color: '#10b981', fontWeight: 600 }}>Zero unrestored drift &bull; Fully aligned</span>
            )}
          </div>
        </div>

        {/* Card 4: Secret Vault & Key Rotator */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'secrets' ? 'is-active is-secrets' : ''}`}
          onClick={() => handleTabChange('secrets')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Secret & Key Vault</span>
            <div style={{ background: 'rgba(139, 92, 246, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <Key size={17} color="#8b5cf6" />
            </div>
          </div>
          <div className="metric-val">
            {vaultStatus?.secrets?.encrypted_count ?? '...'}
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>sealed secrets</span>
          </div>
          <div className="metric-sub">
            AES-256-GCM AEAD &bull; Zero-downtime rotator
          </div>
        </div>

        {/* Card 5: Deep System Forensics */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'forensics' ? 'is-active is-forensics' : ''}`}
          onClick={() => handleTabChange('forensics')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Deep System Forensics</span>
            <div style={{ background: 'rgba(99, 102, 241, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <Sparkles size={17} color="#6366f1" />
            </div>
          </div>
          <div className="metric-val">
            Forensics
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>&amp; Baselines</span>
          </div>
          <div className="metric-sub">
            Attack chain &bull; Persistence watchdog
          </div>
        </div>

        {/* Card 6: Server & Host Infrastructure Telemetry */}
        <div
          className={`webcare-vault-tab-card ${activeTab === 'server' ? 'is-active is-server' : ''}`}
          onClick={() => handleTabChange('server')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="metric-title">Server Telemetry</span>
            <div style={{ background: 'rgba(2, 132, 199, 0.12)', padding: '6px', borderRadius: '8px' }}>
              <HardDrive size={17} color="#0284c7" />
            </div>
          </div>
          <div className="metric-val">
            Server &amp; Host
            <span style={{ fontSize: '13px', fontWeight: 500, marginLeft: '6px', opacity: 0.75 }}>OS &amp; PHP</span>
          </div>
          <div className="metric-sub">
            Kernel, RAM, CPU &bull; Dev diagnostics
          </div>
        </div>
      </div>

      {/* Global Feedback Banner */}
      {feedback && (
        <div
          style={{
            padding: '14px 20px',
            borderRadius: '10px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            background: feedback.type === 'success' ? '#f0fdf4' : '#fef2f2',
            border: feedback.type === 'success' ? '1px solid #bbf7d0' : '1px solid #fecaca',
            color: feedback.type === 'success' ? '#166534' : '#991b1b',
            fontSize: '13.5px',
            fontWeight: 500,
          }}
        >
          {feedback.type === 'success' ? <CheckCircle2 size={18} color="#16a34a" /> : <AlertTriangle size={18} color="#dc2626" />}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* =========================================================================
          4. TAB VIEW CONTENTS
          ========================================================================= */}

      {/* VIEW 1: QUARANTINE VAULT */}
      {activeTab === 'quarantine' && (
        <QuarantinePage
          key={`quarantine-${vaultRefreshNonce}`}
          apiRequest={apiRequest}
          isEmbedded={true}
          onNavigateToDashboard={onNavigateToDashboard}
        />
      )}

      {/* VIEW 2: DATABASE BACKUP VAULT */}
      {activeTab === 'database' && (
        <DatabaseBackupVault key={`database-${vaultRefreshNonce}`} />
      )}

      {/* VIEW 3: ROLLBACK & TRANSACTION VAULT (WITH USER ACCOUNT RECOVERY) */}
      {activeTab === 'rollback' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <RemediationTransactionsCard
            key={`rollback-${vaultRefreshNonce}`}
            apiRequest={apiRequest}
            onRollbackComplete={fetchVaultStatus}
          />
        </div>
      )}

      {/* VIEW 4: SECRET & KEY VAULT */}
      {activeTab === 'secrets' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Cryptographic Architecture Card */}
          <div className="webcare-card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
              <div style={{ background: 'rgba(124, 58, 237, 0.15)', padding: '10px', borderRadius: '10px' }}>
                <Key size={22} color="#7c3aed" />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700 }}>
                  Secret Vault Cryptographic Architecture
                </h3>
                <p style={{ margin: '2px 0 0 0', fontSize: '13px', opacity: 0.75 }}>
                  Hardware-isolated and environment-backed authenticated encryption for high-sensitivity credentials.
                </p>
              </div>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: '16px',
                marginTop: '18px',
              }}
            >
              <div className="webcare-card-elevated" style={{ padding: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, opacity: 0.7, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Active Master Key Derivation
                </div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: keySourceInfo.color, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {loadingStatus && !vaultStatus ? (
                    <RefreshCw size={16} className="webcare-spin-icon" color="#94a3b8" />
                  ) : (
                    <ShieldCheck size={16} />
                  )}
                  {keySourceInfo.label}
                </div>
                <div style={{ fontSize: '12px', opacity: 0.75, marginTop: '6px', lineHeight: 1.4 }}>
                  {vaultStatus?.secrets?.key_source === 'constant' ? (
                    <span>
                      <strong style={{ color: '#0284c7' }}>wp-config.php constant active.</strong>
                      {vaultStatus.secrets.key_fingerprint && (
                        <span style={{ display: 'block', marginTop: '3px', fontFamily: 'monospace', fontSize: '11px', color: '#0369a1' }}>
                          Fingerprint: {vaultStatus.secrets.key_fingerprint} (Plaintext key is isolated in memory)
                        </span>
                      )}
                    </span>
                  ) : (
                    'Isolated 256-bit binary key. Raw key is never exposed in plaintext.'
                  )}
                </div>
              </div>

              <div className="webcare-card-elevated" style={{ padding: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, opacity: 0.7, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Symmetric AEAD Cipher
                </div>
                <div style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Lock size={16} color="#10b981" />
                  AES-256-GCM (128-bit Tag)
                </div>
                <div style={{ fontSize: '12px', opacity: 0.75, marginTop: '6px', lineHeight: 1.4 }}>
                  Authenticated Encryption with unique 96-bit IV per record and tamper-proof verification tags.
                </div>
              </div>

              <div className="webcare-card-elevated" style={{ padding: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, opacity: 0.7, textTransform: 'uppercase', marginBottom: '6px' }}>
                  OpenSSL Environment Engine
                </div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: loadingStatus && !vaultStatus ? '#94a3b8' : vaultStatus?.secrets?.gcm_available ? '#16a34a' : '#dc2626', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {loadingStatus && !vaultStatus ? (
                    <RefreshCw size={16} className="webcare-spin-icon" color="#94a3b8" />
                  ) : vaultStatus?.secrets?.gcm_available ? (
                    <CheckCircle2 size={16} />
                  ) : (
                    <AlertTriangle size={16} />
                  )}
                  {loadingStatus && !vaultStatus ? 'Detecting Engine...' : vaultStatus?.secrets?.gcm_available ? 'Hardware GCM Accelerated' : 'Unavailable'}
                </div>
                <div style={{ fontSize: '12px', opacity: 0.75, marginTop: '6px', lineHeight: 1.4 }}>
                  Native OpenSSL C-extension acceleration for sub-millisecond encryption/decryption.
                </div>
              </div>
            </div>
          </div>

          {/* Protected Credentials Audit Table */}
          {/* Protected Credentials Audit Table */}
          <div className="webcare-card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>
                  Protected Sensitive Secrets & Webhook Credentials
                </h3>
                <p style={{ margin: '3px 0 0 0', fontSize: '13px', opacity: 0.75 }}>
                  Live cryptographic status of all API tokens, webhooks, and automation credentials stored in the database.
                </p>
              </div>
              <span className="webcare-badge-neutral">
                {loadingStatus && !vaultStatus
                  ? 'Loading Status...'
                  : `${vaultStatus?.secrets?.encrypted_count ?? 0} / ${vaultStatus?.secrets?.fields?.length ?? 0} Protected`}
              </span>
            </div>

            <div className="webcare-table-card">
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr>
                    <th style={{ padding: '12px 18px', fontWeight: 600 }}>Secret Name</th>
                    <th style={{ padding: '12px 18px', fontWeight: 600 }}>Configuration Status</th>
                    <th style={{ padding: '12px 18px', fontWeight: 600 }}>Cryptographic State</th>
                    <th style={{ padding: '12px 18px', fontWeight: 600 }}>Cipher Mask Preview</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingStatus && !vaultStatus && (
                    <tr>
                      <td colSpan={4} style={{ padding: '36px', textAlign: 'center' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '10px', fontSize: '13px', fontWeight: 500 }}>
                          <RefreshCw size={16} className="webcare-spin-icon" color="#6366f1" />
                          Synchronizing live credential encryption status...
                        </div>
                      </td>
                    </tr>
                  )}
                  {!loadingStatus && (!vaultStatus?.secrets?.fields || vaultStatus.secrets.fields.length === 0) && (
                    <tr>
                      <td colSpan={4} style={{ padding: '36px', textAlign: 'center' }}>
                        <div style={{ fontSize: '13px', fontWeight: 500 }}>
                          Vault status not loaded. Please pull latest plugin updates on your server and refresh.
                        </div>
                      </td>
                    </tr>
                  )}
                  {vaultStatus?.secrets?.fields?.map((field) => (
                    <tr key={field.key}>
                      <td style={{ padding: '14px 18px', fontWeight: 600 }}>
                        {field.label}
                        <div style={{ fontSize: '11px', opacity: 0.65, fontFamily: 'monospace' }}>
                          settings.{field.key}
                        </div>
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        {field.is_configured ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#10b981', fontWeight: 600, fontSize: '12.5px' }}>
                            <CheckCircle2 size={14} /> Configured
                          </span>
                        ) : (
                          <span style={{ opacity: 0.5, fontSize: '12.5px' }}>
                            Not Configured (Empty)
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        {field.is_encrypted ? (
                          <span className="webcare-badge-clean">
                            <Lock size={12} /> Encrypted (AES-256-GCM)
                          </span>
                        ) : field.is_configured ? (
                          <span className="webcare-badge-critical">
                            <Unlock size={12} /> Plaintext Warning
                          </span>
                        ) : (
                          <span style={{ opacity: 0.4 }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '14px 18px', fontFamily: 'monospace', fontSize: '12px', opacity: 0.75 }}>
                        {field.is_configured ? 'webcare_gcm:••••••••••••••••••••••••' : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Zero-Downtime Key Rotation Panel */}
          <div className="webcare-card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
              <div style={{ background: 'rgba(245, 158, 11, 0.15)', padding: '10px', borderRadius: '10px' }}>
                <RefreshCw size={22} color="#d97706" />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700 }}>
                  Zero-Downtime Cryptographic Key Rotation
                </h3>
                <p style={{ margin: '2px 0 0 0', fontSize: '13px', opacity: 0.75 }}>
                  Re-encrypt all vaulted secrets under a new cryptographic key with atomic verification and pre-rotation fallback.
                </p>
              </div>
            </div>

            <div className="webcare-card-elevated" style={{ padding: '18px', marginTop: '16px' }}>
              {vaultStatus?.secrets?.is_constant_defined && (
                <div
                  style={{
                    marginBottom: '14px',
                    background: 'rgba(59, 130, 246, 0.12)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    fontSize: '12.5px',
                    color: '#3b82f6',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                  }}
                >
                  <Key size={16} color="#3b82f6" style={{ marginTop: '2px', flexShrink: 0 }} />
                  <div>
                    <strong>wp-config.php constant is currently active:</strong>
                    <div style={{ marginTop: '3px', lineHeight: 1.4, opacity: 0.9 }}>
                      Rotating keys here will re-encrypt all credentials in the database under the new key. Because WordPress never modifies <code>wp-config.php</code> directly for file system security, you will need to update <code>define('WEBCARE_VAULT_KEY', '...');</code> in <code>wp-config.php</code> with the new key provided upon completion.
                    </div>
                  </div>
                </div>
              )}
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>
                New Master Key Material (Optional — leave blank to auto-generate a secure 256-bit key)
              </label>
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <input
                  type="text"
                  placeholder="64-character hexadecimal key (e.g. 32-byte cryptographic random string)"
                  value={customKeyInput}
                  onChange={(e) => setCustomKeyInput(e.target.value)}
                  className="webcare-form-input"
                  style={{ flex: 1, minWidth: '280px', fontFamily: 'monospace' }}
                />
                <button
                  type="button"
                  onClick={handleGenerateKey}
                  className="webcare-btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <Sparkles size={14} /> Generate Secure Key
                </button>
                <button
                  type="button"
                  onClick={handleExecuteKeyRotation}
                  disabled={rotatingKey}
                  className="webcare-btn-primary"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    background: 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)',
                  }}
                >
                  <RefreshCw size={15} className={rotatingKey ? 'webcare-spin-icon' : ''} />
                  {rotatingKey ? 'Rotating Vault Keys...' : 'Execute 1-Click Key Rotation'}
                </button>

                {(vaultStatus?.secrets?.rotation_state?.status === 'migrating' ||
                  vaultStatus?.secrets?.rotation_state?.status === 'failed' ||
                  vaultStatus?.secrets?.rotation_state?.status === 'verifying') && (
                  <button
                    type="button"
                    onClick={handleResetRotationState}
                    disabled={resettingRotation}
                    className="webcare-btn-danger"
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                    title="Force clear any stuck rotation locks or state"
                  >
                    <RefreshCw size={14} className={resettingRotation ? 'webcare-spin-icon' : ''} />
                    {resettingRotation ? 'Clearing...' : 'Clear Stuck Rotation Lock'}
                  </button>
                )}
              </div>

              {generatedKey && (
                <div style={{ marginTop: '16px', background: '#f5f3ff', border: '1px solid #ddd6fe', borderRadius: '8px', padding: '14px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: '#6d28d9' }}>
                      ✓ Generated Master Key Material (Save for wp-config.php / Environment Variable):
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyKey(generatedKey)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: '#6d28d9',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      {copiedKey ? <Check size={14} color="#16a34a" /> : <Copy size={14} />}
                      {copiedKey ? 'Copied!' : 'Copy Key'}
                    </button>
                  </div>
                  <code style={{ fontSize: '12px', color: '#1e1b4b', wordBreak: 'break-all', display: 'block' }}>
                    {generatedKey}
                  </code>
                  <p style={{ margin: '8px 0 0 0', fontSize: '11.5px', color: '#6b7280' }}>
                    To permanently lock this key to your server environment, define <code>define('WEBCARE_VAULT_KEY', '{generatedKey}');</code> in <code>wp-config.php</code> or set the <code>WEBCARE_VAULT_KEY</code> environment variable.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* VIEW 5: DEEP SYSTEM FORENSICS */}
      {activeTab === 'forensics' && (
        <ForensicsPage
          apiRequest={apiRequest}
          initialSubTab={forensicsSubTab}
          onSubTabChange={(sub) => {
            setForensicsSubTab(sub);
          }}
          onNavigateToDashboard={onNavigateToDashboard || (() => { window.location.href = 'admin.php?page=webcare-pro-security'; })}
        />
      )}

      {/* VIEW 6: SERVER & HOST INFRASTRUCTURE TELEMETRY */}
      {activeTab === 'server' && (
        <ServerTelemetryPage
          apiRequest={apiRequest}
          onNavigateToDashboard={onNavigateToDashboard}
          onNavigateToFirewall={(subTab) => { window.location.href = `admin.php?page=webcare-pro-firewall${subTab ? `&tab=${subTab}` : ''}`; }}
          onNavigateToSettings={(subTab) => { window.location.href = `admin.php?page=webcare-pro-settings${subTab ? `&tab=${subTab}` : ''}`; }}
        />
      )}

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={vaultConfirmDialog.isOpen}
        title={vaultConfirmDialog.title}
        message={vaultConfirmDialog.message}
        targetItem={vaultConfirmDialog.targetItem}
        confirmLabel={vaultConfirmDialog.confirmLabel}
        variant={vaultConfirmDialog.variant}
        isLoading={vaultConfirmDialog.isLoading}
        onConfirm={vaultConfirmDialog.onConfirm || (() => {})}
        onClose={() => setVaultConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
