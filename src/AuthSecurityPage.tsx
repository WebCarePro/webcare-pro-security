import { useState, useEffect, useMemo } from '@wordpress/element';
import {
  Lock,
  Unlock,
  ShieldCheck,
  ShieldAlert,
  Shield,
  Key,
  QrCode,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Trash2,
  Sliders,
  Smartphone,
  Eye,
  EyeOff,
  UserCheck,
  Laptop,
  Globe,
  LogOut,
  Clock,
  Users,
  UserX,
  AlertCircle,
  Radio,
  Download,
  Fingerprint,
  Zap,
  Tablet,
  History,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Monitor,
  FileText
} from 'lucide-react';
import UserSessionForensicsModal from './UserSessionForensicsModal';
import IdentityForensicsCard from './components/IdentityForensicsCard';
import { WebAuthnPasskeyCard } from './components/WebAuthnPasskeyCard';
import { AppPasswordSentinelCard } from './components/AppPasswordSentinelCard';
import { ConfirmDialog } from './components/ConfirmDialog';
import { UnsavedChangesBar } from './components/ui/UnsavedChangesBar';
import { useWorkspaceMode } from './hooks/useWorkspaceMode';
import { InlineConfirmPopover } from './components/InlineConfirmPopover';
import { toast } from './utils/dialog';

export interface IpHistoryEntry {
  ip: string;
  first_seen: string;
  first_seen_raw?: number;
  first_seen_human: string;
  last_seen: string;
  last_seen_raw?: number;
  last_seen_human: string;
  count: number;
  is_login: boolean;
  is_current: boolean;
  is_local_ip?: boolean;
}

export interface ActiveSessionLoginRecord {
  time?: number | string;
  time_formatted?: string;
  time_human?: string;
  login_time?: string;
  login_time_formatted?: string;
  login_time_human?: string;
  login_time_gmt?: string;
  ip: string;
  country: string;
  country_code: string;
  auth_factor?: string;
  auth_type?: string;
  auth_label?: string;
  browser: string;
  browser_version: string;
  screen_resolution: string;
  timezone: string;
  user_agent: string;
  session_token?: string;
  is_active?: boolean;
  is_current?: boolean;
}

export interface ActiveSession {
  session_id: string;
  token: string;
  user_id: number;
  user_login: string;
  display_name?: string;
  user_email: string;
  avatar_url: string;
  is_current: boolean;
  is_active?: boolean;
  is_pre_install?: boolean;
  is_cloudflare_proxy_ip?: boolean;
  status?: 'active' | 'logged_out';
  is_revoked?: boolean;
  revoked_at?: number | null;
  revoked_at_human?: string | null;
  revocation_reason?: string;
  can_delete?: boolean;
  retention_days_remaining?: number;
  retention_lock_reason?: string | null;
  login_ip: string;
  current_ip?: string;
  is_same_ip: boolean;
  is_local_ip?: boolean;
  has_ip_changed?: boolean;
  distinct_ips?: string[];
  distinct_ip_count?: number;
  ip_changes_count?: number;
  ip_history?: IpHistoryEntry[];
  ip_events?: Array<{
    ip: string;
    time: number;
    type: string;
    ua?: string;
  }>;
  login_time: string;
  login_time_raw?: number;
  login_time_human?: string;
  login_duration_seconds?: number;
  login_duration_formatted?: string;
  last_seen: string;
  last_seen_raw?: number;
  idle_human?: string;
  expiration?: string | null;
  expiration_raw?: number | null;
  expiration_human?: string;
  browser: string;
  browser_version?: string;
  screen_resolution?: string;
  timezone?: string;
  country?: string;
  country_code?: string;
  platform: string;
  device_type?: 'Desktop' | 'Mobile' | 'Tablet';
  device_uuid?: string;
  device_first_seen_formatted?: string;
  total_logins?: number;
  user_agent: string;
  full_user_agent?: string;
  login_records?: ActiveSessionLoginRecord[];
  auth_type?: 'passkey' | 'magic_link' | '2fa' | 'password';
  auth_label?: string;
  auth_details?: Record<string, any>;
  security_level?: 'hardened' | 'sandboxed' | 'at_risk';
  risk_factors?: string[];
  support_link_meta?: {
    link_id: string;
    label: string;
    scope: string;
    restrict_ip?: string;
    expires_at?: string;
  } | null;
}

export interface AccountSessionGroup {
  user_id: number;
  user_login: string;
  display_name: string;
  user_email: string;
  avatar_url: string;
  is_current_account: boolean;
  sessions: ActiveSession[];
  active_sessions_count: number;
  logged_out_sessions_count: number;
  all_distinct_ips: string[];
  has_any_ip_changed: boolean;
  total_ip_count: number;
}

interface TrustedDevice {
  id: string;
  ip: string;
  user_agent: string;
  created_at: string;
  last_used: string;
  expires_at: number;
  days: number;
}

interface AuthStatus {
  auth_2fa_enabled: boolean;
  auth_2fa_algorithm?: 'sha1' | 'sha512';
  auth_2fa_digits?: number;
  user_2fa_algorithm?: 'sha1' | 'sha512';
  user_2fa_digits?: number;
  auth_2fa_remember_device?: boolean;
  auth_2fa_remember_days?: number;
  trusted_devices_count?: number;
  trusted_devices?: TrustedDevice[];
  login_hardening_enabled: boolean;
  login_max_retries: number;
  login_lockout_duration: number;
  session_sentinel_enabled?: boolean;
  session_block_concurrent?: boolean;
  user_2fa_enabled: boolean;
  user_login: string;
  user_email: string;
  lockouts: Array<{
    ip: string;
    attempts: number;
    username: string;
    blocked_at: string;
    expires_at: number;
    user_agent?: string;
  }>;
  stats: {
    total_locked: number;
  };
  active_sessions?: ActiveSession[];
  backup_codes_count?: number;
  current_ip?: string;
}

interface SetupPackage {
  secret: string;
  algorithm?: 'sha1' | 'sha512';
  digits?: number;
  provisioning_uri: string;
  qr_code_url: string;
  backup_codes: string[];
}

interface AdminUser {
  user_id: number;
  user_login: string;
  display_name: string;
  user_email: string;
  avatar_url: string;
  is_current_user: boolean;
  is_2fa_enabled: boolean;
  two_fa_algorithm?: 'sha1' | 'sha512';
  two_fa_digits?: number;
  compliance: {
    status: 'compliant' | 'grace_period' | 'remind_login' | 'enforcement_required' | 'not_enforced';
    label: string;
    is_compliant: boolean;
    grace_remaining: number;
    days_left: number;
    expires_at?: number;
  };
  trusted_devices: number;
  backup_codes_count?: number;
  registered_at: string;
  last_login: string | null;
  is_locked: boolean;
  locked_ips: string[];
}

export type AuthSubTab = '2fa' | 'passkeys' | 'admins' | 'zero_trust' | 'sessions' | 'lockouts' | 'app_passwords' | 'settings';

interface AuthSecurityPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToDashboard?: () => void;
  initialSubTab?: AuthSubTab;
  initialNestedSubTab?: string;
  onSubTabChange?: (sub: AuthSubTab, nestedSubTab?: string) => void;
}

export const AuthSecurityPage = ({
  apiRequest,
  onNavigateToDashboard,
  initialSubTab = '2fa',
  initialNestedSubTab,
  onSubTabChange,
}: AuthSecurityPageProps) => {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const { isSimpleMode, setMode } = useWorkspaceMode();
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<AuthSubTab>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('tab') || urlParams.get('subtab');
      if (sub && ['2fa', 'passkeys', 'admins', 'zero_trust', 'sessions', 'lockouts', 'app_passwords', 'settings'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return initialSubTab || '2fa';
  });
  const [revokingSession, setRevokingSession] = useState<string | null>(null);
  const [revokingAllOthers, setRevokingAllOthers] = useState<boolean>(false);
  const [revokingTrustedDevices, setRevokingTrustedDevices] = useState<boolean>(false);
  const [trustedDeviceSuccess, setTrustedDeviceSuccess] = useState<string | null>(null);
  const [sessionActionMsg, setSessionActionMsg] = useState<{ success: boolean; text: string } | null>(null);
  const [expandedIpHistories, setExpandedIpHistories] = useState<Record<string, boolean>>({});
  const [expandedDeviceDetails, setExpandedDeviceDetails] = useState<Record<string, boolean>>({});
  const [expandedAccounts, setExpandedAccounts] = useState<Record<number, boolean>>({});
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [copiedUa, setCopiedUa] = useState<string | null>(null);

  const toggleAccountDevices = (userId: number) => {
    setExpandedAccounts((prev) => ({
      ...prev,
      [userId]: !prev[userId],
    }));
  };

  const toggleIpHistory = (sessionToken: string) => {
    setExpandedIpHistories((prev) => ({
      ...prev,
      [sessionToken]: !prev[sessionToken],
    }));
  };

  const toggleDeviceDetails = (sessionToken: string) => {
    setExpandedDeviceDetails((prev) => ({
      ...prev,
      [sessionToken]: !prev[sessionToken],
    }));
  };

  const copyIpToClipboard = (text: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(text);
        setCopiedIp(text);
        setTimeout(() => setCopiedIp(null), 2000);
      }
    } catch (e) {}
  };

  const copyUaToClipboard = (text: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(text);
        setCopiedUa(text);
        setTimeout(() => setCopiedUa(null), 2000);
      }
    } catch (e) {}
  };

  // Settings State
  const [loginSettings, setLoginSettings] = useState<{
    auth_2fa_enabled: boolean;
    auth_2fa_algorithm: 'sha1' | 'sha512';
    auth_2fa_digits: number;
    auth_2fa_remember_device: boolean;
    auth_2fa_remember_days: number;
    login_hardening_enabled: boolean;
    login_max_retries: number;
    login_lockout_duration: number;
    session_sentinel_enabled: boolean;
    session_block_concurrent: boolean;
  }>({
    auth_2fa_enabled: true,
    auth_2fa_algorithm: 'sha1',
    auth_2fa_digits: 6,
    auth_2fa_remember_device: true,
    auth_2fa_remember_days: 7,
    login_hardening_enabled: true,
    login_max_retries: 5,
    login_lockout_duration: 15,
    session_sentinel_enabled: true,
    session_block_concurrent: false,
  });
  const [initialLoginSettingsSnapshot, setInitialLoginSettingsSnapshot] = useState<string | null>(null);

  // Global Dialog state for high-impact actions
  const [authConfirmDialog, setAuthConfirmDialog] = useState<{
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

  const requestAuthConfirm = ({
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
    setAuthConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setAuthConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setAuthConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setAuthConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  const isSettingsDirty = useMemo(() => {
    if (!initialLoginSettingsSnapshot) return false;
    try {
      return JSON.stringify(loginSettings) !== initialLoginSettingsSnapshot;
    } catch {
      return false;
    }
  }, [loginSettings, initialLoginSettingsSnapshot]);

  const handleDiscardSettings = () => {
    if (!initialLoginSettingsSnapshot) return;
    try {
      setLoginSettings(JSON.parse(initialLoginSettingsSnapshot));
      toast.info('Unsaved login security changes discarded.');
    } catch {}
  };

  // Tab switch handler with URL updating
  const toCanonicalAuthTab = (tab: AuthSubTab): string => {
    if (tab === 'zero_trust' || tab === 'sessions') return 'sessions';
    if (tab === 'app_passwords') return 'app-passwords';
    if (tab === 'settings') return 'rules';
    return tab;
  };

  const handleTabSwitch = (tab: AuthSubTab, nestedSubTab?: string) => {
    if (activeTab === 'settings' && isSettingsDirty && tab !== 'settings') {
      requestAuthConfirm({
        title: 'Discard unsaved changes?',
        message: 'You have unsaved changes in Login Security & Rate Limiting. If you leave this tab now, your edits will be discarded.',
        confirmLabel: 'Discard & Switch',
        variant: 'warning',
        onConfirm: () => {
          handleDiscardSettings();
          setActiveTab(tab);
          const canonical = toCanonicalAuthTab(tab);
          if (onSubTabChange) {
            onSubTabChange(canonical as any, nestedSubTab);
          } else {
            try {
              const url = new URL(window.location.href);
              url.searchParams.set('tab', canonical);
              if (nestedSubTab) {
                url.searchParams.set('section', nestedSubTab);
              } else {
                url.searchParams.delete('section');
              }
              url.searchParams.delete('subtab');
              window.history.pushState({ tab: canonical, section: nestedSubTab }, '', url.toString());
            } catch (e) {}
          }
        },
      });
      return;
    }

    setActiveTab(tab);
    const canonical = toCanonicalAuthTab(tab);
    if (onSubTabChange) {
      onSubTabChange(canonical as any, nestedSubTab);
    } else {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('tab', canonical);
        if (nestedSubTab) {
          url.searchParams.set('section', nestedSubTab);
        } else {
          url.searchParams.delete('section');
        }
        url.searchParams.delete('subtab');
        window.history.pushState({ tab: canonical, section: nestedSubTab }, '', url.toString());
      } catch (e) {}
    }
  };

  // Auto-switch to Developer Mode on explicit deep link to an engineer-only tab, or fallback to '2fa' if switched manually to Simple Mode
  useEffect(() => {
    const normalizeAuthTab = (raw: string | null): string | null => {
      if (!raw) return null;
      if (raw === 'app-passwords') return 'app_passwords';
      if (raw === 'zero-trust') return 'zero_trust';
      return raw;
    };
    const engineerTabs = ['admins', 'zero_trust', 'sessions', 'app_passwords'];
    if (isSimpleMode && engineerTabs.includes(activeTab)) {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const requestedTab = normalizeAuthTab(urlParams.get('tab') || urlParams.get('subtab'));
        if (requestedTab && engineerTabs.includes(requestedTab)) {
          setMode('developer');
          toast.info(`Switched to Developer Mode for ${requestedTab.replace('_', ' ')}.`);
          return;
        }
      } catch (e) {}
      handleTabSwitch('2fa');
    }
  }, [isSimpleMode, activeTab]);

  // Synchronize if prop changes
  useEffect(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const rawUrlTab = urlParams.get('tab') || urlParams.get('subtab');
      const urlTab = rawUrlTab === 'app-passwords' ? 'app_passwords' : rawUrlTab === 'zero-trust' ? 'zero_trust' : rawUrlTab;
      if (urlTab && ['2fa', 'passkeys', 'admins', 'zero_trust', 'sessions', 'lockouts', 'app_passwords', 'settings'].includes(urlTab)) {
        setActiveTab(urlTab as any);
        return;
      }
    } catch (e) {}

    if (initialSubTab && initialSubTab !== activeTab) {
      setActiveTab(initialSubTab);
    }
  }, [initialSubTab]);

  // Synchronize browser back/forward history navigation and route-change events
  useEffect(() => {
    const handleSync = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const rawSub = urlParams.get('tab') || urlParams.get('subtab');
        const sub = rawSub === 'app-passwords' ? 'app_passwords' : rawSub === 'zero-trust' ? 'zero_trust' : rawSub;
        if (sub && ['2fa', 'passkeys', 'admins', 'zero_trust', 'sessions', 'lockouts', 'app_passwords', 'settings'].includes(sub)) {
          setActiveTab(sub as any);
        } else if (!sub) {
          setActiveTab('2fa');
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handleSync);
    window.addEventListener('webcare:route-change', handleSync);
    return () => {
      window.removeEventListener('popstate', handleSync);
      window.removeEventListener('webcare:route-change', handleSync);
    };
  }, []);

  // User Forensics Inspection Modal State
  const [forensicsModal, setForensicsModal] = useState<{
    isOpen: boolean;
    userId: number | null;
    username: string;
  }>({
    isOpen: false,
    userId: null,
    username: '',
  });

  // Client Dynamic Telemetry Heartbeat (Screen Resolution, Viewport, Timezone)
  useEffect(() => {
    try {
      const screenRes = window.screen ? `${window.screen.width}x${window.screen.height}@${window.devicePixelRatio || 1}` : '';
      const viewport = `${window.innerWidth}x${window.innerHeight}`;
      const tz = Intl?.DateTimeFormat?.().resolvedOptions()?.timeZone || '';
      apiRequest({
        path: '/auth/telemetry',
        method: 'POST',
        data: {
          screen_resolution: screenRes,
          viewport: viewport,
          timezone: tz,
        },
      }).catch(() => {});
    } catch (e) {}
  }, []);
  const [setupPackage, setSetupPackage] = useState<SetupPackage | null>(null);
  const [setupCode, setSetupCode] = useState<string>('');
  const [verifyingCode, setVerifyingCode] = useState<boolean>(false);
  const [setupError, setSetupError] = useState<string | null>(null);
  const [setupSuccess, setSetupSuccess] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState<boolean>(false);
  const [copiedCodes, setCopiedCodes] = useState<boolean>(false);
  const [downloadedCodes, setDownloadedCodes] = useState<boolean>(false);
  const [savedBackupCodes, setSavedBackupCodes] = useState<boolean>(false);
  const [disabling2fa, setDisabling2fa] = useState<boolean>(false);

  // Administrator Directory & 2FA Governance State
  const [admins, setAdmins] = useState<AdminUser[]>([]);
  const [loadingAdmins, setLoadingAdmins] = useState<boolean>(false);
  const [policySaving, setPolicySaving] = useState<boolean>(false);
  const [policyEnforceAdmins, setPolicyEnforceAdmins] = useState<boolean>(false);
  const [policyMode, setPolicyMode] = useState<'immediate' | 'grace_period' | 'remind_login'>('remind_login');
  const [policyGraceDays, setPolicyGraceDays] = useState<number>(30);
  const [adminActionMsg, setAdminActionMsg] = useState<{ success: boolean; text: string } | null>(null);
  const [adminActionLoading, setAdminActionLoading] = useState<number | null>(null); // target user_id
  const [adminSetupModal, setAdminSetupModal] = useState<{
    isOpen: boolean;
    userLogin: string;
    setupPackage: SetupPackage | null;
  }>({
    isOpen: false,
    userLogin: '',
    setupPackage: null,
  });

  // Backup Codes Delivery Modal (for self regeneration or admin regeneration)
  const [backupCodesModal, setBackupCodesModal] = useState<{
    isOpen: boolean;
    userLogin: string;
    backupCodes: string[];
  }>({
    isOpen: false,
    userLogin: '',
    backupCodes: [],
  });
  const [regeneratingCodes, setRegeneratingCodes] = useState<boolean>(false);
  const [regenSuccessMsg, setRegenSuccessMsg] = useState<string | null>(null);

  const [savingSettings, setSavingSettings] = useState<boolean>(false);
  const [settingsSuccess, setSettingsSuccess] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  // Load Status
  const loadStatus = async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);

      const res = await apiRequest({ path: '/auth/status', method: 'GET' });
      if (res) {
        setStatus(res);
        setPolicyEnforceAdmins(Boolean(res.auth_2fa_enforce_admins));
        setPolicyMode(res.auth_2fa_policy_mode || 'immediate');
        setPolicyGraceDays(typeof res.auth_2fa_grace_days === 'number' ? res.auth_2fa_grace_days : 0);
        const loaded = {
          auth_2fa_enabled: res.auth_2fa_enabled !== false,
          auth_2fa_algorithm: (res.auth_2fa_algorithm === 'sha512' ? 'sha512' : 'sha1') as 'sha1' | 'sha512',
          auth_2fa_digits: res.auth_2fa_algorithm === 'sha512' || res.auth_2fa_digits === 8 ? 8 : 6,
          auth_2fa_remember_device: res.auth_2fa_remember_device !== false,
          auth_2fa_remember_days: res.auth_2fa_remember_days || 7,
          login_hardening_enabled: res.login_hardening_enabled !== false,
          login_max_retries: res.login_max_retries || 5,
          login_lockout_duration: res.login_lockout_duration || 15,
          session_sentinel_enabled: res.session_sentinel_enabled !== false,
          session_block_concurrent: !!res.session_block_concurrent,
        };
        setLoginSettings(loaded);
        setInitialLoginSettingsSnapshot(JSON.stringify(loaded));
      }

    } catch (err) {
      console.error('Failed to load auth security status', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Load Admin Directory
  const loadAdmins = async () => {
    try {
      setLoadingAdmins(true);
      const res = await apiRequest({ path: '/auth/admins', method: 'GET' });
      if (res && res.admins) {
        setAdmins(res.admins);
        setPolicyEnforceAdmins(!!res.enforce_admins);
        setPolicyMode(res.policy_mode || 'immediate');
        setPolicyGraceDays(typeof res.grace_days === 'number' ? res.grace_days : 0);
      }
    } catch (err) {
      console.error('Failed to load administrator directory', err);
    } finally {
      setLoadingAdmins(false);
    }
  };

  // Save 2FA Policy (Immediate vs Grace Period vs Remind Login)
  const handleSavePolicy = async (enforce: boolean, mode: 'immediate' | 'grace_period' | 'remind_login', graceDays: number) => {
    try {
      setPolicySaving(true);
      setAdminActionMsg(null);
      const res = await apiRequest({
        path: '/auth/policy/save',
        method: 'POST',
        data: {
          auth_2fa_enforce_admins: enforce,
          auth_2fa_policy_mode: mode,
          auth_2fa_grace_days: mode === 'immediate' ? 0 : graceDays,
        },
      });
      if (res && res.success) {
        setPolicyEnforceAdmins(enforce);
        setPolicyMode(mode);
        setPolicyGraceDays(mode === 'immediate' ? 0 : graceDays);
        if (res.admins) setAdmins(res.admins);
        setAdminActionMsg({ success: true, text: res.message || '2FA enforcement policy updated successfully.' });
        setTimeout(() => setAdminActionMsg(null), 5000);
      }
    } catch (err: any) {
      setAdminActionMsg({ success: false, text: err?.message || 'Failed to update 2FA policy.' });
    } finally {
      setPolicySaving(false);
    }
  };

  // Disable / Unlock 2FA for target administrator
  const handleAdminDisable2fa = async (user: AdminUser) => {
    requestAuthConfirm({
      title: 'Disable Two-Factor Authentication',
      message: 'Are you sure you want to disable 2FA for this administrator? They will be allowed to log in using only their username and password.',
      targetItem: user.user_login,
      confirmLabel: 'Disable 2FA',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setAdminActionLoading(user.user_id);
          setAdminActionMsg(null);
          const res = await apiRequest({
            path: '/auth/admin-2fa/disable',
            method: 'POST',
            data: { user_id: user.user_id },
          });
          if (res && res.success) {
            setAdminActionMsg({ success: true, text: res.message });
            if (res.admins) setAdmins(res.admins);
            setTimeout(() => setAdminActionMsg(null), 5000);
            loadStatus(true);
          }
        } catch (err: any) {
          setAdminActionMsg({ success: false, text: err?.message || 'Failed to disable 2FA for administrator.' });
        } finally {
          setAdminActionLoading(null);
        }
      },
    });
  };

  // Reset 2FA & Generate Credentials for target administrator
  const handleAdminReset2fa = async (user: AdminUser) => {
    requestAuthConfirm({
      title: 'Reset 2FA & Generate Credentials',
      message: 'Generate a brand-new 2FA secret and setup package for this administrator? Their existing authenticator codes will immediately stop working.',
      targetItem: user.user_login,
      confirmLabel: 'Reset 2FA Secret',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setAdminActionLoading(user.user_id);
          setAdminActionMsg(null);
          const res = await apiRequest({
            path: '/auth/admin-2fa/reset',
            method: 'POST',
            data: { user_id: user.user_id },
          });
          if (res && res.success) {
            if (res.admins) setAdmins(res.admins);
            if (res.setup_package) {
              setAdminSetupModal({
                isOpen: true,
                userLogin: user.user_login,
                setupPackage: res.setup_package,
              });
            }
            setAdminActionMsg({ success: true, text: res.message });
            setTimeout(() => setAdminActionMsg(null), 5000);
            loadStatus(true);
          }
        } catch (err: any) {
          setAdminActionMsg({ success: false, text: err?.message || 'Failed to reset 2FA for administrator.' });
        } finally {
          setAdminActionLoading(null);
        }
      },
    });
  };

  // Regenerate Backup Codes for Current User
  const handleRegenerateMyBackupCodes = async () => {
    requestAuthConfirm({
      title: 'Regenerate Backup Codes',
      message: 'Generate a brand-new set of emergency backup codes? All your previously generated backup codes will immediately become invalid.',
      confirmLabel: 'Generate New Codes',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setRegeneratingCodes(true);
          setRegenSuccessMsg(null);
          const res = await apiRequest({
            path: '/auth/2fa/regenerate-backup-codes',
            method: 'POST',
          });
          if (res && res.success && res.backup_codes) {
            setBackupCodesModal({
              isOpen: true,
              userLogin: status?.user_login || 'Administrator',
              backupCodes: res.backup_codes,
            });
            setRegenSuccessMsg(res.message || '8 new emergency backup codes generated successfully.');
            setTimeout(() => setRegenSuccessMsg(null), 5000);
            loadStatus(true);
          }
        } catch (err: any) {
          setAdminActionMsg({ success: false, text: 'Failed to regenerate backup codes: ' + (err?.message || 'Error') });
        } finally {
          setRegeneratingCodes(false);
        }
      },
    });
  };

  // Regenerate Backup Codes for Target Administrator
  const handleAdminRegenerateBackupCodes = async (user: AdminUser) => {
    requestAuthConfirm({
      title: 'Regenerate Administrator Backup Codes',
      message: 'Generate new emergency backup codes for this administrator? Their existing backup codes will be revoked immediately.',
      targetItem: user.user_login,
      confirmLabel: 'Regenerate Codes',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setAdminActionLoading(user.user_id);
          setAdminActionMsg(null);
          const res = await apiRequest({
            path: '/auth/admin-2fa/regenerate-backup-codes',
            method: 'POST',
            data: { user_id: user.user_id },
          });
          if (res && res.success && res.backup_codes) {
            if (res.admins) setAdmins(res.admins);
            setBackupCodesModal({
              isOpen: true,
              userLogin: user.user_login,
              backupCodes: res.backup_codes,
            });
            setAdminActionMsg({ success: true, text: res.message });
            setTimeout(() => setAdminActionMsg(null), 5000);
            loadStatus(true);
          }
        } catch (err: any) {
          setAdminActionMsg({ success: false, text: err?.message || 'Failed to regenerate backup codes.' });
        } finally {
          setAdminActionLoading(null);
        }
      },
    });
  };

  // Unlock Login Hardening Lockout for target administrator
  const handleAdminUnlockLockout = async (user: AdminUser) => {
    try {
      setAdminActionLoading(user.user_id);
      setAdminActionMsg(null);
      const res = await apiRequest({
        path: '/auth/admin-lockout/clear',
        method: 'POST',
        data: { user_id: user.user_id },
      });
      if (res && res.success) {
        setAdminActionMsg({ success: true, text: res.message });
        if (res.admins) setAdmins(res.admins);
        setTimeout(() => setAdminActionMsg(null), 5000);
        loadStatus(true);
      }
    } catch (err: any) {
      setAdminActionMsg({ success: false, text: err?.message || 'Failed to clear lockout.' });
    } finally {
      setAdminActionLoading(null);
    }
  };

  // Session Revocation Handlers
  const handleRevokeSession = async (token: string, userId: number) => {
    try {
      setRevokingSession(token);
      setSessionActionMsg(null);
      const res = await apiRequest({
        path: '/auth/sessions/revoke',
        method: 'POST',
        data: { token, user_id: userId },
      });
      if (res && res.success) {
        setSessionActionMsg({ success: true, text: res.message || 'Session revoked successfully.' });
        setTimeout(() => setSessionActionMsg(null), 4000);
        loadStatus(true);
      }
    } catch (err: any) {
      setSessionActionMsg({ success: false, text: err?.message || 'Failed to revoke session.' });
    } finally {
      setRevokingSession(null);
    }
  };

  const [deletingRecord, setDeletingRecord] = useState<string | null>(null);

  const handleDeleteSessionRecord = async (token: string, userId: number) => {
    requestAuthConfirm({
      title: 'Permanently Purge Device Record',
      message: 'This device record has completed the mandatory 30-day forensic retention period. Permanently purge it from both the active database and the encrypted security vault?',
      confirmLabel: 'Purge Record',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setDeletingRecord(token);
          setSessionActionMsg(null);
          const res = await apiRequest({
            path: '/auth/sessions/revoke',
            method: 'POST',
            data: { token, user_id: userId, delete_record: true },
          });
          if (res && res.success) {
            setSessionActionMsg({ success: true, text: res.message || 'Device record permanently purged from database and vault.' });
            setTimeout(() => setSessionActionMsg(null), 4000);
            loadStatus(true);
          }
        } catch (err: any) {
          setSessionActionMsg({ success: false, text: err?.message || 'Failed to purge record.' });
        } finally {
          setDeletingRecord(null);
        }
      },
    });
  };

  const handleRevokeAllOtherSessions = async () => {
    requestAuthConfirm({
      title: 'Log Out All Other Sessions',
      message: 'Are you sure you want to log out everyone else on the site (and your other devices), keeping only your current browser session active? All login history and device records for every user will be preserved.',
      confirmLabel: 'Log Out Everyone Else',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setRevokingAllOthers(true);
          setSessionActionMsg(null);
          const res = await apiRequest({
            path: '/auth/sessions/revoke',
            method: 'POST',
            data: { revoke_others: true, all_users: true, all_admins: true },
          });
          if (res && res.success) {
            setSessionActionMsg({ success: true, text: res.message || 'All other sessions have been logged out. All login history has been preserved.' });
            setTimeout(() => setSessionActionMsg(null), 4000);
            loadStatus(true);
          }
        } catch (err: any) {
          setSessionActionMsg({ success: false, text: err?.message || 'Failed to log out other sessions.' });
        } finally {
          setRevokingAllOthers(false);
        }
      },
    });
  };

  const handleRevokeAccountSessions = (targetUserId: number, targetUsername: string, isCurrentUser: boolean) => {
    requestAuthConfirm({
      title: isCurrentUser ? 'Log Out Other Devices' : `Log Out All Devices for ${targetUsername}`,
      message: isCurrentUser
        ? 'Are you sure you want to log out all other active devices for your account? Other browsers will be logged out immediately while keeping their device records.'
        : `Are you sure you want to log out all active sessions for administrator "${targetUsername}"? They will be logged out immediately and their device records will remain visible.`,
      confirmLabel: isCurrentUser ? 'Log Out Other Devices' : 'Log Out Account Devices',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setRevokingAllOthers(true);
          setSessionActionMsg(null);
          const res = await apiRequest({
            path: '/auth/sessions/revoke',
            method: 'POST',
            data: { revoke_others: true, user_id: targetUserId },
          });
          if (res && res.success) {
            setSessionActionMsg({ success: true, text: res.message || 'Account devices logged out successfully.' });
            setTimeout(() => setSessionActionMsg(null), 4000);
            loadStatus(true);
          }
        } catch (err: any) {
          setSessionActionMsg({ success: false, text: err?.message || 'Failed to log out account devices.' });
        } finally {
          setRevokingAllOthers(false);
        }
      },
    });
  };

  // Memoized Per-Account Session Grouping with Multi-Device & Unlimited IP Telemetry
  const accountGroups: AccountSessionGroup[] = useMemo(() => {
    if (!status?.active_sessions || status.active_sessions.length === 0) {
      return [];
    }
    const map = new Map<number, AccountSessionGroup>();

    for (const sess of status.active_sessions) {
      let group = map.get(sess.user_id);
      if (!group) {
        group = {
          user_id: sess.user_id,
          user_login: sess.user_login,
          display_name: sess.display_name || sess.user_login,
          user_email: sess.user_email,
          avatar_url: sess.avatar_url,
          is_current_account: sess.user_id === status.user_id || sess.user_login === status.user_login,
          sessions: [],
          active_sessions_count: 0,
          logged_out_sessions_count: 0,
          all_distinct_ips: [],
          has_any_ip_changed: false,
          total_ip_count: 0,
        };
        map.set(sess.user_id, group);
      }
      group.sessions.push(sess);
      if (sess.is_current) {
        group.is_current_account = true;
      }
      if (sess.distinct_ips && Array.isArray(sess.distinct_ips)) {
        for (const ip of sess.distinct_ips) {
          if (ip && !group.all_distinct_ips.includes(ip)) {
            group.all_distinct_ips.push(ip);
          }
        }
      } else if (sess.login_ip && !group.all_distinct_ips.includes(sess.login_ip)) {
        group.all_distinct_ips.push(sess.login_ip);
      }
      if (sess.current_ip && !group.all_distinct_ips.includes(sess.current_ip)) {
        group.all_distinct_ips.push(sess.current_ip);
      }
      if (sess.has_ip_changed) {
        group.has_any_ip_changed = true;
      }
    }

    const groups = Array.from(map.values());
    for (const g of groups) {
      g.total_ip_count = g.all_distinct_ips.length;
      g.active_sessions_count = g.sessions.filter(s => s.is_active !== false && s.status !== 'logged_out').length;
      g.logged_out_sessions_count = g.sessions.filter(s => s.is_active === false || s.status === 'logged_out').length;

      g.sessions.sort((a, b) => {
        if (a.is_current && !b.is_current) return -1;
        if (!a.is_current && b.is_current) return 1;
        const aActive = a.is_active !== false && a.status !== 'logged_out';
        const bActive = b.is_active !== false && b.status !== 'logged_out';
        if (aActive && !bActive) return -1;
        if (!aActive && bActive) return 1;
        return (b.last_seen_raw || 0) - (a.last_seen_raw || 0);
      });
    }

    return groups.sort((a, b) => {
      if (a.is_current_account && !b.is_current_account) return -1;
      if (!a.is_current_account && b.is_current_account) return 1;
      if (a.active_sessions_count > 0 && b.active_sessions_count === 0) return -1;
      if (a.active_sessions_count === 0 && b.active_sessions_count > 0) return 1;
      return a.user_login.localeCompare(b.user_login);
    });
  }, [status?.active_sessions, status?.user_id, status?.user_login]);

  const allSiteUniqueIps = useMemo(() => {
    const set = new Set<string>();
    if (status?.active_sessions) {
      for (const s of status.active_sessions) {
        if (s.distinct_ips && Array.isArray(s.distinct_ips)) {
          for (const ip of s.distinct_ips) if (ip) set.add(ip);
        } else if (s.login_ip) {
          set.add(s.login_ip);
        }
        if (s.current_ip) set.add(s.current_ip);
      }
    }
    return Array.from(set);
  }, [status?.active_sessions]);

  useEffect(() => {
    loadStatus();
    loadAdmins();
    try {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('setup') === '1') {
        handleStartSetup();
      }
    } catch (e) {}
  }, []);

  useEffect(() => {
    if (activeTab === 'admins') {
      loadAdmins();
    }
  }, [activeTab]);

  // 2FA Actions
  const handleStartSetup = async () => {
    try {
      setSetupError(null);
      setSetupSuccess(null);
      const res = await apiRequest({ path: '/auth/2fa/setup', method: 'POST' });
      if (res && res.secret) {
        setSetupPackage(res);
      }
    } catch (err: any) {
      setSetupError(err?.message || 'Failed to start 2FA setup.');
    }
  };

  const downloadBackupCodes = (backupCodes: string[], userLogin?: string) => {
    try {
      const siteDomain = window.location.hostname.replace(/:\d+$/, '') || 'website';
      const cleanDomain = siteDomain.replace(/[^a-zA-Z0-9.-]/g, '_');
      const filename = `${cleanDomain}_2F_backup_code.txt`;

      const username = userLogin || status?.user_login || 'Administrator';
      const createdDate = new Date().toISOString().replace('T', ' ').substring(0, 19);

      const content = [
        `================================================================================`,
        `TWO-FACTOR AUTHENTICATION (2FA) EMERGENCY RECOVERY BACKUP CODES`,
        `================================================================================`,
        ``,
        `Website Domain : ${siteDomain}`,
        `Website URL    : ${window.location.origin}`,
        `Account User   : ${username}`,
        `Generated On   : ${createdDate} (UTC)`,
        ``,
        `IMPORTANT INSTRUCTIONS:`,
        `1. These backup codes are single-use emergency recovery keys strictly for`,
        `   2FA login verification on ${siteDomain}.`,
        `2. If you lose access to your primary authenticator application (Google Authenticator,`,
        `   Authy, 1Password, etc.), you can enter one of these backup codes to sign in.`,
        `3. Each backup code can be used ONLY ONCE. After using a code, cross it off your list.`,
        `4. Store this document in an encrypted, secure location (such as a password vault).`,
        ``,
        `--------------------------------------------------------------------------------`,
        `EMERGENCY BACKUP CODES:`,
        `--------------------------------------------------------------------------------`,
        ...backupCodes.map((code, idx) => ` [${idx + 1}]  ${code}`),
        ``,
        `--------------------------------------------------------------------------------`,
        `Protected by WebCare Pro Security & Two-Factor Authentication (RFC 6238 TOTP)`,
        `================================================================================`,
      ].join('\r\n');

      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.style.display = 'none';
      link.setAttribute('href', url);
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      setTimeout(() => {
        try {
          document.body.removeChild(link);
          window.URL.revokeObjectURL(url);
        } catch (e) {}
      }, 1000);

      setDownloadedCodes(true);
      setSavedBackupCodes(true);
      setTimeout(() => setDownloadedCodes(false), 3000);
      return true;
    } catch (e) {
      console.error('Failed to trigger backup codes download', e);
      return false;
    }
  };

  const handleVerifySetup = async () => {
    const requiredDigits = setupPackage?.digits || 6;
    if (!setupPackage || !setupCode.trim()) {
      setSetupError(`Please enter the ${requiredDigits}-digit code from your authenticator app.`);
      return;
    }

    try {
      setVerifyingCode(true);
      setSetupError(null);
      const res = await apiRequest({
        path: '/auth/2fa/verify-setup',
        method: 'POST',
        data: {
          code: setupCode.trim(),
        },
      });

      if (res && res.success) {
        // Trigger backup codes download ONLY after TOTP code verification succeeds
        if (!savedBackupCodes && setupPackage.backup_codes && setupPackage.backup_codes.length > 0) {
          downloadBackupCodes(setupPackage.backup_codes);
        }
        setSetupSuccess('Two-Factor Authentication is now enabled for your account! Your backup codes have been safely secured.');
        setSetupPackage(null);
        setSetupCode('');
        setSavedBackupCodes(false);
        loadStatus(true);
      } else {
        setSetupError(res?.message || 'Invalid verification code.');
      }
    } catch (err: any) {
      setSetupError(err?.message || 'Verification failed. Please check the code and try again.');
    } finally {
      setVerifyingCode(false);
    }
  };

  const handleDisable2fa = async () => {
    requestAuthConfirm({
      title: 'Disable Two-Factor Authentication',
      message: 'Are you sure you want to disable Two-Factor Authentication on your account? This will lower your login security to password-only.',
      confirmLabel: 'Disable 2FA',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setDisabling2fa(true);
          const res = await apiRequest({ path: '/auth/2fa/disable', method: 'POST' });
          if (res && res.success) {
            setSetupPackage(null);
            loadStatus(true);
          }
        } catch (err: any) {
          toast.error('Failed to disable 2FA: ' + (err?.message || 'Error'));
        } finally {
          setDisabling2fa(false);
        }
      },
    });
  };

  const handleRevokeTrustedDevices = async () => {
    requestAuthConfirm({
      title: 'Revoke Trusted Devices',
      message: 'Revoke all remembered/trusted devices for your account? You will be prompted to enter a 2FA verification code on your next login on all browsers.',
      confirmLabel: 'Revoke All Devices',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setRevokingTrustedDevices(true);
          setTrustedDeviceSuccess(null);
          const res = await apiRequest({ path: '/auth/2fa/revoke-trusted-devices', method: 'POST' });
          if (res && res.success) {
            setTrustedDeviceSuccess(res.message || 'All remembered devices have been revoked.');
            toast.success(res.message || 'All remembered devices have been revoked.');
            setTimeout(() => setTrustedDeviceSuccess(null), 5000);
            loadStatus(true);
          }
        } catch (err: any) {
          toast.error('Failed to revoke remembered devices: ' + (err?.message || 'Error'));
        } finally {
          setRevokingTrustedDevices(false);
        }
      },
    });
  };

  const handleUnlockIp = async (ip: string) => {
    try {
      const res = await apiRequest({
        path: '/auth/unlock-ip',
        method: 'POST',
        data: { ip },
      });
      if (res && res.success) {
        toast.success(`IP address ${ip} unlocked successfully.`);
        loadStatus(true);
      }
    } catch (err: any) {
      toast.error('Failed to unlock IP: ' + (err?.message || 'Error'));
    }
  };

  const handleClearAllLockouts = async () => {
    requestAuthConfirm({
      title: 'Clear All Active Lockouts',
      message: 'Are you sure you want to unblock and clear all locked IP addresses? Locked attackers and legitimate users will regain immediate login access.',
      confirmLabel: 'Unblock All IPs',
      variant: 'warning',
      onConfirm: async () => {
        try {
          const res = await apiRequest({ path: '/auth/clear-lockouts', method: 'POST' });
          if (res && res.success) {
            toast.success(res.message || 'All IP lockouts cleared.');
            loadStatus(true);
          }
        } catch (err: any) {
          toast.error('Failed to clear lockouts: ' + (err?.message || 'Error'));
        }
      },
    });
  };

  const handleSaveSettings = async () => {
    try {
      setSavingSettings(true);
      setSettingsSuccess(null);
      setSettingsError(null);

      // Direct partial save: avoid GET /settings round-trip, race conditions, and masked secret corruption
      const res = await apiRequest({
        path: '/settings',
        method: 'POST',
        data: loginSettings,
      });

      if (res && res.settings) {
        setInitialLoginSettingsSnapshot(JSON.stringify(loginSettings));
        setSettingsSuccess('Login security & rate-limiting settings saved successfully!');
        setTimeout(() => setSettingsSuccess(null), 4000);
        loadStatus(true);
      }
    } catch (err: any) {
      setSettingsError(err?.message || 'Failed to save settings.');
    } finally {
      setSavingSettings(false);
    }
  };

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setSavedBackupCodes(true);
    setTimeout(() => setCopied(false), 2500);
  };



  return (
    <div className="webcare-page-container webcare-fade-in" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Lock size={24} color="#0284c7" />
            Multi-Factor Authentication (2FA) &amp; Login Security
          </h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #64748b)' }}>
            RFC 6238 TOTP authentication and brute-force rate-limiting protection for WordPress administrators.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          {onNavigateToDashboard && (
            <button
              type="button"
              className="webcare-btn"
              onClick={onNavigateToDashboard}
              style={{ background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px', borderRadius: '8px' }}
            >
              ← Back to Scanner Dashboard
            </button>
          )}
          <button
            type="button"
            className="webcare-btn"
            onClick={() => loadStatus(true)}
            disabled={loading || refreshing}
            style={{ background: 'var(--webcare-bg-card, #fff)', border: '1px solid var(--webcare-border-strong, #cbd5e1)', color: 'var(--webcare-text-primary, #334155)', fontSize: '13px' }}
          >
            <RefreshCw size={14} className={refreshing ? 'webcare-spin-icon' : ''} />
            {refreshing ? 'Refreshing...' : 'Refresh Status'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="webcare-tabs-bar" style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <button
          type="button"
          className={`webcare-tab-link ${activeTab === '2fa' ? 'is-active' : ''}`}
          onClick={() => handleTabSwitch('2fa')}
        >
          <Smartphone size={16} /> Two-Factor Authentication (TOTP)
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeTab === 'passkeys' ? 'is-active' : ''}`}
          onClick={() => handleTabSwitch('passkeys')}
        >
          <Key size={16} /> Biometric Passkeys (WebAuthn)
        </button>

        {!isSimpleMode && (
          <button
            type="button"
            className={`webcare-tab-link ${activeTab === 'admins' ? 'is-active' : ''}`}
            onClick={() => handleTabSwitch('admins')}
          >
            <Users size={16} /> Administrator 2FA Policy ({admins.length})
          </button>
        )}

        {!isSimpleMode && (
          <button
            type="button"
            className={`webcare-tab-link ${activeTab === 'zero_trust' ? 'is-active' : ''}`}
            onClick={() => handleTabSwitch('zero_trust')}
          >
            <Fingerprint size={16} /> Zero-Trust Identity &amp; Sessions
          </button>
        )}

        {!isSimpleMode && (
          <button
            type="button"
            className={`webcare-tab-link ${activeTab === 'sessions' ? 'is-active' : ''}`}
            onClick={() => handleTabSwitch('sessions')}
          >
            <Laptop size={16} /> Active Sessions Sentinel ({status?.active_sessions?.length || 1})
          </button>
        )}

        <button
          type="button"
          className={`webcare-tab-link ${activeTab === 'lockouts' ? 'is-active' : ''}`}
          onClick={() => handleTabSwitch('lockouts')}
        >
          <ShieldAlert size={16} /> Brute-Force Lockouts ({status?.lockouts?.length || 0})
        </button>

        {!isSimpleMode && (
          <button
            type="button"
            className={`webcare-tab-link ${activeTab === 'app_passwords' ? 'is-active' : ''}`}
            onClick={() => handleTabSwitch('app_passwords')}
          >
            <Key size={16} /> REST App Passwords &amp; Phishing Sentinel
          </button>
        )}

        <button
          type="button"
          className={`webcare-tab-link ${activeTab === 'settings' ? 'is-active' : ''}`}
          onClick={() => handleTabSwitch('settings')}
        >
          <Sliders size={16} /> Security &amp; Session Settings
        </button>

        {isSimpleMode && (
          <button
            type="button"
            className="webcare-btn-micro"
            onClick={() => {
              setMode('developer');
              toast.info('Switched to Developer Mode.');
            }}
            style={{
              marginLeft: 'auto',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '5px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 600,
              background: 'var(--webcare-surface-elevated, #f1f5f9)',
              color: 'var(--webcare-primary, #6366f1)',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            title="Switch to Developer Mode to manage Administrator policies, Zero-Trust rules, active sessions, and REST app passwords"
          >
            <Sliders size={12} color="#0284c7" />
            <span>+ Show 4 Pro Tabs</span>
          </button>
        )}
      </div>

      {/* TAB 1: TWO-FACTOR AUTHENTICATION */}
      {activeTab === '2fa' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* Status & Setup Card */}
          <div className="webcare-2fa-card">
            <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <UserCheck size={18} color="#0284c7" /> Your Administrator Account Security
            </h3>

            {setupSuccess && (
              <div style={{ padding: '12px 16px', background: 'var(--webcare-status-clean-soft, #ecfdf5)', color: 'var(--webcare-status-clean, #065f46)', borderRadius: '8px', border: '1px solid var(--webcare-status-clean-border, #a7f3d0)', marginBottom: '16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} /> {setupSuccess}
              </div>
            )}

            <div className="webcare-2fa-status-box">
              <div>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px' }}>
                  Current Status
                </span>
                <div style={{ fontSize: '18px', fontWeight: 700, color: status?.user_2fa_enabled ? 'var(--webcare-status-clean, #15803d)' : 'var(--webcare-status-critical, #dc2626)', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {status?.user_2fa_enabled ? <ShieldCheck size={20} /> : <AlertTriangle size={20} />}
                  {status?.user_2fa_enabled ? '2FA Enabled & Armed' : '2FA Not Configured'}
                </div>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px', display: 'block' }}>
                  Account: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{status?.user_login || 'admin'}</strong> ({status?.user_email})
                </span>
                {status?.user_2fa_enabled && (
                  <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="webcare-badge-pill" style={{ fontSize: '11px', padding: '2px 8px', fontWeight: 600, background: status?.user_2fa_algorithm === 'sha512' ? 'rgba(79, 70, 229, 0.12)' : 'rgba(2, 132, 199, 0.12)', color: status?.user_2fa_algorithm === 'sha512' ? '#6366f1' : '#0284c7', border: '1px solid ' + (status?.user_2fa_algorithm === 'sha512' ? 'rgba(99, 102, 241, 0.3)' : 'rgba(2, 132, 199, 0.3)') }}>
                      {status?.user_2fa_algorithm === 'sha512' ? 'HMAC-SHA-512 (8 Digits)' : 'HMAC-SHA-1 (6 Digits)'}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>RFC 6238 Standard TOTP</span>
                  </div>
                )}
              </div>

              <div>
                {status?.user_2fa_enabled ? (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ background: 'var(--webcare-status-critical-soft, #fee2e2)', color: 'var(--webcare-status-critical, #991b1b)', border: '1px solid var(--webcare-status-critical-border, #fecaca)', fontSize: '12px' }}
                    onClick={handleDisable2fa}
                    disabled={disabling2fa}
                  >
                    {disabling2fa ? <Loader2 size={14} className="webcare-spin-icon" /> : <Trash2 size={14} />}
                    Disable 2FA
                  </button>
                ) : (
                  <button
                    type="button"
                    className="webcare-btn webcare-btn-primary"
                    style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '8px 16px', fontWeight: 600 }}
                    onClick={handleStartSetup}
                  >
                    <Smartphone size={15} /> Setup 2FA Now
                  </button>
                )}
              </div>
            </div>

            {/* 2FA Setup Wizard Active */}
            {setupPackage && !status?.user_2fa_enabled && (
              <div className="webcare-2fa-setup-box">
                <h4 style={{ margin: '0 0 12px 0', fontSize: '15px', color: 'var(--webcare-status-cyan, #0284c7)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <QrCode size={18} /> Step 1: Scan QR Code with Authenticator App
                </h4>
                <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Open Google Authenticator, Authy, 1Password, or Microsoft Authenticator and scan this QR code:
                </p>

                <div style={{ display: 'flex', gap: '20px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '16px' }}>
                  <div className="webcare-2fa-qr-wrap">
                    <img src={setupPackage.qr_code_url} alt="2FA QR Code" width={160} height={160} style={{ display: 'block' }} />
                  </div>

                  <div style={{ flex: 1, minWidth: '220px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '6px' }}>
                      Can't scan? Enter secret key manually:
                    </span>
                    <div className="webcare-2fa-secret-box">
                      <code className="webcare-2fa-secret-code">
                        {setupPackage.secret}
                      </code>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: copiedSecret ? '#16a34a' : 'var(--webcare-text-muted, #64748b)' }}
                        onClick={() => copyToClipboard(setupPackage.secret, setCopiedSecret)}
                        title="Copy Secret"
                      >
                        {copiedSecret ? <Check size={16} /> : <Copy size={16} />}
                      </button>
                    </div>
                  </div>
                </div>

                <h4 style={{ margin: '16px 0 10px 0', fontSize: '15px', color: 'var(--webcare-status-cyan, #0284c7)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Key size={18} /> Step 2: Emergency Recovery Codes
                </h4>
                <p style={{ margin: '0 0 10px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Save these single-use recovery codes in a password manager. If you lose your authenticator device, you can use any of these codes to sign in.
                </p>

                <div className="webcare-2fa-codes-container">
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
                    {setupPackage.backup_codes.map((code, idx) => (
                      <div key={idx} className="webcare-2fa-code-badge">
                        {code}
                      </div>
                    ))}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '12px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="webcare-2fa-copy-btn"
                      onClick={() => copyToClipboard(setupPackage.backup_codes.join('\n'), setCopiedCodes)}
                    >
                      {copiedCodes ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                      {copiedCodes ? 'Backup Codes Copied!' : 'Copy All Backup Codes'}
                    </button>

                    <button
                      type="button"
                      className="webcare-2fa-download-btn"
                      onClick={() => downloadBackupCodes(setupPackage.backup_codes)}
                      title="Download text file with backup codes and instructions"
                    >
                      {downloadedCodes ? <Check size={13} color="#16a34a" /> : <Download size={13} />}
                      {downloadedCodes ? 'Downloaded Codes (.txt)!' : 'Download Backup Codes (.txt)'}
                    </button>
                  </div>
                </div>

                <div style={{ margin: '16px 0 10px 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <h4 style={{ margin: 0, fontSize: '15px', color: 'var(--webcare-status-cyan, #0284c7)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Smartphone size={18} /> Step 3: Enter {setupPackage.digits || 6}-Digit Code to Confirm &amp; Arm
                  </h4>
                  <span className="webcare-badge-pill" style={{ fontSize: '11px', padding: '2px 8px', fontWeight: 600, background: setupPackage.algorithm === 'sha512' ? 'rgba(79, 70, 229, 0.14)' : 'rgba(2, 132, 199, 0.14)', color: setupPackage.algorithm === 'sha512' ? '#6366f1' : '#0284c7', border: '1px solid ' + (setupPackage.algorithm === 'sha512' ? 'rgba(99, 102, 241, 0.35)' : 'rgba(2, 132, 199, 0.35)') }}>
                    {setupPackage.algorithm === 'sha512' ? 'SHA-512 (8 Digits)' : 'SHA-1 (6 Digits)'}
                  </span>
                </div>

                {setupError && (
                  <div style={{ padding: '10px 14px', background: 'var(--webcare-status-critical-soft, #fef2f2)', color: 'var(--webcare-status-critical, #dc2626)', borderRadius: '8px', border: '1px solid var(--webcare-status-critical-border, #fecaca)', marginBottom: '12px', fontSize: '13px' }}>
                    {setupError}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                  <input
                    type="text"
                    maxLength={setupPackage.digits || 6}
                    placeholder={setupPackage.digits === 8 ? '12345678' : '123456'}
                    value={setupCode}
                    onChange={(e) => setSetupCode(e.target.value.replace(/[^0-9]/g, ''))}
                    className="webcare-2fa-input-code"
                    style={{ letterSpacing: setupPackage.digits === 8 ? '3px' : '4px', maxWidth: setupPackage.digits === 8 ? '210px' : '170px' }}
                  />
                  <button
                    type="button"
                    className="webcare-btn webcare-btn-primary"
                    style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '10px 18px', fontWeight: 600 }}
                    onClick={handleVerifySetup}
                    disabled={verifyingCode}
                  >
                    {verifyingCode ? <Loader2 size={16} className="webcare-spin-icon" /> : <Check size={16} />}
                    {verifyingCode ? 'Verifying Code...' : 'Verify & Enable 2FA'}
                  </button>
                </div>
              </div>
            )}

            {status?.user_2fa_enabled && (
              <>
                <div className="webcare-2fa-mini-panel" style={{ marginTop: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div>
                      <h4 style={{ margin: '0 0 4px 0', fontSize: '14px', color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Laptop size={16} color="#0284c7" /> Remembered Trusted Devices
                      </h4>
                      <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)' }}>
                        {status?.trusted_devices_count && status.trusted_devices_count > 0 ? (
                          <span>You currently have <strong style={{ color: 'var(--webcare-text-heading, #0f172a)' }}>{status.trusted_devices_count}</strong> active remembered device(s) bypassing 2FA for up to {status.auth_2fa_remember_days || 7} days.</span>
                        ) : (
                          <span>No devices are currently remembered. Check "Remember this device for 7 days" when signing in to skip 2FA challenges.</span>
                        )}
                      </p>
                    </div>
                    {status?.trusted_devices_count && status.trusted_devices_count > 0 ? (
                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={handleRevokeTrustedDevices}
                        disabled={revokingTrustedDevices}
                        style={{ background: 'var(--webcare-bg-panel, #fff)', border: '1px solid var(--webcare-status-critical-border, #fecaca)', color: 'var(--webcare-status-critical, #b91c1c)', fontSize: '12px', padding: '6px 12px' }}
                      >
                        {revokingTrustedDevices ? <Loader2 size={13} className="webcare-spin-icon" /> : <ShieldAlert size={13} />}
                        Revoke All Remembered Devices
                      </button>
                    ) : null}
                  </div>

                  {trustedDeviceSuccess && (
                    <div style={{ marginTop: '12px', padding: '8px 12px', background: 'var(--webcare-status-clean-soft, #ecfdf5)', color: 'var(--webcare-status-clean, #065f46)', borderRadius: '6px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle2 size={14} /> {trustedDeviceSuccess}
                    </div>
                  )}
                </div>

                {/* Emergency Backup Codes Management Card */}
                <div className="webcare-2fa-mini-panel">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div>
                      <h4 style={{ margin: '0 0 4px 0', fontSize: '14px', color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Key size={16} color="#0284c7" /> Emergency Backup Codes
                      </h4>
                      <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)' }}>
                        {typeof status?.backup_codes_count === 'number' && status.backup_codes_count > 0 ? (
                          <span>You have <strong style={{ color: 'var(--webcare-text-heading, #0f172a)' }}>{status.backup_codes_count}</strong> single-use emergency recovery backup code(s) remaining.</span>
                        ) : (
                          <span style={{ color: 'var(--webcare-status-critical, #dc2626)', fontWeight: 600 }}>⚠️ You have 0 backup codes remaining. Regenerate backup codes now to prevent lockout!</span>
                        )}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="webcare-btn"
                      onClick={handleRegenerateMyBackupCodes}
                      disabled={regeneratingCodes}
                      style={{ background: 'var(--webcare-status-cyan-soft, #e0f2fe)', border: '1px solid var(--webcare-status-cyan-border, #bae6fd)', color: 'var(--webcare-status-cyan, #0369a1)', fontSize: '12px', padding: '7px 14px', fontWeight: 600 }}
                      title="Generate 8 new single-use backup recovery codes"
                    >
                      {regeneratingCodes ? <Loader2 size={13} className="webcare-spin-icon" /> : <RefreshCw size={13} />}
                      {regeneratingCodes ? 'Regenerating...' : 'Regenerate Backup Codes'}
                    </button>
                  </div>

                  {regenSuccessMsg && (
                    <div style={{ marginTop: '12px', padding: '8px 12px', background: 'var(--webcare-status-clean-soft, #ecfdf5)', color: 'var(--webcare-status-clean, #065f46)', borderRadius: '6px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle2 size={14} /> {regenSuccessMsg}
                    </div>
                  )}
                </div>
              </>
            )}

            <div style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.6, marginTop: '20px' }}>
              <strong>How It Works:</strong> After entering your username and password on <code>wp-login.php</code>,
              WordPress will request a rotating 6-digit TOTP code. Even if an attacker steals your admin password,
              they cannot log in without your physical device.
            </div>
          </div>

          {/* Compatibility & Info Card */}
          <div className="webcare-2fa-card">
            <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Smartphone size={18} color="#0284c7" /> Supported Authenticator Apps
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--webcare-text-secondary, #64748b)', margin: '0 0 16px 0', lineHeight: 1.5 }}>
              WebCare Pro Security & Firewall implements the universal open standard <strong>RFC 6238 TOTP</strong>, making it 100% compatible with:
            </p>

            <ul style={{ margin: '0 0 20px 0', paddingLeft: '20px', fontSize: '13px', color: 'var(--webcare-text-primary, #334155)', lineHeight: 1.8 }}>
              <li><strong>Google Authenticator</strong> (iOS &amp; Android)</li>
              <li><strong>Authy by Twilio</strong> (iOS, Android, Desktop)</li>
              <li><strong>1Password &amp; Bitwarden</strong> (Built-in TOTP generators)</li>
              <li><strong>Microsoft Authenticator</strong></li>
              <li><strong>YubiKey OATH-TOTP</strong> hardware keys</li>
            </ul>

            <div style={{ background: 'var(--webcare-bg-elevated, #f8fafc)', padding: '14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
              <strong style={{ display: 'block', color: 'var(--webcare-text-heading, #0f172a)', marginBottom: '4px' }}>No External API Dependency:</strong>
              The TOTP algorithm executes completely in pure PHP on your own server. Your secret keys never leave your WordPress database.
            </div>
          </div>
        </div>
      )}

      {/* TAB: ADMINISTRATOR 2FA GOVERNANCE, USERS DIRECTORY & ENFORCEMENT POLICY */}
      {activeTab === 'admins' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Policy Enforce Control Banner */}
          <div className="webcare-admin-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
              <div>
                <h3 style={{ margin: '0 0 6px 0', fontSize: '17px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={20} color="#4f46e5" /> Mandatory Administrator 2FA Enforcement Policy
                </h3>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)', maxWidth: '720px', lineHeight: 1.5 }}>
                  Require all users with the <strong>Administrator</strong> role to configure Two-Factor Authentication. Choose between immediate lock on next login or a grace period in days.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  type="button"
                  className="webcare-btn"
                  onClick={loadAdmins}
                  disabled={loadingAdmins}
                  style={{ background: 'var(--webcare-bg-panel, #fff)', border: '1px solid var(--webcare-border-strong, #cbd5e1)', color: 'var(--webcare-text-primary, #334155)', fontSize: '12.5px' }}
                >
                  <RefreshCw size={13} className={loadingAdmins ? 'webcare-spin-icon' : ''} />
                  {loadingAdmins ? 'Refreshing...' : 'Reload Directory'}
                </button>
              </div>
            </div>

            {/* Action Feedback Alerts */}
            {adminActionMsg && (
              <div style={{
                padding: '12px 16px',
                borderRadius: '8px',
                marginBottom: '18px',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: adminActionMsg.success ? '#ecfdf5' : '#fef2f2',
                color: adminActionMsg.success ? '#065f46' : '#991b1b',
                border: adminActionMsg.success ? '1px solid #a7f3d0' : '1px solid #fecaca'
              }}>
                {adminActionMsg.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                <span>{adminActionMsg.text}</span>
              </div>
            )}

            {/* Policy Toggles & Grace Period Form */}
            <div className="webcare-admin-policy-banner">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, minWidth: '280px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={policyEnforceAdmins}
                    onChange={(e) => setPolicyEnforceAdmins(e.target.checked)}
                    style={{ accentColor: '#4f46e5', width: '18px', height: '18px' }}
                  />
                  <span>Enforce Two-Factor Authentication on All Administrators</span>
                </label>

                {policyEnforceAdmins && (
                  <div style={{ paddingLeft: '28px', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                      Enforcement Timeline:
                    </span>
                    <select
                      value={policyMode}
                      onChange={(e) => {
                        const m = e.target.value as 'immediate' | 'grace_period' | 'remind_login';
                        setPolicyMode(m);
                        if (m === 'immediate') {
                          setPolicyGraceDays(0);
                        } else if (m === 'remind_login') {
                          setPolicyGraceDays(policyGraceDays > 0 ? policyGraceDays : 30);
                        } else if (policyGraceDays <= 0) {
                          setPolicyGraceDays(7);
                        }
                      }}
                      style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-strong, #cbd5e1)', fontSize: '13px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                    >
                      <option value="remind_login">Remind on Next Login & Grace Period (Days)</option>
                      <option value="grace_period">Strict Enforcement with Grace Period (Lock after X days)</option>
                      <option value="immediate">Force Immediately on Next Login</option>
                    </select>

                    {policyMode !== 'immediate' && (
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        <input
                          type="number"
                          min={1}
                          max={90}
                          value={policyGraceDays || (policyMode === 'remind_login' ? 30 : 7)}
                          onChange={(e) => setPolicyGraceDays(Math.max(1, parseInt(e.target.value) || 1))}
                          style={{ width: '65px', padding: '6px 8px', borderRadius: '6px', border: '1px solid var(--webcare-border-strong, #cbd5e1)', fontSize: '13px', background: 'var(--webcare-bg-panel, #fff)', color: 'var(--webcare-text-primary, #0f172a)' }}
                        />
                        <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                          {policyMode === 'remind_login' ? 'Days of reminder notices before locking' : 'Days to configure before restrictions'}
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div>
                <button
                  type="button"
                  className="webcare-btn webcare-btn-primary"
                  onClick={() => handleSavePolicy(policyEnforceAdmins, policyMode, policyGraceDays)}
                  disabled={policySaving}
                  style={{
                    background: '#4f46e5',
                    color: '#fff',
                    fontSize: '13px',
                    padding: '8px 18px',
                    fontWeight: 600,
                    borderRadius: '8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {policySaving ? <Loader2 size={14} className="webcare-spin-icon" /> : <Check size={14} />}
                  {policySaving ? 'Applying Policy...' : 'Save & Enforce Policy'}
                </button>
              </div>
            </div>

            {/* Administrators Table */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)' }}>
                Administrator Accounts ({admins.length})
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                {admins.filter(a => a.is_2fa_enabled).length} of {admins.length} administrators secured with 2FA
              </div>
            </div>

            <div className="webcare-admin-table-wrap">
              <table className="webcare-admin-table">
                <thead>
                  <tr>
                    <th>Administrator</th>
                    <th>2FA Status</th>
                    <th>Policy Compliance</th>
                    <th>Trusted Devices</th>
                    <th>Lockout / Brute Force</th>
                    <th>Quick Management</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingAdmins && admins.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        <Loader2 size={24} className="webcare-spin-icon" style={{ margin: '0 auto 8px auto', display: 'block' }} />
                        Loading administrator directory...
                      </td>
                    </tr>
                  ) : admins.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '24px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        No administrator accounts found.
                      </td>
                    </tr>
                  ) : (
                    admins.map((adm) => (
                      <tr key={adm.user_id}>
                        <td>
                          <div className="webcare-admin-user-cell">
                            <img
                              src={adm.avatar_url}
                              alt=""
                              className="webcare-admin-user-avatar"
                            />
                            <div>
                              <div className="webcare-admin-user-name">
                                <span>{adm.display_name}</span>
                                {adm.is_current_user && (
                                  <span className="webcare-admin-you-badge">
                                    YOU
                                  </span>
                                )}
                              </div>
                              <div className="webcare-admin-user-meta">
                                <span>{adm.user_login}</span> &bull; <span>{adm.user_email}</span>
                              </div>
                            </div>
                          </div>
                        </td>

                        <td>
                          {adm.is_2fa_enabled ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                              <span className="webcare-admin-badge webcare-admin-badge-clean">
                                <ShieldCheck size={13} /> Active (TOTP)
                              </span>
                              <span style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', paddingLeft: '4px' }}>
                                {adm.two_fa_algorithm === 'sha512' ? 'SHA-512 (8 Digits)' : 'SHA-1 (6 Digits)'}
                              </span>
                            </div>
                          ) : (
                            <span className="webcare-admin-badge webcare-admin-badge-danger">
                              <ShieldAlert size={13} /> Disabled
                            </span>
                          )}
                        </td>

                        <td>
                          {adm.is_2fa_enabled ? (
                            <span className="webcare-admin-compliance-clean">
                              ✓ Compliant
                            </span>
                          ) : adm.compliance.status === 'remind_login' ? (
                            <span className="webcare-admin-badge webcare-admin-badge-info">
                              <Clock size={12} /> Remind on Login ({adm.compliance.days_left}d left)
                            </span>
                          ) : adm.compliance.status === 'grace_period' ? (
                            <span className="webcare-admin-badge webcare-admin-badge-warn">
                              <Clock size={12} /> {adm.compliance.days_left}d grace remaining
                            </span>
                          ) : adm.compliance.status === 'enforcement_required' ? (
                            <span className="webcare-admin-badge webcare-admin-badge-danger">
                              <AlertCircle size={12} /> Enforced (Action Required)
                            </span>
                          ) : (
                            <span className="webcare-admin-compliance-optional">
                              Optional
                            </span>
                          )}
                        </td>

                        <td>
                          <span className="webcare-admin-devices-count">
                            {adm.trusted_devices} {adm.trusted_devices === 1 ? 'device' : 'devices'}
                          </span>
                        </td>

                        <td>
                          {adm.is_locked ? (
                            <span className="webcare-admin-badge webcare-admin-badge-danger" title={`Locked IPs: ${adm.locked_ips.join(', ')}`}>
                              <Lock size={12} /> Locked Out ({adm.locked_ips.length} IP)
                            </span>
                          ) : (
                            <span className="webcare-admin-lockout-clear">
                              ✓ Clear / Unlocked
                            </span>
                          )}
                        </td>

                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            {adm.is_locked && (
                              <button
                                type="button"
                                className="webcare-admin-btn-action webcare-admin-btn-unlock"
                                onClick={() => handleAdminUnlockLockout(adm)}
                                disabled={adminActionLoading === adm.user_id}
                                title="Unlock IP address & rate-limiting lockout for this user"
                              >
                                <Unlock size={12} /> Unlock Lockout
                              </button>
                            )}

                            {adm.is_2fa_enabled ? (
                              <button
                                type="button"
                                className="webcare-admin-btn-action webcare-admin-btn-disable"
                                onClick={() => handleAdminDisable2fa(adm)}
                                disabled={adminActionLoading === adm.user_id}
                                title="Emergency unlock: Disable 2FA if admin lost their phone/keys"
                              >
                                {adminActionLoading === adm.user_id ? <Loader2 size={12} className="webcare-spin-icon" /> : <UserX size={12} />}
                                Disable 2FA
                              </button>
                            ) : null}

                            {adm.is_2fa_enabled && (
                              <button
                                type="button"
                                className="webcare-admin-btn-action webcare-admin-btn-codes"
                                onClick={() => handleAdminRegenerateBackupCodes(adm)}
                                disabled={adminActionLoading === adm.user_id}
                                title={`Generate new emergency backup codes for ${adm.user_login} (${adm.backup_codes_count ?? 8} remaining)`}
                              >
                                {adminActionLoading === adm.user_id ? <Loader2 size={12} className="webcare-spin-icon" /> : <RefreshCw size={12} />}
                                New Codes {typeof adm.backup_codes_count === 'number' ? `(${adm.backup_codes_count})` : ''}
                              </button>
                            )}

                            <button
                              type="button"
                              className="webcare-admin-btn-action webcare-admin-btn-setup"
                              onClick={() => handleAdminReset2fa(adm)}
                              disabled={adminActionLoading === adm.user_id}
                              title="Generate brand new QR Code & emergency backup keys for this admin"
                            >
                              {adminActionLoading === adm.user_id ? <Loader2 size={12} className="webcare-spin-icon" /> : <Key size={12} />}
                              {adm.is_2fa_enabled ? 'Reset Keys' : 'Enable & Setup'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Admin 2FA Setup Package Delivery Modal */}
      {adminSetupModal.isOpen && adminSetupModal.setupPackage && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.7)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 99999,
          padding: '20px'
        }}>
          <div className="webcare-admin-card" style={{ maxWidth: '520px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={18} color="#4f46e5" /> New 2FA Credentials: {adminSetupModal.userLogin}
              </h3>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setAdminSetupModal({ isOpen: false, userLogin: '', setupPackage: null })}
                style={{ border: 'none', background: 'transparent', fontSize: '18px', color: 'var(--webcare-text-muted, #64748b)', cursor: 'pointer' }}
              >
                &times;
              </button>
            </div>

            <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
              A new 2FA secret has been provisioned and activated for administrator <strong>{adminSetupModal.userLogin}</strong>. Provide this QR code or Secret Key directly to them to configure their Authenticator app.
            </p>

            {/* QR Code Presentation */}
            <div style={{ textAlign: 'center', padding: '16px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)', marginBottom: '16px' }}>
              <img
                src={adminSetupModal.setupPackage.qr_code_url}
                alt="2FA QR Code"
                style={{ width: '160px', height: '160px', margin: '0 auto 12px auto', display: 'block', background: '#fff', padding: '8px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
              />
              <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#64748b', marginBottom: '4px' }}>
                Base32 Secret Key
              </div>
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px' }}>
                <code style={{ fontSize: '14px', fontWeight: 700, letterSpacing: '2px', color: '#0284c7', background: 'var(--webcare-bg-card, #fff)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--webcare-border-strong, #cbd5e1)' }}>
                  {adminSetupModal.setupPackage.secret}
                </code>
                <button
                  type="button"
                  className="webcare-btn"
                  onClick={() => copyToClipboard(adminSetupModal.setupPackage!.secret, setCopiedSecret)}
                  style={{ fontSize: '11px', padding: '4px 8px', background: 'var(--webcare-bg-card, #fff)', border: '1px solid var(--webcare-border-strong, #cbd5e1)', color: 'var(--webcare-text-primary, #334155)' }}
                >
                  {copiedSecret ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Backup Codes */}
            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <span>Emergency Backup Codes (Single-Use):</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={() => copyToClipboard(adminSetupModal.setupPackage!.backup_codes.join('\n'), setCopiedCodes)}
                    style={{ fontSize: '11px', padding: '3px 8px', background: 'var(--webcare-bg-panel, #fff)', border: '1px solid var(--webcare-border-strong, #cbd5e1)' }}
                  >
                    {copiedCodes ? <Check size={11} color="#16a34a" /> : <Copy size={11} />}
                    {copiedCodes ? 'Copied Codes!' : 'Copy All Codes'}
                  </button>

                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={() => downloadBackupCodes(adminSetupModal.setupPackage!.backup_codes, adminSetupModal.userLogin)}
                    style={{ fontSize: '11px', padding: '3px 8px', background: '#e0f2fe', color: '#0369a1', border: '1px solid #bae6fd', fontWeight: 600 }}
                  >
                    {downloadedCodes ? <Check size={11} color="#16a34a" /> : <Download size={11} />}
                    {downloadedCodes ? 'Downloaded!' : 'Download (.txt)'}
                  </button>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px', background: 'var(--webcare-bg-elevated, #f8fafc)', padding: '12px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                {adminSetupModal.setupPackage.backup_codes.map((code, idx) => (
                  <code key={idx} style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #334155)', textAlign: 'center', padding: '3px', background: 'var(--webcare-bg-panel, #fff)', borderRadius: '4px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                    {code}
                  </code>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="webcare-btn webcare-btn-primary"
                onClick={() => setAdminSetupModal({ isOpen: false, userLogin: '', setupPackage: null })}
                style={{ background: '#4f46e5', color: '#fff', fontSize: '13px', padding: '8px 20px', borderRadius: '8px' }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Emergency Backup Codes Delivery / Regeneration Modal */}
      {backupCodesModal.isOpen && backupCodesModal.backupCodes.length > 0 && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.7)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 99999,
          padding: '20px'
        }}>
          <div className="webcare-admin-card" style={{ maxWidth: '520px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={18} color="#0284c7" /> Emergency Backup Codes: {backupCodesModal.userLogin}
              </h3>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setBackupCodesModal({ isOpen: false, userLogin: '', backupCodes: [] })}
                style={{ border: 'none', background: 'transparent', fontSize: '18px', color: 'var(--webcare-text-muted, #64748b)', cursor: 'pointer' }}
              >
                &times;
              </button>
            </div>

            <div style={{ padding: '12px 14px', background: '#ecfdf5', borderRadius: '8px', border: '1px solid #a7f3d0', color: '#065f46', fontSize: '13px', marginBottom: '16px', lineHeight: 1.5 }}>
              <strong>✓ New Backup Codes Active:</strong> 8 brand-new single-use emergency recovery keys have been generated. Any previous backup codes are now permanently revoked.
            </div>

            <p style={{ margin: '0 0 14px 0', fontSize: '12.5px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
              Save or download this file now. If you ever lose your phone or authenticator app, each code can be used once as your 2FA verification password.
            </p>

            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <span>Recovery Backup Codes (Single-Use):</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={() => copyToClipboard(backupCodesModal.backupCodes.join('\n'), setCopiedCodes)}
                    style={{ fontSize: '11px', padding: '4px 10px', background: 'var(--webcare-bg-panel, #fff)', border: '1px solid var(--webcare-border-strong, #cbd5e1)' }}
                  >
                    {copiedCodes ? <Check size={11} color="#16a34a" /> : <Copy size={11} />}
                    {copiedCodes ? 'Copied Codes!' : 'Copy All Codes'}
                  </button>

                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={() => downloadBackupCodes(backupCodesModal.backupCodes, backupCodesModal.userLogin)}
                    style={{ fontSize: '11px', padding: '4px 10px', background: '#e0f2fe', color: '#0369a1', border: '1px solid #bae6fd', fontWeight: 600 }}
                  >
                    {downloadedCodes ? <Check size={11} color="#16a34a" /> : <Download size={11} />}
                    {downloadedCodes ? 'Downloaded!' : 'Download (.txt)'}
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', padding: '14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                {backupCodesModal.backupCodes.map((code, idx) => (
                  <code key={idx} style={{ fontSize: '12.5px', color: 'var(--webcare-text-primary, #334155)', textAlign: 'center', padding: '5px', background: 'var(--webcare-bg-panel, #fff)', borderRadius: '4px', border: '1px solid var(--webcare-border, #e2e8f0)', fontWeight: 600, letterSpacing: '0.5px' }}>
                    {code}
                  </code>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                className="webcare-btn webcare-btn-primary"
                onClick={() => setBackupCodesModal({ isOpen: false, userLogin: '', backupCodes: [] })}
                style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '8px 22px', borderRadius: '8px', fontWeight: 600 }}
              >
                I Have Saved My Codes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB: ZERO-TRUST IDENTITY & SESSION FORENSICS */}
      {activeTab === 'zero_trust' && (
        <IdentityForensicsCard
          apiRequest={apiRequest}
          initialSubTab={(initialNestedSubTab as any) || (new URLSearchParams(window.location.search).get('subtab') as any) || 'sessions'}
          onSubTabChange={(sub) => handleTabSwitch('zero_trust', sub)}
        />
      )}

      {/* TAB 1.5: ACTIVE SESSIONS SENTINEL */}
      {activeTab === 'sessions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Top Banner Action */}
          <div className="webcare-sentinel-banner">
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px', flexWrap: 'wrap' }}>
                <div className="webcare-sentinel-icon-wrap">
                  <Radio size={20} />
                </div>
                <h3 className="webcare-sentinel-title">
                  Concurrent Administrator Session Sentinel
                </h3>
                <span className="webcare-sentinel-badge">
                  Anti-Session Hijack Active
                </span>
                <span className="webcare-session-forensic-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 700, padding: '3px 8px', borderRadius: '12px', background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                  <ShieldCheck size={11} /> Database &amp; Vault Encrypted
                </span>
                <span className="webcare-session-forensic-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 700, padding: '3px 8px', borderRadius: '12px', background: '#e0f2fe', color: '#0369a1', border: '1px solid #bae6fd' }}>
                  <Lock size={11} /> 30-Day Retention Locked
                </span>
              </div>
              <p className="webcare-sentinel-desc">
                Monitors authenticated administrator accounts and devices in real time with dual AES-256-GCM encrypted persistence (Database &amp; Security Vault) and mandatory 30-day forensic retention.
              </p>
            </div>

            <button
              type="button"
              className="webcare-btn"
              style={{
                background: '#ef4444',
                color: '#fff',
                fontSize: '13px',
                fontWeight: 600,
                borderRadius: '8px',
                padding: '9px 18px',
                border: 'none',
                boxShadow: '0 2px 6px rgba(239, 68, 68, 0.35)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer'
              }}
              onClick={handleRevokeAllOtherSessions}
              disabled={revokingAllOthers}
            >
              {revokingAllOthers ? <Loader2 size={14} className="webcare-spin-icon" /> : <LogOut size={14} />}
              {revokingAllOthers ? 'Revoking...' : 'Revoke All Other Sessions'}
            </button>
          </div>

          {sessionActionMsg && (
            <div style={{
              padding: '12px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: sessionActionMsg.success ? '#ecfdf5' : '#fef2f2',
              color: sessionActionMsg.success ? '#065f46' : '#991b1b',
              border: sessionActionMsg.success ? '1px solid #a7f3d0' : '1px solid #fecaca'
            }}>
              {sessionActionMsg.success ? <CheckCircle2 size={16} color="#10b981" /> : <AlertTriangle size={16} color="#ef4444" />}
              <span>{sessionActionMsg.text}</span>
            </div>
          )}

          {/* Sentinel Metrics Summary Bar */}
          <div className="webcare-sentinel-stats-row">
            <div className="webcare-sentinel-stat-card">
              <Users size={15} color="#0284c7" />
              <span>Online Accounts:</span>
              <span className="stat-count">{accountGroups.length}</span>
            </div>
            <div className="webcare-sentinel-stat-card">
              <Laptop size={15} color="#4f46e5" />
              <span>Active Devices:</span>
              <span className="stat-count" style={{ color: '#4338ca' }}>{status?.active_sessions?.length || 0}</span>
            </div>
            <div className="webcare-sentinel-stat-card">
              <Globe size={15} color="#6366f1" />
              <span>Observed IPs:</span>
              <span className="stat-count" style={{ color: '#4f46e5' }}>{allSiteUniqueIps.length}</span>
            </div>
            <div className="webcare-sentinel-stat-card">
              <Fingerprint size={15} color="#10b981" />
              <span>Passkey Verified:</span>
              <span className="stat-count" style={{ color: '#047857' }}>
                {status?.active_sessions?.filter(s => s.auth_type === 'passkey').length || 0}
              </span>
            </div>
            <div className="webcare-sentinel-stat-card">
              <ShieldCheck size={15} color="#3b82f6" />
              <span>2FA Protected:</span>
              <span className="stat-count" style={{ color: '#1d4ed8' }}>
                {status?.active_sessions?.filter(s => s.auth_type === '2fa').length || 0}
              </span>
            </div>
            {(status?.active_sessions?.filter(s => s.auth_type === 'magic_link').length || 0) > 0 && (
              <div className="webcare-sentinel-stat-card">
                <Zap size={15} color="#8b5cf6" />
                <span>Support Links:</span>
                <span className="stat-count" style={{ color: '#7e22ce' }}>
                  {status?.active_sessions?.filter(s => s.auth_type === 'magic_link').length || 0}
                </span>
              </div>
            )}
            <div className="webcare-sentinel-stat-card">
              <Lock size={15} color="#f59e0b" />
              <span>Password Only:</span>
              <span className="stat-count" style={{ color: '#b45309' }}>
                {status?.active_sessions?.filter(s => s.auth_type === 'password' || !s.auth_type).length || 0}
              </span>
            </div>
          </div>

          {/* Section Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Laptop size={18} color="#0284c7" /> Active Administrator Accounts ({accountGroups.length})
              </h3>
              <span style={{ fontSize: '12px', color: '#64748b' }}>
                Grouped on an account basis with multi-device sessions, unlimited IP history tracking, and individual revocation controls.
              </span>
            </div>

            {accountGroups.length > 0 && (
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button
                  type="button"
                  className="webcare-btn-micro webcare-action-btn-clean"
                  onClick={() => {
                    const anyExpanded = accountGroups.some(a => !!expandedAccounts[a.user_id]);
                    if (anyExpanded) {
                      setExpandedAccounts({});
                    } else {
                      const allExp: Record<number, boolean> = {};
                      accountGroups.forEach(a => { allExp[a.user_id] = true; });
                      setExpandedAccounts(allExp);
                    }
                  }}
                  title={accountGroups.some(a => !!expandedAccounts[a.user_id]) ? "Collapse all connected device lists" : "Expand all connected device lists"}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 14px', fontSize: '12px', fontWeight: 600, borderRadius: '8px' }}
                >
                  {accountGroups.some(a => !!expandedAccounts[a.user_id]) ? (
                    <>
                      <ChevronUp size={13} />
                      <span>Collapse All</span>
                    </>
                  ) : (
                    <>
                      <ChevronDown size={13} />
                      <span>Expand All Devices</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {accountGroups.length === 0 ? (
            <div className="webcare-card" style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b', borderRadius: '12px' }}>
              <p>No active administrator sessions detected.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {accountGroups.map((account) => {
                const otherActiveSessionsCount = account.sessions.filter(s => !s.is_current && s.is_active !== false && s.status !== 'logged_out').length;
                const anyActiveSessionsCount = account.sessions.filter(s => s.is_active !== false && s.status !== 'logged_out').length;
                const isExpanded = !!expandedAccounts[account.user_id];

                return (
                  <div key={account.user_id} className="webcare-session-account-card">
                    {/* Account Header */}
                    <div className="webcare-session-account-header">
                      <div className="webcare-session-account-user-info">
                        <div className="webcare-session-avatar-wrap">
                          <img
                            src={account.avatar_url}
                            alt={account.user_login}
                            className="webcare-session-account-avatar"
                          />
                          {account.sessions.some(s => s.is_current) && (
                            <span className="webcare-session-online-dot" title="Active on this device" />
                          )}
                        </div>

                        <div className="webcare-session-account-meta">
                          <div className="webcare-session-account-title-row">
                            <span className="webcare-session-account-login">{account.user_login}</span>
                            <button
                              type="button"
                              className={`webcare-session-forensics-btn ${forensicsModal.isOpen && forensicsModal.userId === account.user_id ? 'is-active' : ''}`}
                              onClick={() => {
                                if (forensicsModal.isOpen && forensicsModal.userId === account.user_id) {
                                  setForensicsModal({ isOpen: false, userId: null, username: '' });
                                } else {
                                  setForensicsModal({ isOpen: true, userId: account.user_id, username: account.user_login });
                                }
                              }}
                              title={forensicsModal.isOpen && forensicsModal.userId === account.user_id ? 'Close device forensics' : `Inspect forensics & login audit for ${account.user_login}`}
                            >
                              <Eye size={11} /> {forensicsModal.isOpen && forensicsModal.userId === account.user_id ? 'Hide Forensics' : 'Forensics'}
                            </button>
                            <span className="webcare-session-account-email">({account.user_email})</span>
                          </div>

                          <div className="webcare-session-account-badges-row">
                            <span className="webcare-firewall-role-chip">
                              <ShieldCheck size={11} /> Administrator
                            </span>
                            <button
                              type="button"
                              className={`webcare-session-badge-pill webcare-session-badge-clickable ${isExpanded ? 'is-active-filter' : ''}`}
                              onClick={() => toggleAccountDevices(account.user_id)}
                              title={isExpanded ? "Collapse device list" : "Expand device list"}
                            >
                              <Laptop size={11} color="#0284c7" />
                              <span>
                                {account.sessions.length} {account.sessions.length === 1 ? 'Device' : 'Devices'}
                                {account.logged_out_sessions_count > 0 ? ` (${account.active_sessions_count} Active)` : ' Connected'}
                              </span>
                              {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                            </button>
                            <span className="webcare-session-badge-pill">
                              <Globe size={11} color="#6366f1" />
                              <span>{account.all_distinct_ips.length} {account.all_distinct_ips.length === 1 ? 'Observed IP' : 'Observed IPs'}</span>
                            </span>
                            {account.has_any_ip_changed && (
                              <span className="webcare-session-badge-pill webcare-badge-warning" title="Network shifts / IP changes detected during active sessions">
                                <AlertTriangle size={11} color="#b45309" />
                                <span>IP Change Detected</span>
                              </span>
                            )}
                            {account.is_current_account && (
                              <span className="webcare-session-badge-pill webcare-badge-current">
                                <Check size={11} strokeWidth={3} /> Your Account
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Account Level Action Button */}
                      <div className="webcare-session-account-action-wrap">
                        {account.is_current_account ? (
                          otherActiveSessionsCount > 0 ? (
                            <button
                              type="button"
                              className="webcare-btn-danger-outline"
                              onClick={() => handleRevokeAccountSessions(account.user_id, account.user_login, true)}
                              disabled={revokingAllOthers}
                            >
                              {revokingAllOthers ? <Loader2 size={13} className="webcare-spin-icon" /> : <LogOut size={13} />}
                              <span>Log Out Other Devices ({otherActiveSessionsCount})</span>
                            </button>
                          ) : (
                            <span className="webcare-session-badge-pill webcare-badge-current">
                              <Check size={11} /> Single Device Active
                            </span>
                          )
                        ) : (
                          anyActiveSessionsCount > 0 ? (
                            <button
                              type="button"
                              className="webcare-btn-danger-outline"
                              onClick={() => handleRevokeAccountSessions(account.user_id, account.user_login, false)}
                              disabled={revokingAllOthers}
                            >
                              {revokingAllOthers ? <Loader2 size={13} className="webcare-spin-icon" /> : <UserX size={13} />}
                              <span>Log Out All Devices ({anyActiveSessionsCount})</span>
                            </button>
                          ) : (
                            <span className="webcare-session-badge-pill webcare-badge-neutral">
                              <LogOut size={11} /> All Devices Logged Out
                            </span>
                          )
                        )}
                      </div>
                    </div>

                    {/* Inline Expandable Forensics Panel Below User Account */}
                    {forensicsModal.isOpen && forensicsModal.userId === account.user_id && (
                      <div className="webcare-session-inline-forensics">
                        <UserSessionForensicsModal
                          isOpen={true}
                          userId={account.user_id}
                          username={account.user_login}
                          onClose={() => setForensicsModal({ isOpen: false, userId: null, username: '' })}
                          apiRequest={apiRequest}
                          inline={true}
                        />
                      </div>
                    )}

                    {/* Connected Devices List (Expandable Accordion) */}
                    <div className={`webcare-session-devices-section ${isExpanded ? 'is-expanded' : 'is-collapsed'}`}>
                      <div
                        className={`webcare-session-devices-toggle-bar ${isExpanded ? 'is-expanded' : 'is-collapsed'}`}
                        onClick={() => toggleAccountDevices(account.user_id)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            toggleAccountDevices(account.user_id);
                          }
                        }}
                        aria-expanded={isExpanded}
                        title={isExpanded ? 'Click to collapse connected devices' : `Click to view all ${account.sessions.length} connected devices`}
                      >
                        <div className="webcare-session-devices-toggle-left">
                          <div className={`webcare-session-devices-icon-pill ${isExpanded ? 'is-expanded' : ''}`}>
                            <Laptop size={18} />
                          </div>
                          <div className="webcare-session-devices-toggle-text">
                            <div className="webcare-session-devices-toggle-heading-row">
                              <span className="webcare-session-devices-toggle-heading">
                                Connected Devices &amp; Active Browsers
                              </span>
                              <span className="webcare-session-devices-count-chip">
                                {account.sessions.length} {account.sessions.length === 1 ? 'Device' : 'Devices'}
                              </span>
                            </div>
                            <span className="webcare-session-devices-toggle-sub">
                              {account.sessions.length} {account.sessions.length === 1 ? 'device registered' : 'devices registered'}
                              {anyActiveSessionsCount > 0 ? ` (${anyActiveSessionsCount} active)` : ' (all logged out)'} &bull; {account.all_distinct_ips.length} {account.all_distinct_ips.length === 1 ? 'unique IP' : 'unique IPs'} observed
                            </span>
                          </div>
                        </div>

                        <div className="webcare-session-devices-toggle-right">
                          {isExpanded ? (
                            <span className="webcare-session-collapse-btn">
                              <ChevronUp size={13} />
                              <span>Collapse Devices</span>
                            </span>
                          ) : (
                            <span className="webcare-session-awesome-expand-btn">
                              <ChevronDown size={14} className="webcare-bounce-subtle" />
                              <span>View Connected Devices ({account.sessions.length})</span>
                            </span>
                          )}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="webcare-session-devices-grid webcare-fade-in">
                        {account.sessions.map((sess) => {
                          const DeviceIcon = sess.device_type === 'Mobile' ? Smartphone : sess.device_type === 'Tablet' ? Tablet : Laptop;
                          const isHistoryOpen = !!expandedIpHistories[sess.token];
                          const isDetailsOpen = !!expandedDeviceDetails[sess.token];
                          const ipList = sess.ip_history && sess.ip_history.length > 0 ? sess.ip_history : [];
                          const isLoggedOut = sess.is_active === false || sess.status === 'logged_out';

                          return (
                            <div
                              key={sess.token}
                              className={`webcare-session-device-card ${sess.is_current ? 'is-current-device' : ''} ${isLoggedOut ? 'is-logged-out-device' : ''}`}
                            >
                              {/* Device Main Info Row */}
                              <div className="webcare-session-device-main-row">
                                <div className="webcare-session-device-left">
                                  <div className="webcare-session-device-icon-box">
                                    <DeviceIcon size={18} color={sess.is_current ? '#0284c7' : isLoggedOut ? '#94a3b8' : '#64748b'} />
                                  </div>

                                  <div className="webcare-session-device-heading">
                                    <div className="webcare-session-device-name-row">
                                      <strong className={`webcare-session-device-name ${isLoggedOut ? 'is-logged-out-title' : ''}`}>
                                        {sess.browser} on {sess.platform}
                                        {sess.browser_version ? ` v${sess.browser_version.split('.')[0]}` : ''}
                                        {' '}
                                        <span
                                          style={{ fontWeight: 500, opacity: 0.72, fontSize: '0.88em', fontFamily: 'monospace' }}
                                          title={`Unique Device ID: ${(sess.device_uuid || sess.session_id || sess.token || '').slice(0, 8).toUpperCase()}`}
                                        >
                                          #{(sess.device_uuid || sess.session_id || sess.token || '0000').replace(/[^a-zA-Z0-9]/g, '').slice(-4).toUpperCase()}
                                        </span>
                                      </strong>

                                      {/* Current Device Badge */}
                                      {sess.is_current && (
                                        <span className="webcare-badge-device-active">
                                          <Check size={11} strokeWidth={3} /> Current Device (Active)
                                        </span>
                                      )}

                                      {/* Logged Out Badge */}
                                      {isLoggedOut && (
                                        <span className="webcare-badge-device-logged-out" title={sess.revoked_at_human ? `Logged out ${sess.revoked_at_human}` : 'Session logged out'}>
                                          <LogOut size={10} /> Logged Out
                                        </span>
                                      )}

                                      {/* Pre-Install Old Login Badge */}
                                      {sess.is_pre_install && (
                                        <span
                                          className="webcare-badge-device-logged-out"
                                          title="Logged in before WebCare Pro was installed. Real IP and login history will be recorded automatically on next visit or login."
                                        >
                                          <Clock size={10} /> Old Login (Pre-Install)
                                        </span>
                                      )}

                                      {/* Cloudflare Proxy IP Notice on Pre-Install Sessions */}
                                      {sess.is_cloudflare_proxy_ip && !sess.is_current && (
                                        <span
                                          className="webcare-badge-device-logged-out"
                                          title="WordPress recorded a Cloudflare proxy IP before WebCare Pro was installed. Real IP will update automatically on next access."
                                        >
                                          <Globe size={10} /> Cloudflare Proxy IP
                                        </span>
                                      )}

                                      {/* Auth Type Badge */}
                                      {sess.auth_type === 'passkey' && (
                                        <span className="webcare-auth-pill webcare-auth-pill-passkey" title={sess.auth_details?.device_name ? `Verified via ${sess.auth_details.device_name}` : 'Hardware-bound WebAuthn / FIDO2 Passkey'}>
                                          <Fingerprint size={12} />
                                          <span>Passkey Verified</span>
                                        </span>
                                      )}
                                      {sess.auth_type === '2fa' && (
                                        <span className="webcare-auth-pill webcare-auth-pill-2fa" title="Time-Based One-Time Password (TOTP) Authenticator Code Verified">
                                          <ShieldCheck size={12} />
                                          <span>2FA Protected</span>
                                        </span>
                                      )}
                                      {sess.auth_type === 'magic_link' && (
                                        <span className="webcare-auth-pill webcare-auth-pill-magic" title={`Support Link: ${sess.support_link_meta?.label || 'Support Technician'}`}>
                                          <Zap size={12} />
                                          <span>Magic Support Link</span>
                                        </span>
                                      )}
                                      {(!sess.auth_type || sess.auth_type === 'password') && (
                                        <span className="webcare-auth-pill webcare-auth-pill-password" title="Single-factor password login. MFA not enabled.">
                                          <Lock size={12} />
                                          <span>Password Only</span>
                                        </span>
                                      )}
                                    </div>

                                    {/* Device Telemetry Chips Row */}
                                    <div className="webcare-session-device-chips-row">
                                      {/* Current / Active IP Chip */}
                                      <span className={`webcare-session-telemetry-chip ${sess.has_ip_changed ? 'is-shifted-ip' : ''}`}>
                                        <Globe size={12} color={sess.has_ip_changed ? '#b45309' : '#0284c7'} />
                                        <span>
                                          IP: <code>{sess.current_ip || sess.login_ip}</code>
                                          {sess.is_local_ip && <small className="webcare-lan-tag">(LAN)</small>}
                                        </span>
                                      </span>

                                      {/* IP Changed Badge if shifted */}
                                      {sess.has_ip_changed && (
                                        <span className="webcare-session-telemetry-chip webcare-chip-shift-warning" title={`Initial login from ${sess.login_ip}, current requests arriving from ${sess.current_ip}`}>
                                          <AlertTriangle size={12} color="#b45309" />
                                          <span>IP Changed: <code style={{ textDecoration: 'line-through', opacity: 0.7 }}>{sess.login_ip}</code> &rarr; <strong>{sess.current_ip}</strong></span>
                                        </span>
                                      )}

                                      {/* Interactive IP History Button */}
                                      <button
                                        type="button"
                                        className={`webcare-session-ip-history-btn ${isHistoryOpen ? 'is-open' : ''} ${sess.has_ip_changed ? 'has-changes' : ''}`}
                                        onClick={() => toggleIpHistory(sess.token)}
                                        title="View complete list of all IP addresses recorded during this device session"
                                      >
                                        <History size={12} />
                                        <span>IP History ({sess.distinct_ip_count || ipList.length || 1})</span>
                                        {isHistoryOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                                      </button>

                                      {/* Interactive Device Details & Logins Button */}
                                      <button
                                        type="button"
                                        className={`webcare-session-device-details-btn ${isDetailsOpen ? 'is-open' : ''}`}
                                        onClick={() => toggleDeviceDetails(sess.token)}
                                        title="View full User-Agent, Screen size, Timezone, Browser version, Country, and continuous login history for this device"
                                      >
                                        <Monitor size={12} />
                                        <span>Device Details &amp; Logins ({sess.login_records?.length || sess.total_logins || 1})</span>
                                        {isDetailsOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                                      </button>

                                      {/* Session Timestamps */}
                                      {sess.login_duration_formatted && (
                                        <span className="webcare-session-telemetry-chip" title={`Logged in at ${sess.login_time}`}>
                                          <Clock size={12} color="#0284c7" />
                                          <span>Age: <strong>{sess.login_duration_formatted}</strong></span>
                                        </span>
                                      )}

                                      <span className="webcare-session-telemetry-chip" title={`Last active at ${sess.last_seen}`}>
                                        <Clock size={12} color="#64748b" />
                                        <span>Last Activity: {sess.idle_human || sess.last_seen}</span>
                                      </span>

                                      {sess.expiration_human && (
                                        <span className={`webcare-session-telemetry-chip ${isLoggedOut ? 'is-logged-out-chip' : ''}`} title={`Status: ${sess.expiration || sess.expiration_human}`}>
                                          <Clock size={12} color={isLoggedOut ? '#94a3b8' : '#64748b'} />
                                          <span>{sess.expiration_human}</span>
                                        </span>
                                      )}

                                      {sess.total_logins && sess.total_logins > 1 && (
                                        <span className="webcare-session-telemetry-chip" title={`Persistent Device: Authenticated ${sess.total_logins} times across re-logins without generating duplicate ghost devices.`}>
                                          <ShieldCheck size={12} color="#10b981" />
                                          <span>Recognized Device ({sess.total_logins} logins)</span>
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                </div>

                                {/* Device Action Button */}
                                <div className="webcare-session-device-right">
                                  {sess.is_current ? (
                                    <span className="webcare-device-current-pill">
                                      <span className="webcare-pulse-dot" /> This Device
                                    </span>
                                  ) : !isLoggedOut ? (
                                    <button
                                      type="button"
                                      className="webcare-device-revoke-btn"
                                      onClick={() => handleRevokeSession(sess.token, sess.user_id)}
                                      disabled={revokingSession === sess.token}
                                      title="Log out this specific device (invalidates auth cookies)"
                                    >
                                      {revokingSession === sess.token ? <Loader2 size={12} className="webcare-spin-icon" /> : <LogOut size={12} />}
                                      <span>{revokingSession === sess.token ? 'Logging out...' : 'Log Out Device'}</span>
                                    </button>
                                  ) : (
                                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span className="webcare-logged-out-pill" title={sess.revocation_reason ? `Reason: ${sess.revocation_reason}` : 'Session logged out'}>
                                        <LogOut size={11} /> Logged Out
                                      </span>
                                      {sess.can_delete ? (
                                        <button
                                          type="button"
                                          className="webcare-device-remove-btn"
                                          onClick={() => handleDeleteSessionRecord(sess.token, sess.user_id)}
                                          disabled={deletingRecord === sess.token}
                                          title="Permanently remove this 30+ days old device record from history and security vault"
                                        >
                                          {deletingRecord === sess.token ? <Loader2 size={11} className="webcare-spin-icon" /> : <Trash2 size={11} />}
                                          <span>Remove</span>
                                        </button>
                                      ) : (
                                        <span
                                          className="webcare-retention-lock-pill"
                                          title={sess.retention_lock_reason || `Forensic Retention Policy: Device records are preserved for 30 days after logout. Can be purged in ${sess.retention_days_remaining || 30} days.`}
                                        >
                                          <Lock size={11} />
                                          <span>Locked ({sess.retention_days_remaining || 30}d left)</span>
                                        </span>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* Single-factor Warning Notice */}
                              {!isLoggedOut && (!sess.auth_type || sess.auth_type === 'password') && (
                                <div className="webcare-session-notice-strip webcare-session-notice-strip-warning" style={{ marginTop: '10px' }}>
                                  <AlertTriangle size={13} style={{ flexShrink: 0 }} />
                                  <span>
                                    <strong>Single-Factor Password:</strong> This device authenticated with standard password only. Protect with Passkeys or TOTP.
                                  </span>
                                </div>
                              )}

                              {/* Expandable IP History Timeline Drawer */}
                              {isHistoryOpen && (
                                <div className="webcare-session-ip-timeline-drawer">
                                  <div className="webcare-session-ip-timeline-header">
                                    <div className="webcare-session-ip-timeline-title">
                                      <History size={14} color="#0284c7" />
                                      <strong>Recorded IP Address History ({ipList.length})</strong>
                                    </div>
                                    <span className="webcare-session-ip-timeline-subtitle">
                                      Every unique IP address recorded during this device's authenticated session, including initial login and network shifts.
                                    </span>
                                  </div>

                                  <div className="webcare-session-ip-table-wrap">
                                    <table className="webcare-session-ip-table">
                                      <thead>
                                        <tr>
                                          <th>IP Address</th>
                                          <th>Role / State</th>
                                          <th>First Seen</th>
                                          <th>Last Activity</th>
                                          <th style={{ textAlign: 'right' }}>Requests</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {ipList.map((entry, idx) => (
                                          <tr key={`${entry.ip}-${idx}`} className={entry.is_current ? 'is-active-ip-row' : ''}>
                                            <td>
                                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                                <code className="webcare-session-ip-code">{entry.ip}</code>
                                                {entry.is_local_ip && (
                                                  <span className="webcare-lan-pill">LAN</span>
                                                )}
                                                <button
                                                  type="button"
                                                  className="webcare-session-copy-ip-btn"
                                                  onClick={() => copyIpToClipboard(entry.ip)}
                                                  title="Copy IP Address"
                                                >
                                                  {copiedIp === entry.ip ? <Check size={11} color="#10b981" /> : <Copy size={11} />}
                                                </button>
                                              </div>
                                            </td>
                                            <td>
                                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', flexWrap: 'wrap' }}>
                                                {entry.is_login && (
                                                  <span className="webcare-session-ip-badge is-login-badge">
                                                    <Check size={10} /> Initial Login IP
                                                  </span>
                                                )}
                                                {!entry.is_login && (
                                                  <span className="webcare-session-ip-badge is-shift-badge">
                                                    <AlertTriangle size={10} /> Network Shift / Roaming
                                                  </span>
                                                )}
                                                {entry.is_current && (
                                                  <span className="webcare-session-ip-badge is-current-badge">
                                                    Current Active IP
                                                  </span>
                                                )}
                                              </div>
                                            </td>
                                            <td>
                                              <div className="webcare-session-time-cell">
                                                <span>{entry.first_seen}</span>
                                                <small>({entry.first_seen_human})</small>
                                              </div>
                                            </td>
                                            <td>
                                              <div className="webcare-session-time-cell">
                                                <span>{entry.last_seen}</span>
                                                <small>({entry.last_seen_human})</small>
                                              </div>
                                            </td>
                                            <td style={{ textAlign: 'right' }}>
                                              <span className="webcare-session-count-chip">
                                                {entry.count} {entry.count === 1 ? 'request' : 'requests'}
                                              </span>
                                            </td>
                                          </tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              )}

                              {/* Expandable Device Details & Logins Drawer */}
                              {isDetailsOpen && (
                                <div className="webcare-device-forensics-drawer">
                                  <div className="webcare-device-forensics-header">
                                    <div className="webcare-device-forensics-title">
                                      <Monitor size={15} color="#4f46e5" />
                                      <strong>Client Device Forensics &amp; Specifications</strong>
                                    </div>
                                    <span className="webcare-device-forensics-subtitle">
                                      Deep forensic telemetry collected from this client device, including screen geometry, timezone, browser build, Cloudflare Edge country resolution, and persistent login records.
                                    </span>
                                  </div>

                                  {/* Forensic Specifications Cards Grid */}
                                  <div className="webcare-device-specs-grid">
                                    {/* 1. Browser & Version */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <Globe size={13} color="#4f46e5" />
                                        <span>Browser &amp; Version</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <strong>{sess.browser} {sess.browser_version || ''}</strong>
                                      </div>
                                      <div className="webcare-device-spec-meta">Platform: {sess.platform} ({sess.device_type || 'Desktop'})</div>
                                    </div>

                                    {/* 2. Screen Size & Geometry */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <Monitor size={13} color="#10b981" />
                                        <span>Screen Resolution</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <code>{sess.screen_resolution || '1920x1080 (Estimated)'}</code>
                                      </div>
                                      <div className="webcare-device-spec-meta">Client display raster dimensions</div>
                                    </div>

                                    {/* 3. User Local Timezone */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <Clock size={13} color="#d97706" />
                                        <span>Local PC Timezone</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <strong>{sess.timezone || 'UTC'}</strong>
                                      </div>
                                      <div className="webcare-device-spec-meta">Detected from client Intl API</div>
                                    </div>

                                    {/* 4. Country (Cloudflare Edge Header) */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <ShieldCheck size={13} color="#0284c7" />
                                        <span>Origin Country</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <strong>{sess.country || 'Unknown'}</strong>
                                        {sess.country_code && sess.country_code !== 'XX' && (
                                          <span className="webcare-country-badge">{sess.country_code}</span>
                                        )}
                                      </div>
                                      <div className="webcare-device-spec-meta">Resolved via Cloudflare Edge header (no 3rd-party WHOIS)</div>
                                    </div>

                                    {/* 5. Device Identification */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <Laptop size={13} color="#8b5cf6" />
                                        <span>Device UUID</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <code style={{ fontSize: '11.5px' }}>{sess.device_uuid || 'Hardware-bound fingerprint'}</code>
                                      </div>
                                      <div className="webcare-device-spec-meta">First observed: {sess.device_first_seen_formatted || sess.login_time}</div>
                                    </div>

                                    {/* 6. Total Logins Audit */}
                                    <div className="webcare-device-spec-card">
                                      <div className="webcare-device-spec-label">
                                        <History size={13} color="#10b981" />
                                        <span>Total Recorded Logins</span>
                                      </div>
                                      <div className="webcare-device-spec-value">
                                        <strong style={{ color: '#10b981' }}>{sess.login_records?.length || sess.total_logins || 1}</strong>
                                        <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--webcare-text-muted, #64748b)', marginLeft: '6px' }}>logins on this device</span>
                                      </div>
                                      <div className="webcare-device-spec-meta">Continuous device audit trail</div>
                                    </div>
                                  </div>

                                  {/* Full User Agent with 1-Click Copy */}
                                  <div className="webcare-device-ua-container">
                                    <div className="webcare-device-ua-header">
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <FileText size={13} color="#6366f1" />
                                        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>Full User-Agent String</span>
                                      </div>
                                      <button
                                        type="button"
                                        className="webcare-copy-ua-btn"
                                        onClick={() => copyUaToClipboard(sess.full_user_agent || sess.user_agent)}
                                        title="Copy complete User-Agent string to clipboard"
                                      >
                                        {copiedUa === (sess.full_user_agent || sess.user_agent) ? (
                                          <>
                                            <Check size={12} color="#10b981" />
                                            <span>Copied</span>
                                          </>
                                        ) : (
                                          <>
                                            <Copy size={12} />
                                            <span>Copy User-Agent</span>
                                          </>
                                        )}
                                      </button>
                                    </div>
                                    <div className="webcare-device-ua-box">
                                      <code>{sess.full_user_agent || sess.user_agent}</code>
                                    </div>
                                  </div>

                                  {/* Continuous Logins Audit Trail Table */}
                                  <div className="webcare-device-logins-section">
                                    <div className="webcare-device-logins-title">
                                      <History size={14} color="#4f46e5" />
                                      <strong>Recorded Authentication History on This Device ({sess.login_records?.length || sess.total_logins || 1})</strong>
                                    </div>
                                    <p className="webcare-device-logins-subtitle">
                                      Every login event from this physical device is preserved below, ensuring continuous security visibility even across repeated logins and sessions.
                                    </p>

                                    <div className="webcare-device-logins-table-wrap">
                                      <table className="webcare-device-logins-table">
                                        <thead>
                                          <tr>
                                           <th>Status</th>
                                           <th>Login Date &amp; Time</th>
                                           <th>Network IP</th>
                                           <th>Country</th>
                                           <th>Auth Factor</th>
                                           <th>Browser &amp; Version</th>
                                           <th>Screen &amp; Timezone</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {(sess.login_records && sess.login_records.length > 0 ? sess.login_records : [
                                            {
                                              login_time: sess.login_time,
                                              login_time_formatted: sess.login_time,
                                              login_time_human: sess.login_duration_formatted ? `${sess.login_duration_formatted} ago` : 'Active',
                                              ip: sess.current_ip || sess.login_ip,
                                              country: sess.country || 'Unknown',
                                              country_code: sess.country_code || 'XX',
                                              auth_factor: sess.auth_label || (sess.auth_type === 'passkey' ? 'Passkey' : sess.auth_type === '2fa' ? '2FA TOTP' : 'Password Only'),
                                              browser: sess.browser,
                                              browser_version: sess.browser_version || '',
                                              screen_resolution: sess.screen_resolution || '1920x1080',
                                              timezone: sess.timezone || 'UTC',
                                              user_agent: sess.full_user_agent || sess.user_agent,
                                              is_active: sess.is_current || !isLoggedOut,
                                            }
                                          ]).map((rec, rIdx) => {
                                            const displayTime = rec.login_time_formatted || rec.time_formatted || rec.login_time || (rec.time ? String(rec.time) : '');
                                            const displayHuman = rec.login_time_human || rec.time_human;
                                            const displayFactor = rec.auth_factor || rec.auth_label || rec.auth_type || 'Password';
                                            const isRowActive = rec.is_active ?? rec.is_current ?? (rIdx === 0 && !isLoggedOut);
                                            return (
                                            <tr key={`rec-${rIdx}-${rec.login_time || rec.time || rIdx}`} className={isRowActive ? 'is-active-login-row' : ''}>
                                              <td>
                                                {isRowActive ? (
                                                  <span className="webcare-login-status-badge is-active">
                                                    <span className="webcare-pulse-dot" /> Active Session
                                                  </span>
                                                ) : (
                                                  <span className="webcare-login-status-badge is-past">
                                                    <Check size={11} /> Authenticated
                                                  </span>
                                                )}
                                              </td>
                                              <td>
                                                <div className="webcare-session-time-cell">
                                                  <strong>{displayTime}</strong>
                                                  {displayHuman && <small>({displayHuman})</small>}
                                                </div>
                                              </td>
                                              <td>
                                                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                                  <code className="webcare-session-ip-code">{rec.ip}</code>
                                                  <button
                                                    type="button"
                                                    className="webcare-session-copy-ip-btn"
                                                    onClick={() => copyIpToClipboard(rec.ip)}
                                                    title="Copy IP"
                                                  >
                                                    {copiedIp === rec.ip ? <Check size={11} color="#10b981" /> : <Copy size={11} />}
                                                  </button>
                                                </div>
                                              </td>
                                              <td>
                                                <span className="webcare-country-text">
                                                  {rec.country || 'Unknown'}
                                                </span>
                                              </td>
                                              <td>
                                                <span className="webcare-auth-factor-badge">
                                                  {displayFactor}
                                                </span>
                                              </td>
                                              <td>
                                                <span style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                                  {rec.browser} {rec.browser_version || ''}
                                                </span>
                                              </td>
                                              <td>
                                                <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                                  <code>{rec.screen_resolution || 'N/A'}</code> &bull; {rec.timezone || 'UTC'}
                                                </div>
                                              </td>
                                            </tr>
                                            );
                                          })}
                                        </tbody>
                                      </table>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: BRUTE FORCE LOCKOUTS */}
      {activeTab === 'lockouts' && (
        <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #fff)', borderRadius: '12px', border: '1px solid #e2e8f0', padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>Active Brute-Force IP Lockouts</h3>
              <p style={{ margin: '2px 0 0 0', fontSize: '13px', color: '#64748b' }}>
                IP addresses temporarily blocked after exceeding failed login thresholds.
              </p>
            </div>

            {status?.lockouts && status.lockouts.length > 0 && (
              <button
                type="button"
                className="webcare-btn"
                style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '13px' }}
                onClick={handleClearAllLockouts}
              >
                <Trash2 size={14} /> Clear All Lockouts
              </button>
            )}
          </div>

          {!status?.lockouts || status.lockouts.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--webcare-text-muted, #64748b)', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px' }}>
              <ShieldCheck size={36} color="#10b981" style={{ margin: '0 auto 12px auto' }} />
              <h4 style={{ margin: '0 0 4px 0', fontSize: '15px', color: '#1e293b' }}>Zero Locked Out IPs</h4>
              <p style={{ margin: 0, fontSize: '13px' }}>No malicious brute-force attempts currently require active cooldown lockout.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                    <th style={{ padding: '10px 12px', color: '#475569' }}>Blocked IP</th>
                    <th style={{ padding: '10px 12px', color: '#475569' }}>Targeted Username</th>
                    <th style={{ padding: '10px 12px', color: '#475569' }}>Failed Retries</th>
                    <th style={{ padding: '10px 12px', color: '#475569' }}>Locked At</th>
                    <th style={{ padding: '10px 12px', color: '#475569', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {status.lockouts.map((lockout) => (
                    <tr key={lockout.ip} style={{ borderBottom: '1px solid #f1f5f9' }}>
                      <td style={{ padding: '10px 12px', fontWeight: 600, color: '#0f172a' }}>
                        <code>{lockout.ip}</code>
                      </td>
                      <td style={{ padding: '10px 12px', color: '#334155' }}>
                        {lockout.username || 'unknown'}
                      </td>
                      <td style={{ padding: '10px 12px', color: '#dc2626', fontWeight: 600 }}>
                        {lockout.attempts} attempts
                      </td>
                      <td style={{ padding: '10px 12px', color: '#64748b' }}>
                        {lockout.blocked_at}
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                        <button
                          type="button"
                          className="webcare-btn"
                          style={{ fontSize: '12px', padding: '4px 10px', background: '#dcfce7', color: '#15803d', border: 'none' }}
                          onClick={() => handleUnlockIp(lockout.ip)}
                        >
                          <Unlock size={13} /> Unlock IP
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: RATE-LIMIT SETTINGS */}
      {activeTab === 'settings' && (
        <div className="webcare-card" style={{ background: 'var(--webcare-bg-card, #fff)', borderRadius: '12px', border: '1px solid #e2e8f0', padding: '24px', maxWidth: '680px' }}>
          <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sliders size={18} color="#0284c7" /> Login Rate-Limiting &amp; Protection Parameters
          </h3>

          {settingsSuccess && (
            <div style={{ padding: '10px 14px', background: '#ecfdf5', color: '#065f46', borderRadius: '8px', marginBottom: '16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={16} /> {settingsSuccess}
            </div>
          )}

          {settingsError && (
            <div style={{ padding: '10px 14px', background: '#fef2f2', color: '#991b1b', borderRadius: '8px', marginBottom: '16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={16} /> {settingsError}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* 2FA Cryptographic Algorithm & Code Length */}
            <div style={{ paddingBottom: '16px', borderBottom: '1px solid var(--webcare-border, #f1f5f9)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <h4 style={{ margin: '0 0 4px 0', fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={16} color="#0284c7" /> 2FA Cryptographic Algorithm &amp; Code Length
                </h4>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                  Select the cryptographic hashing algorithm and one-time password length used for all newly provisioned 2FA authenticator profiles.
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                {/* Standard SHA-1 6-Digit */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    background: loginSettings.auth_2fa_algorithm === 'sha1' ? 'var(--webcare-bg-surface-elevated, rgba(2, 132, 199, 0.05))' : 'var(--webcare-bg-panel, #ffffff)',
                    border: '1px solid ' + (loginSettings.auth_2fa_algorithm === 'sha1' ? '#0284c7' : 'var(--webcare-border, #e2e8f0)'),
                    transition: 'all 0.15s ease',
                  }}
                >
                  <input
                    type="radio"
                    name="webcare_auth_2fa_algo"
                    value="sha1"
                    checked={loginSettings.auth_2fa_algorithm === 'sha1'}
                    onChange={() => setLoginSettings({ ...loginSettings, auth_2fa_algorithm: 'sha1', auth_2fa_digits: 6 })}
                    style={{ accentColor: '#0284c7', marginTop: '3px' }}
                  />
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      SHA-1 &bull; 6 Digits
                      <span className="webcare-badge-pill" style={{ fontSize: '10px', padding: '1px 6px', background: 'var(--webcare-bg-elevated, #f1f5f9)', color: 'var(--webcare-text-secondary, #475569)' }}>Standard</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)', marginTop: '2px', lineHeight: 1.4 }}>
                      Universal compatibility across all authenticator apps (Google Authenticator, Microsoft Authenticator, Authy, Apple Passwords).
                    </div>
                  </div>
                </label>

                {/* Advanced SHA-512 8-Digit */}
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    background: loginSettings.auth_2fa_algorithm === 'sha512' ? 'var(--webcare-bg-surface-elevated, rgba(79, 70, 229, 0.06))' : 'var(--webcare-bg-panel, #ffffff)',
                    border: '1px solid ' + (loginSettings.auth_2fa_algorithm === 'sha512' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'),
                    transition: 'all 0.15s ease',
                  }}
                >
                  <input
                    type="radio"
                    name="webcare_auth_2fa_algo"
                    value="sha512"
                    checked={loginSettings.auth_2fa_algorithm === 'sha512'}
                    onChange={() => setLoginSettings({ ...loginSettings, auth_2fa_algorithm: 'sha512', auth_2fa_digits: 8 })}
                    style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                  />
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      SHA-512 &bull; 8 Digits
                      <span className="webcare-badge-pill" style={{ fontSize: '10px', padding: '1px 6px', background: 'rgba(79, 70, 229, 0.12)', color: '#6366f1', fontWeight: 600 }}>High Security</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)', marginTop: '2px', lineHeight: 1.4 }}>
                      Maximum cryptographic resistance against collision and brute force. Supported by Aegis, 1Password, YubiKey, Bitwarden, and 2FAS.
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {/* 2FA Trusted Devices Configuration */}
            <div style={{ paddingBottom: '16px', borderBottom: '1px solid var(--webcare-border, #f1f5f9)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-heading, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Smartphone size={16} color="#0284c7" /> Two-Factor Authentication (2FA) Remember Device
              </h4>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
                <input
                  type="checkbox"
                  checked={loginSettings.auth_2fa_remember_device}
                  onChange={(e) => setLoginSettings({ ...loginSettings, auth_2fa_remember_device: e.target.checked })}
                  style={{ accentColor: '#0284c7', marginTop: '2px' }}
                />
                <div>
                  <strong>Allow Remembering Trusted Devices</strong>
                  <div style={{ fontSize: '12px', color: '#64748b' }}>
                    Enables the "Remember this device" option on the 2FA challenge screen to skip rotating TOTP prompts on verified browsers.
                  </div>
                </div>
              </label>

              {loginSettings.auth_2fa_remember_device && (
                <div style={{ paddingLeft: '26px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                    Trusted Device Expiration (Days)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={90}
                    value={loginSettings.auth_2fa_remember_days}
                    onChange={(e) => setLoginSettings({ ...loginSettings, auth_2fa_remember_days: parseInt(e.target.value) || 7 })}
                    style={{ width: '120px', padding: '8px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px' }}
                  />
                  <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginTop: '4px' }}>
                    Default: 7 days. After this duration, the user must re-enter their 2FA code.
                  </span>
                </div>
              )}
            </div>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
              <input
                type="checkbox"
                checked={loginSettings.login_hardening_enabled}
                onChange={(e) => setLoginSettings({ ...loginSettings, login_hardening_enabled: e.target.checked })}
                style={{ accentColor: '#0284c7', marginTop: '2px' }}
              />
              <div>
                <strong>Enable Login Rate-Limiting &amp; Brute Force Defense</strong>
                <div style={{ fontSize: '12px', color: '#64748b' }}>
                  Automatically locks out IP addresses that exceed failed authentication thresholds.
                </div>
              </div>
            </label>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                Maximum Failed Attempts Before Lockout
              </label>
              <input
                type="number"
                min={1}
                max={20}
                value={loginSettings.login_max_retries}
                onChange={(e) => setLoginSettings({ ...loginSettings, login_max_retries: parseInt(e.target.value) || 5 })}
                style={{ width: '120px', padding: '8px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px' }}
              />
              <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginTop: '4px' }}>
                Recommended: 5 attempts.
              </span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                Temporary Lockout Duration (Minutes)
              </label>
              <input
                type="number"
                min={5}
                max={1440}
                value={loginSettings.login_lockout_duration}
                onChange={(e) => setLoginSettings({ ...loginSettings, login_lockout_duration: parseInt(e.target.value) || 15 })}
                style={{ width: '120px', padding: '8px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px' }}
              />
              <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginTop: '4px' }}>
                Recommended: 15 minutes.
              </span>
            </div>

            {/* Session Sentinel Security Controls */}
            <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Laptop size={16} color="#0284c7" /> Session Sentinel &amp; Anti-Hijacking Rules
              </h4>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
                <input
                  type="checkbox"
                  checked={loginSettings.session_sentinel_enabled}
                  onChange={(e) => setLoginSettings({ ...loginSettings, session_sentinel_enabled: e.target.checked })}
                  style={{ accentColor: '#0284c7', marginTop: '2px' }}
                />
                <div>
                  <strong>Enable Active Session Sentinel</strong>
                  <div style={{ fontSize: '12px', color: '#64748b' }}>
                    Tracks and audits all concurrent authenticated administrator cookies in real time.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
                <input
                  type="checkbox"
                  checked={loginSettings.session_block_concurrent}
                  onChange={(e) => setLoginSettings({ ...loginSettings, session_block_concurrent: e.target.checked })}
                  style={{ accentColor: '#0284c7', marginTop: '2px' }}
                />
                <div>
                  <strong>Enforce Dual-Device Session Limit (1 Desktop + 1 Mobile Maximum)</strong>
                  <div style={{ fontSize: '12px', color: '#64748b' }}>
                    Permits up to 2 concurrent devices per administrator (strictly 1 Desktop and 1 Mobile). Automatically terminates prior sessions of the same device type when a new login occurs.
                  </div>
                </div>
              </label>
            </div>

            <button
              type="button"
              className="webcare-btn webcare-btn-primary"
              style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '10px 20px', width: 'fit-content', marginTop: '8px' }}
              onClick={handleSaveSettings}
              disabled={savingSettings}
            >
              {savingSettings ? <Loader2 size={15} className="webcare-spin-icon" /> : <Check size={15} />}
              {savingSettings ? 'Saving Settings...' : 'Save Settings'}
            </button>
          </div>
        </div>
      )}

      {/* TAB: WebAuthn W3C Biometric Passkeys */}
      {activeTab === 'passkeys' && (
        <WebAuthnPasskeyCard apiRequest={apiRequest} />
      )}

      {/* TAB: REST Application Passwords & Phishing Sentinel */}
      {activeTab === 'app_passwords' && (
        <AppPasswordSentinelCard apiRequest={apiRequest} />
      )}

      {/* Sticky Unsaved Changes Action Bar */}
      <UnsavedChangesBar
        isDirty={activeTab === 'settings' && isSettingsDirty}
        isSaving={savingSettings}
        onSave={handleSaveSettings}
        onDiscard={handleDiscardSettings}
        message="You have unsaved login security settings"
      />

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={authConfirmDialog.isOpen}
        title={authConfirmDialog.title}
        message={authConfirmDialog.message}
        targetItem={authConfirmDialog.targetItem}
        confirmLabel={authConfirmDialog.confirmLabel}
        variant={authConfirmDialog.variant}
        isLoading={authConfirmDialog.isLoading}
        onConfirm={authConfirmDialog.onConfirm || (() => {})}
        onClose={() => setAuthConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};

export default AuthSecurityPage;
