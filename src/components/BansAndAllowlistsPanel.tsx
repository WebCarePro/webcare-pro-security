import React, { useState, useEffect } from 'react';
import {
  Ban,
  Lock,
  Globe,
  AlertCircle,
  Plus,
  RefreshCw,
  Trash2,
  Unlock,
  RotateCcw,
  Edit2,
  X,
  Search,
  Check,
  Save,
  Loader2,
  Cloud,
  List,
  ListFilter,
  Activity,
  ChevronLeft,
  ChevronRight,
  Shield,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { TargetedAllowlistManagerCard } from './TargetedAllowlistManagerCard';
import { ConfirmDialog } from './ConfirmDialog';

export interface LockedIpItem {
  ip: string;
  reason: string;
  locked_at: string;
  locked_at_raw: number;
  expires_at: string;
  expires_at_raw: number;
  duration_seconds: number;
  is_expired: boolean;
  time_remaining: string;
  remaining_seconds: number;
  cf_banned?: boolean;
}

export interface WhitelistedIpItem {
  ip: string;
  reason: string;
  added_at: string;
  added_at_raw: number | null;
  added_ago: string;
  added_by: string;
  type: string;
  require_admin: boolean;
  scope?: 'rule' | 'category' | 'global';
  allowed_rules?: string[];
  allowed_rule_names?: Record<string, string>;
  allowed_cats?: string[];
  endpoint?: string;
  expires_at?: number;
  is_expired?: boolean;
}

export interface FirewallRuleCatalogItem {
  id: string;
  name: string;
  category: string;
  description: string;
}

export interface CloudflareRuleItem {
  id: string;
  mode: string;
  configuration: {
    target: string;
    value: string;
  };
  notes: string;
}

interface BansAndAllowlistsPanelProps {
  apiRequest: (options: any) => Promise<any>;
  onNotice?: (type: 'success' | 'error' | 'warning' | 'info', message: string) => void;
  // Optional controlled settings & state from parent
  initialWafSettings?: any;
  activePluginSlugs?: string[];
  cfConfigured?: boolean;
}

export const BansAndAllowlistsPanel: React.FC<BansAndAllowlistsPanelProps> = ({
  apiRequest,
  onNotice,
  initialWafSettings,
  activePluginSlugs = [],
  cfConfigured = false,
}) => {
  // Notification helper
  const showNotice = (type: 'success' | 'error' | 'warning' | 'info', msg: string) => {
    if (onNotice) {
      onNotice(type, msg);
    }
  };

  // Confirm dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'primary';
    isLoading?: boolean;
    onConfirm?: () => Promise<void> | void;
  }>({
    isOpen: false,
    title: '',
    message: '',
  });

  const requestConfirm = ({
    title,
    message,
    targetItem,
    confirmLabel,
    variant = 'danger',
    onConfirm,
  }: {
    title: string;
    message: string;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'primary';
    onConfirm: () => Promise<void> | void;
  }) => {
    setConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch {
          setConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  // Local WAF Settings for Allowlisted URLs, Progressive warnings, Targeted rules, etc.
  const [wafSettings, setWafSettings] = useState<{
    waf_whitelisted_urls: string;
    waf_whitelist_require_admin: boolean;
    waf_whitelist_log_telemetry: boolean;
    waf_enable_progressive_warnings: boolean;
    waf_contact_support_url: string;
    waf_targeted_allowlist_rules: string;
  }>({
    waf_whitelisted_urls: initialWafSettings?.waf_whitelisted_urls || '',
    waf_whitelist_require_admin: initialWafSettings?.waf_whitelist_require_admin ?? true,
    waf_whitelist_log_telemetry: initialWafSettings?.waf_whitelist_log_telemetry ?? true,
    waf_enable_progressive_warnings: initialWafSettings?.waf_enable_progressive_warnings ?? true,
    waf_contact_support_url: initialWafSettings?.waf_contact_support_url || '',
    waf_targeted_allowlist_rules: initialWafSettings?.waf_targeted_allowlist_rules || '[]',
  });

  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [savedSuccessKey, setSavedSuccessKey] = useState<Record<string, boolean>>({});

  const handleSaveSingleRule = async (key: string, explicitValue?: any) => {
    try {
      setSavingKey(key);
      const val = explicitValue !== undefined ? explicitValue : (wafSettings as any)[key];
      const res = await apiRequest({
        path: '/firewall/save-rule',
        method: 'POST',
        data: { rule_key: key, value: val }
      });
      if (res && res.success) {
        setSavedSuccessKey(prev => ({ ...prev, [key]: true }));
        setTimeout(() => setSavedSuccessKey(prev => ({ ...prev, [key]: false })), 3000);
        showNotice('success', `Saved: ${key.replace(/^waf_/, '').replace(/_/g, ' ')}`);
      } else {
        showNotice('error', res?.message || `Failed to save ${key}`);
      }
    } catch (e: any) {
      showNotice('error', e?.message || `Error saving ${key}`);
    } finally {
      setSavingKey(null);
    }
  };

  // --- SECTION 1: BLOCKED IP ADDRESSES & SUBNETS ---
  const [lockedIpsList, setLockedIpsList] = useState<LockedIpItem[]>([]);
  const [loadingBlocklist, setLoadingBlocklist] = useState<boolean>(false);
  const [newBlockIp, setNewBlockIp] = useState<string>('');
  const [newBlockReason, setNewBlockReason] = useState<string>('');
  const [addingBlockIp, setAddingBlockIp] = useState<boolean>(false);
  const [blockedFilterTab, setBlockedFilterTab] = useState<'all' | 'active' | 'expired'>('active');
  const [blockedTableSearch, setBlockedTableSearch] = useState<string>('');
  const [blockedPage, setBlockedPage] = useState<number>(1);
  const [blockedPageSize, setBlockedPageSize] = useState<number>(10);
  const [unblockingIp, setUnblockingIp] = useState<string | null>(null);
  const [clearingExpiredBans, setClearingExpiredBans] = useState<boolean>(false);
  const [isUnbanningAllIps, setIsUnbanningAllIps] = useState<boolean>(false);

  // Cloudflare blocklist sync
  const [syncingBlocklistToCf, setSyncingBlocklistToCf] = useState<boolean>(false);
  const [isBatchSyncingCf, setIsBatchSyncingCf] = useState<boolean>(false);
  const [blocklistSyncResult, setBlocklistSyncResult] = useState<{ success: boolean; message: string } | null>(null);
  const [cfActionIp, setCfActionIp] = useState<string | null>(null);
  const [showBannedIpsModal, setShowBannedIpsModal] = useState<boolean>(false);
  const [bannedIpsList, setBannedIpsList] = useState<CloudflareRuleItem[]>([]);
  const [bannedIpsTotal, setBannedIpsTotal] = useState<number>(0);
  const [loadingBannedIps, setLoadingBannedIps] = useState<boolean>(false);
  const [unbanningRuleId, setUnbanningRuleId] = useState<string | null>(null);
  const [blocklistModalOpen, setBlocklistModalOpen] = useState<boolean>(false);

  // Edit Blocklist Modal
  const [editBlocklistItem, setEditBlocklistItem] = useState<{
    isOpen: boolean;
    ip: string;
    reason: string;
    durationSeconds: number;
    isSubmitting: boolean;
  }>({
    isOpen: false,
    ip: '',
    reason: '',
    durationSeconds: 0,
    isSubmitting: false,
  });

  const fetchBlocklistData = async () => {
    try {
      setLoadingBlocklist(true);
      const res = await apiRequest({
        path: '/firewall/blocklist',
        method: 'GET'
      });
      if (res && res.locked_ips) {
        setLockedIpsList(res.locked_ips);
      }
    } catch {
      // ignore
    } finally {
      setLoadingBlocklist(false);
    }
  };

  const handleAddBlockedIpInline = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanIp = newBlockIp.trim();
    if (!cleanIp) {
      showNotice('warning', 'Please enter a valid IP address or CIDR range.');
      return;
    }
    try {
      setAddingBlockIp(true);
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: {
          ip: cleanIp,
          reason: newBlockReason.trim() || 'Blocked manually by administrator policy',
          duration_seconds: 0
        }
      });
      if (res && res.success) {
        setNewBlockIp('');
        setNewBlockReason('');
        await fetchBlocklistData();
        showNotice('success', `IP ${cleanIp} added to blocklist.`);
      } else {
        showNotice('error', res?.message || 'Failed to add IP to blocklist.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error adding IP to blocklist.');
    } finally {
      setAddingBlockIp(false);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      setUnblockingIp(ip);
      const res = await apiRequest({
        path: '/firewall/logs/unblock-ip',
        method: 'POST',
        data: { ip }
      });
      if (res && res.success) {
        setLockedIpsList(prev => prev.filter(item => item.ip !== ip));
        showNotice('success', `IP ${ip} was unblocked.`);
      } else {
        showNotice('error', res?.message || 'Failed to unblock IP.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error unblocking IP.');
    } finally {
      setUnblockingIp(null);
    }
  };

  const handleUnbanAllIps = () => {
    requestConfirm({
      title: 'Unban All IP Addresses',
      message: 'Are you sure you want to completely clear the firewall blocklist and unban all IP addresses across local firewall and Cloudflare Edge?',
      confirmLabel: 'Yes, Unban All IPs',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setIsUnbanningAllIps(true);
          const res = await apiRequest({
            path: '/firewall/logs/unblock-all',
            method: 'POST'
          });
          if (res && res.success) {
            setLockedIpsList(res.locked_ips || []);
            showNotice('success', res.message || `Successfully unbanned all ${res.cleared_count || 0} IPs.`);
          } else {
            showNotice('error', res?.message || 'Failed to unban all IPs.');
          }
        } catch (e: any) {
          showNotice('error', e?.message || 'Error occurred while unbanning all IPs.');
        } finally {
          setIsUnbanningAllIps(false);
        }
      }
    });
  };

  const handleClearExpiredBans = async () => {
    try {
      setClearingExpiredBans(true);
      const res = await apiRequest({
        path: '/firewall/blocklist/clear-expired',
        method: 'POST'
      });
      if (res && res.success) {
        if (res.locked_ips) {
          setLockedIpsList(res.locked_ips);
        }
        showNotice('success', res.message || `Cleared ${res.cleared_count || 0} expired bans.`);
      } else {
        showNotice('error', res?.message || 'Failed to clear expired bans.');
      }
    } catch (e: any) {
      showNotice('error', e?.message || 'Error clearing expired bans.');
    } finally {
      setClearingExpiredBans(false);
    }
  };

  const handleOpenEditBlocklistModal = (item: LockedIpItem) => {
    setEditBlocklistItem({
      isOpen: true,
      ip: item.ip,
      reason: item.reason || '',
      durationSeconds: item.duration_seconds || 0,
      isSubmitting: false,
    });
  };

  const handleSaveEditBlocklist = async () => {
    if (!editBlocklistItem.ip) return;
    try {
      setEditBlocklistItem(prev => ({ ...prev, isSubmitting: true }));
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: {
          ip: editBlocklistItem.ip,
          reason: editBlocklistItem.reason.trim() || 'Updated blocklist policy by administrator',
          duration_seconds: editBlocklistItem.durationSeconds,
        }
      });
      if (res && res.success) {
        await fetchBlocklistData();
        showNotice('success', `Blocklist entry for ${editBlocklistItem.ip} updated successfully.`);
        setEditBlocklistItem(prev => ({ ...prev, isOpen: false }));
      } else {
        showNotice('error', res?.message || 'Failed to update blocklist entry.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error updating blocklist entry.');
    } finally {
      setEditBlocklistItem(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  // Cloudflare blocklist edge sync
  const handlePushIpToCloudflareEdge = async (rawIp: string, reason?: string) => {
    try {
      setCfActionIp(`push-${rawIp}`);
      const res = await apiRequest({
        path: '/cloudflare/block-ip',
        method: 'POST',
        data: { ip: rawIp, reason: reason || 'Blocked via WebCare Pro' }
      });
      if (res && res.success) {
        setLockedIpsList(prev => prev.map(item => item.ip === rawIp ? { ...item, cf_banned: true } : item));
        showNotice('success', `IP ${rawIp} pushed to Cloudflare Edge IP Access Rules.`);
      } else {
        showNotice('error', res?.message || 'Failed to push IP to Cloudflare.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Network error pushing to Cloudflare.');
    } finally {
      setCfActionIp(null);
    }
  };

  const handleUnblockIpFromCloudflareEdge = async (rawIp: string) => {
    try {
      setCfActionIp(`unblock-${rawIp}`);
      const res = await apiRequest({
        path: '/cloudflare/unblock-ip-by-ip',
        method: 'POST',
        data: { ip: rawIp }
      });
      if (res && res.success) {
        setLockedIpsList(prev => prev.map(item => item.ip === rawIp ? { ...item, cf_banned: false } : item));
        showNotice('success', `IP ${rawIp} unblocked from Cloudflare Edge.`);
      } else {
        showNotice('error', res?.message || 'Failed to remove from Cloudflare.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Network error unblocking from Cloudflare.');
    } finally {
      setCfActionIp(null);
    }
  };

  const handleSyncBlocklistToCloudflare = async () => {
    try {
      setSyncingBlocklistToCf(true);
      setBlocklistSyncResult(null);
      const res = await apiRequest({
        path: '/cloudflare/sync-blocklist',
        method: 'POST'
      });
      if (res && res.success) {
        setBlocklistSyncResult({
          success: true,
          message: `Successfully synced ${res.added_count || 0} IPs to Cloudflare Edge.`
        });
        await fetchBlocklistData();
      } else {
        setBlocklistSyncResult({
          success: false,
          message: res?.message || 'Failed to sync blocklist to Cloudflare.'
        });
      }
    } catch (e: any) {
      setBlocklistSyncResult({
        success: false,
        message: e?.message || 'Network error syncing blocklist.'
      });
    } finally {
      setSyncingBlocklistToCf(false);
    }
  };

  // --- SECTION 2: WHITELISTED IP ADDRESSES ---
  const [whitelistedIpsList, setWhitelistedIpsList] = useState<WhitelistedIpItem[]>([]);
  const [loadingWhitelist, setLoadingWhitelist] = useState<boolean>(false);
  const [newWhitelistIp, setNewWhitelistIp] = useState<string>('');
  const [newWhitelistReason, setNewWhitelistReason] = useState<string>('');
  const [newWhitelistScope, setNewWhitelistScope] = useState<'rule' | 'category' | 'global'>('global');
  const [newWhitelistSelectedRule, setNewWhitelistSelectedRule] = useState<string>('');
  const [newWhitelistSelectedCats, setNewWhitelistSelectedCats] = useState<string[]>([]);
  const [newWhitelistEndpoint, setNewWhitelistEndpoint] = useState<string>('');
  const [newWhitelistExpiresIn, setNewWhitelistExpiresIn] = useState<number>(0);
  const [rulesCatalog, setRulesCatalog] = useState<FirewallRuleCatalogItem[]>([]);
  const [addingWhitelistIp, setAddingWhitelistIp] = useState<boolean>(false);
  const [removingWhitelistIp, setRemovingWhitelistIp] = useState<string | null>(null);
  const [syncingWhitelistToCf, setSyncingWhitelistToCf] = useState<boolean>(false);
  const [whitelistSyncResult, setWhitelistSyncResult] = useState<{ success: boolean; message: string } | null>(null);
  const [showCfWhitelistModal, setShowCfWhitelistModal] = useState<boolean>(false);
  const [cfWhitelistList, setCfWhitelistList] = useState<CloudflareRuleItem[]>([]);
  const [cfWhitelistTotal, setCfWhitelistTotal] = useState<number>(0);
  const [loadingCfWhitelist, setLoadingCfWhitelist] = useState<boolean>(false);
  const [removingCfWhitelistId, setRemovingCfWhitelistId] = useState<string | null>(null);

  // Edit Whitelist Modal
  const [editWhitelistItem, setEditWhitelistItem] = useState<{
    isOpen: boolean;
    ip: string;
    reason: string;
    scope: 'rule' | 'category' | 'global';
    selectedRule: string;
    selectedCats: string[];
    endpoint: string;
    expiresIn: number;
    isSubmitting: boolean;
  }>({
    isOpen: false,
    ip: '',
    reason: '',
    scope: 'global',
    selectedRule: '',
    selectedCats: [],
    endpoint: '',
    expiresIn: 0,
    isSubmitting: false,
  });

  const fetchWhitelistData = async () => {
    try {
      setLoadingWhitelist(true);
      const res = await apiRequest({
        path: '/firewall/whitelist',
        method: 'GET'
      });
      if (res && res.whitelisted_ips) {
        setWhitelistedIpsList(res.whitelisted_ips);
      }
      if (res && res.rules_catalog && Array.isArray(res.rules_catalog)) {
        setRulesCatalog(res.rules_catalog);
      }
    } catch {
      // ignore
    } finally {
      setLoadingWhitelist(false);
    }
  };

  const handleAddWhitelistIp = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanIp = newWhitelistIp.trim();
    if (!cleanIp) {
      showNotice('warning', 'Please enter a valid IP address or CIDR range.');
      return;
    }

    try {
      setAddingWhitelistIp(true);
      const payload: any = {
        ip: cleanIp,
        reason: newWhitelistReason.trim() || (newWhitelistScope === 'category' ? `Allowed for categories: ${newWhitelistSelectedCats.join(', ')}` : 'Trusted administrative access policy'),
        scope: newWhitelistScope,
        expires_in: newWhitelistExpiresIn,
      };

      if (newWhitelistScope === 'rule') {
        payload.allowed_rules = [newWhitelistSelectedRule];
      } else if (newWhitelistScope === 'category') {
        payload.allowed_cats = newWhitelistSelectedCats;
      }
      if (newWhitelistEndpoint.trim()) {
        payload.endpoint = newWhitelistEndpoint.trim();
      }

      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: payload
      });

      if (res && res.success) {
        setNewWhitelistIp('');
        setNewWhitelistReason('');
        setNewWhitelistEndpoint('');
        setNewWhitelistScope('global');
        setNewWhitelistSelectedRule('');
        setNewWhitelistSelectedCats([]);
        await fetchWhitelistData();
        showNotice('success', res.message || `IP ${cleanIp} added to whitelist.`);
      } else {
        showNotice('error', res?.message || 'Failed to add IP to whitelist.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error adding IP to whitelist.');
    } finally {
      setAddingWhitelistIp(false);
    }
  };

  const handleRemoveWhitelistIp = async (ip: string) => {
    try {
      setRemovingWhitelistIp(ip);
      const res = await apiRequest({
        path: '/firewall/whitelist/remove',
        method: 'POST',
        data: { ip }
      });
      if (res && res.success) {
        setWhitelistedIpsList(prev => prev.filter(item => item.ip !== ip));
        showNotice('success', `IP ${ip} was removed from whitelist.`);
      } else {
        showNotice('error', res?.message || 'Failed to remove IP from whitelist.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error removing IP from whitelist.');
    } finally {
      setRemovingWhitelistIp(null);
    }
  };

  const handleOpenEditWhitelistModal = (item: WhitelistedIpItem) => {
    const existingRule = (item.allowed_rules && item.allowed_rules[0]) || '';
    const existingCats = Array.isArray(item.allowed_cats) && item.allowed_cats.length > 0 
      ? item.allowed_cats 
      : ((item as any).allowed_cat ? [(item as any).allowed_cat] : []);
    let remainingTtl = 86400;
    if (item.expires_at && item.expires_at > 0) {
      const diff = item.expires_at - Math.floor(Date.now() / 1000);
      remainingTtl = diff > 0 ? diff : 0;
    } else if (item.expires_at === 0) {
      remainingTtl = 0;
    }

    setEditWhitelistItem({
      isOpen: true,
      ip: item.ip,
      reason: item.reason || '',
      scope: item.scope || 'global',
      selectedRule: existingRule,
      selectedCats: existingCats,
      endpoint: item.endpoint || '',
      expiresIn: remainingTtl,
      isSubmitting: false,
    });
  };

  const handleSaveEditWhitelist = async () => {
    if (!editWhitelistItem.ip) return;
    try {
      setEditWhitelistItem(prev => ({ ...prev, isSubmitting: true }));
      const payload: any = {
        ip: editWhitelistItem.ip,
        scope: editWhitelistItem.scope,
        reason: editWhitelistItem.reason.trim() || 'Updated allowlist policy by administrator',
        expires_in: editWhitelistItem.expiresIn,
      };
      if (editWhitelistItem.scope === 'rule') {
        payload.allowed_rules = [editWhitelistItem.selectedRule];
      } else if (editWhitelistItem.scope === 'category') {
        payload.allowed_cats = editWhitelistItem.selectedCats;
      }
      if (editWhitelistItem.endpoint.trim()) {
        payload.endpoint = editWhitelistItem.endpoint.trim();
      }

      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: payload
      });

      if (res && res.success) {
        await fetchWhitelistData();
        showNotice('success', `Allowlist entry for ${editWhitelistItem.ip} updated.`);
        setEditWhitelistItem(prev => ({ ...prev, isOpen: false }));
      } else {
        showNotice('error', res?.message || 'Failed to update allowlist.');
      }
    } catch (err: any) {
      showNotice('error', err?.message || 'Error updating allowlist entry.');
    } finally {
      setEditWhitelistItem(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  const handleSyncWhitelistToCloudflare = async () => {
    try {
      setSyncingWhitelistToCf(true);
      setWhitelistSyncResult(null);
      const res = await apiRequest({
        path: '/cloudflare/sync-whitelist',
        method: 'POST'
      });
      if (res && res.success) {
        setWhitelistSyncResult({
          success: true,
          message: `Successfully synced ${res.added_count || 0} IPs to Cloudflare Edge.`
        });
        await fetchWhitelistData();
      } else {
        setWhitelistSyncResult({
          success: false,
          message: res?.message || 'Failed to sync whitelist to Cloudflare.'
        });
      }
    } catch (e: any) {
      setWhitelistSyncResult({
        success: false,
        message: e?.message || 'Network error syncing whitelist.'
      });
    } finally {
      setSyncingWhitelistToCf(false);
    }
  };

  // Initial load
  useEffect(() => {
    fetchBlocklistData();
    fetchWhitelistData();
  }, []);

  // Filtered blocked IPs
  const filteredBlocked = lockedIpsList.filter(item => {
    if (blockedFilterTab === 'active' && item.is_expired) return false;
    if (blockedFilterTab === 'expired' && !item.is_expired) return false;
    if (blockedTableSearch) {
      const q = blockedTableSearch.toLowerCase();
      return (
        item.ip.toLowerCase().includes(q) ||
        (item.reason && item.reason.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const totalBlockedPages = Math.ceil(filteredBlocked.length / blockedPageSize) || 1;
  const currentBlockedPage = Math.min(blockedPage, totalBlockedPages);
  const pagedBlocked = filteredBlocked.slice((currentBlockedPage - 1) * blockedPageSize, currentBlockedPage * blockedPageSize);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Title Card */}
      <div className="webcare-firewall-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, margin: '0 0 4px', display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--webcare-text-primary, #0f172a)' }}>
              <Shield size={22} color="#4f46e5" /> Bans, Block &amp; Allowlist Rules
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Comprehensive access control matrix: manage banned IPs, trusted administrator allowlists, payment callback URLs, and targeted bypass rules across origin server and Cloudflare Edge.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '11.5px',
              fontWeight: 700,
              padding: '4px 10px',
              borderRadius: '20px',
              background: 'rgba(79, 70, 229, 0.08)',
              color: '#4f46e5',
              border: '1px solid rgba(79, 70, 229, 0.25)'
            }}>
              Dual-Surface Active
            </span>
          </div>
        </div>
      </div>

      {/* 1. Blocked IP Addresses & Subnets (Central Blocklist Card) */}
      <div id="webcare-blocked-ips-section" className="webcare-firewall-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h3 className="webcare-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
              <Ban size={18} color="#dc2626" /> Blocked IP Addresses &amp; Subnets
            </h3>
            {(() => {
              const activeCount = lockedIpsList.filter(item => !item.is_expired).length;
              const expiredCount = lockedIpsList.filter(item => item.is_expired).length;
              return (
                <>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '10px',
                    background: activeCount > 0 ? 'rgba(220, 38, 38, 0.1)' : 'var(--webcare-bg-elevated, #f1f5f9)',
                    color: activeCount > 0 ? '#dc2626' : 'var(--webcare-text-muted, #64748b)',
                    border: `1px solid ${activeCount > 0 ? 'rgba(220, 38, 38, 0.25)' : 'var(--webcare-border, #e2e8f0)'}`
                  }}>
                    {activeCount} Active
                  </span>
                  {expiredCount > 0 && (
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '10px',
                      background: 'rgba(245, 158, 11, 0.12)',
                      color: '#d97706',
                      border: '1px solid rgba(245, 158, 11, 0.3)'
                    }}>
                      {expiredCount} Expired
                    </span>
                  )}
                </>
              );
            })()}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {Boolean(lockedIpsList.length > 0) && (
              <button
                type="button"
                className="webcare-btn"
                onClick={handleUnbanAllIps}
                disabled={isUnbanningAllIps}
                style={{
                  fontSize: '11px',
                  padding: '5px 12px',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  color: '#dc2626',
                  borderRadius: '5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  fontWeight: 700,
                  cursor: isUnbanningAllIps ? 'not-allowed' : 'pointer'
                }}
                title="Unban all IP addresses from local firewall in 1 click"
              >
                {isUnbanningAllIps ? <Loader2 size={12} className="webcare-spin-icon" /> : <Unlock size={12} />}
                <span>{isUnbanningAllIps ? 'Unbanning All...' : 'Unban All IPs'}</span>
              </button>
            )}
            {Boolean(lockedIpsList.some(item => item.is_expired)) && (
              <button
                type="button"
                className="webcare-btn"
                onClick={handleClearExpiredBans}
                disabled={clearingExpiredBans}
                style={{
                  fontSize: '11px',
                  padding: '5px 12px',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: '#dc2626',
                  borderRadius: '5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  fontWeight: 600,
                  cursor: clearingExpiredBans ? 'not-allowed' : 'pointer'
                }}
                title="Purge all expired temporary ban records in one click"
              >
                {clearingExpiredBans ? <Loader2 size={12} className="webcare-spin-icon" /> : <Trash2 size={12} />}
                <span>{clearingExpiredBans ? 'Clearing...' : `Clear Expired (${lockedIpsList.filter(item => item.is_expired).length})`}</span>
              </button>
            )}
            <button
              type="button"
              className="webcare-btn"
              onClick={fetchBlocklistData}
              disabled={loadingBlocklist}
              style={{
                fontSize: '11px',
                padding: '5px 10px',
                background: 'none',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                color: 'var(--webcare-text-muted, #64748b)',
                borderRadius: '5px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                cursor: 'pointer'
              }}
              title="Refresh blocked IPs list"
            >
              <RefreshCw size={11} className={loadingBlocklist ? 'webcare-spin' : ''} />
            </button>
          </div>
        </div>

        <p className="webcare-firewall-section-desc" style={{ marginBottom: '14px', fontSize: '12px', lineHeight: 1.45 }}>
          Connections originating from these IPs are rejected immediately with HTTP 403 Forbidden before reaching WordPress. Add single IPv4/IPv6 addresses or CIDR subnets (e.g. <code>203.0.113.0/24</code>) with an administrative reason.
        </p>

        {/* Add Blocked IP Form Strip */}
        <form onSubmit={handleAddBlockedIpInline} style={{
          background: 'var(--webcare-bg-elevated, #f8fafc)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          borderRadius: '8px',
          padding: '12px 14px',
          marginBottom: '16px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Plus size={13} color="#dc2626" />
            <span>Add IP or Subnet to Blocklist</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(220px, 2fr) auto', gap: '10px', alignItems: 'center' }}>
            <div>
              <input
                type="text"
                placeholder="IP or Subnet (e.g. 198.51.100.26 or 203.0.113.0/24)"
                value={newBlockIp}
                onChange={(e) => setNewBlockIp(e.target.value)}
                className="webcare-firewall-input"
                style={{ width: '100%', fontSize: '12px', padding: '7px 10px', fontFamily: 'monospace' }}
                required
              />
            </div>
            <div>
              <input
                type="text"
                placeholder="Reason (e.g. Malicious scanning detected, brute-force bot)"
                value={newBlockReason}
                onChange={(e) => setNewBlockReason(e.target.value)}
                className="webcare-firewall-input"
                style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
              />
            </div>
            <div>
              <button
                type="submit"
                disabled={addingBlockIp || !newBlockIp.trim()}
                className="webcare-btn"
                style={{
                  background: '#dc2626',
                  color: '#ffffff',
                  border: 'none',
                  padding: '7px 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: (addingBlockIp || !newBlockIp.trim()) ? 'not-allowed' : 'pointer'
                }}
              >
                {addingBlockIp ? <Loader2 size={12} className="webcare-spin" /> : <Ban size={12} />}
                Block IP
              </button>
            </div>
          </div>
        </form>

        {/* Filter & Search Bar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flex: 1, minWidth: '220px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '320px' }}>
              <Search size={13} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--webcare-text-muted, #94a3b8)' }} />
              <input
                type="text"
                placeholder="Filter blocked IPs, reason..."
                value={blockedTableSearch}
                onChange={(e) => { setBlockedTableSearch(e.target.value); setBlockedPage(1); }}
                className="webcare-firewall-input"
                style={{ width: '100%', paddingLeft: '30px', fontSize: '12px', padding: '6px 10px 6px 30px' }}
              />
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            {(['all', 'active', 'expired'] as const).map(tab => (
              <button
                key={tab}
                type="button"
                className={`webcare-tab-link ${blockedFilterTab === tab ? 'is-active' : ''}`}
                onClick={() => { setBlockedFilterTab(tab); setBlockedPage(1); }}
                style={{ fontSize: '11px', padding: '4px 10px' }}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)} (
                  {tab === 'all' ? lockedIpsList.length : tab === 'active' ? lockedIpsList.filter(i => !i.is_expired).length : lockedIpsList.filter(i => i.is_expired).length}
                )
              </button>
            ))}
          </div>
        </div>

        {/* Blocked IPs Table */}
        <div style={{ overflowX: 'auto', marginBottom: '12px' }}>
          <table className="webcare-waf-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>IP Address / Subnet</th>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>Reason</th>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>Timing / Expiry</th>
                <th style={{ padding: '8px 10px', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pagedBlocked.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '24px 12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    No blocked IP entries found.
                  </td>
                </tr>
              ) : (
                pagedBlocked.map(item => (
                  <tr key={item.ip} style={{ borderBottom: '1px solid var(--webcare-border, #f1f5f9)' }}>
                    <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontWeight: 600 }}>
                      {item.ip}
                    </td>
                    <td style={{ padding: '8px 10px', color: 'var(--webcare-text-secondary, #475569)' }}>
                      {item.reason || 'Manual block'}
                    </td>
                    <td style={{ padding: '8px 10px', fontSize: '11px' }}>
                      <span className={`webcare-badge-pill ${item.is_expired ? 'webcare-badge-neutral' : 'webcare-badge-danger'}`}>
                        {item.is_expired ? 'Expired' : item.time_remaining || 'Permanent'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        <button
                          type="button"
                          className="webcare-btn-micro"
                          onClick={() => handleOpenEditBlocklistModal(item)}
                          title="Edit ban reason or duration"
                        >
                          <Edit2 size={11} /> Edit
                        </button>
                        <button
                          type="button"
                          className="webcare-btn-micro"
                          onClick={() => handleUnblockIp(item.ip)}
                          disabled={unblockingIp === item.ip}
                          style={{ color: '#0284c7' }}
                          title="Unban IP immediately"
                        >
                          {unblockingIp === item.ip ? <Loader2 size={11} className="webcare-spin" /> : <Unlock size={11} />} Unblock
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Cloudflare Edge Sync Toolbar */}
        <div className="webcare-firewall-rule-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <strong style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
              <Cloud size={14} color="#dc2626" /> Cloudflare Edge Sync for IP Blocklist
            </strong>
            <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Creates <code>mode: block</code> IP Access Rules at Cloudflare Edge so malicious traffic is rejected before reaching your origin server.
            </span>
          </div>
          <button
            type="button"
            className="webcare-btn"
            onClick={handleSyncBlocklistToCloudflare}
            disabled={syncingBlocklistToCf || lockedIpsList.length === 0}
            style={{
              background: '#dc2626',
              color: '#ffffff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: (syncingBlocklistToCf || lockedIpsList.length === 0) ? 'not-allowed' : 'pointer'
            }}
          >
            {syncingBlocklistToCf ? <Loader2 size={12} className="webcare-spin" /> : <RefreshCw size={12} />}
            Sync Blocklist to Cloudflare Edge
          </button>
        </div>
      </div>

      {/* 2. Whitelisted IP Addresses */}
      <div className="webcare-firewall-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h3 className="webcare-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
              <Lock size={18} color="#16a34a" /> Whitelisted IP Addresses
            </h3>
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '10px',
              background: whitelistedIpsList.length > 0 ? 'rgba(22, 163, 74, 0.1)' : 'var(--webcare-bg-elevated, #f1f5f9)',
              color: whitelistedIpsList.length > 0 ? '#15803d' : 'var(--webcare-text-muted, #64748b)',
              border: `1px solid ${whitelistedIpsList.length > 0 ? 'rgba(22, 163, 74, 0.25)' : 'var(--webcare-border, #e2e8f0)'}`
            }}>
              {whitelistedIpsList.length} Trusted
            </span>
          </div>
          <button
            type="button"
            className="webcare-btn"
            onClick={fetchWhitelistData}
            disabled={loadingWhitelist}
            style={{
              fontSize: '11px',
              padding: '5px 10px',
              background: 'none',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              color: 'var(--webcare-text-muted, #64748b)',
              borderRadius: '5px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              cursor: 'pointer'
            }}
            title="Refresh whitelisted IPs"
          >
            <RefreshCw size={11} className={loadingWhitelist ? 'webcare-spin' : ''} />
          </button>
        </div>

        <p className="webcare-firewall-section-desc" style={{ marginBottom: '14px', fontSize: '12px', lineHeight: 1.45 }}>
          Requests originating from these IPs are granted high-trust access. Pre-auth traffic bypasses login rate limits and diagnostic tripwires; active admin sessions bypass all inspection.
        </p>

        {/* Add Whitelist Form */}
        <form onSubmit={handleAddWhitelistIp} style={{
          background: 'var(--webcare-bg-elevated, #f8fafc)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          borderRadius: '8px',
          padding: '14px 16px',
          marginBottom: '16px',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px'
        }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(180px, 1.1fr) minmax(200px, 1.8fr)', gap: '10px', alignItems: 'center' }}>
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)', marginBottom: '3px' }}>
                IP Address or CIDR Subnet:
              </label>
              <input
                type="text"
                placeholder="e.g. 198.51.100.42 or 10.0.0.0/8"
                value={newWhitelistIp}
                onChange={(e) => setNewWhitelistIp(e.target.value)}
                className="webcare-firewall-input"
                style={{ width: '100%', fontSize: '12px', padding: '6px 10px', fontFamily: 'monospace' }}
                required
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)', marginBottom: '3px' }}>
                Exemption Scope:
              </label>
              <select
                value={newWhitelistScope}
                onChange={(e) => setNewWhitelistScope(e.target.value as any)}
                className="webcare-firewall-select"
                style={{ width: '100%', fontSize: '12px', padding: '6px 10px' }}
              >
                <option value="global">Global (Full Bypass)</option>
                <option value="rule">Rule-Specific</option>
                <option value="category">Category-Scoped</option>
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)', marginBottom: '3px' }}>
                Reason / Note:
              </label>
              <input
                type="text"
                placeholder="e.g. Office Static IP / Payment Webhook Server"
                value={newWhitelistReason}
                onChange={(e) => setNewWhitelistReason(e.target.value)}
                className="webcare-firewall-input"
                style={{ width: '100%', fontSize: '12px', padding: '6px 10px' }}
              />
            </div>
          </div>

          {/* Secondary Row: Specific Rule or Category Group Multi-select */}
          {newWhitelistScope !== 'global' && (
            <div style={{ paddingTop: '8px', borderTop: '1px dashed var(--webcare-border, #e2e8f0)' }}>
              {newWhitelistScope === 'rule' && (
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)', marginBottom: '4px' }}>
                    Select Specific Rule to Exempt:
                  </label>
                  <select
                    value={newWhitelistSelectedRule}
                    onChange={(e) => {
                      const rId = e.target.value;
                      setNewWhitelistSelectedRule(rId);
                      if (!newWhitelistReason) {
                        const found = rulesCatalog.find(r => r.id === rId);
                        if (found) {
                          setNewWhitelistReason(`Allowed for rule ${found.name}`);
                        }
                      }
                    }}
                    className="webcare-firewall-input"
                    style={{ width: '100%', maxWidth: '500px', fontSize: '12px', padding: '7px 10px' }}
                    required
                  >
                    <option value="">-- Choose Firewall Rule ({rulesCatalog.length || 30}+ Available) --</option>
                    {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => (
                      <optgroup key={cat} label={`📂 ${cat}`}>
                        {rulesCatalog.filter(r => r.category === cat).map(r => (
                          <option key={r.id} value={r.id}>
                            {r.name} [{r.id}]
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                </div>
              )}

              {newWhitelistScope === 'category' && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)' }}>
                      Select Category Groups to Exempt ({newWhitelistSelectedCats.length} selected):
                    </label>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        type="button"
                        onClick={() => {
                          const allCats = Array.from(new Set(rulesCatalog.map(r => r.category)));
                          setNewWhitelistSelectedCats(allCats);
                          if (!newWhitelistReason) {
                            setNewWhitelistReason(`Allowed for all ${allCats.length} category groups`);
                          }
                        }}
                        style={{ background: 'none', border: 'none', padding: 0, fontSize: '11px', color: '#4f46e5', cursor: 'pointer', fontWeight: 600, textDecoration: 'underline' }}
                      >
                        Select All
                      </button>
                      <span style={{ fontSize: '10px', color: 'var(--webcare-text-muted, #94a3b8)' }}>|</span>
                      <button
                        type="button"
                        onClick={() => setNewWhitelistSelectedCats([])}
                        style={{ background: 'none', border: 'none', padding: 0, fontSize: '11px', color: '#64748b', cursor: 'pointer', fontWeight: 500 }}
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div style={{
                    maxHeight: '140px',
                    overflowY: 'auto',
                    padding: '8px 10px',
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    borderRadius: '6px',
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: '6px',
                  }}>
                    {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => {
                      const count = rulesCatalog.filter(r => r.category === cat).length;
                      const isSelected = newWhitelistSelectedCats.includes(cat);
                      return (
                        <button
                          key={cat}
                          type="button"
                          onClick={() => {
                            setNewWhitelistSelectedCats(prev => {
                              const updated = prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat];
                              if (!newWhitelistReason && updated.length > 0) {
                                setNewWhitelistReason(`Allowed for categories: ${updated.join(', ')}`);
                              }
                              return updated;
                            });
                          }}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '5px',
                            padding: '4px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: isSelected ? 600 : 500,
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                            border: isSelected ? '1px solid #4f46e5' : '1px solid var(--webcare-border, #cbd5e1)',
                            background: isSelected ? 'rgba(79, 70, 229, 0.12)' : 'var(--webcare-bg-card, #ffffff)',
                            color: isSelected ? '#4f46e5' : 'var(--webcare-text-primary, #0f172a)',
                          }}
                        >
                          <span style={{ fontSize: '10px' }}>{isSelected ? '✓' : '+'}</span>
                          <span>{cat}</span>
                          <span style={{
                            fontSize: '9.5px',
                            opacity: 0.8,
                            padding: '1px 4px',
                            borderRadius: '3px',
                            background: isSelected ? 'rgba(79, 70, 229, 0.2)' : 'var(--webcare-bg-elevated, #f1f5f9)'
                          }}>
                            {count}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                  {newWhitelistSelectedCats.length === 0 && (
                    <div style={{ fontSize: '11px', color: '#dc2626', marginTop: '4px' }}>
                      * Click one or more category badges above to exempt them.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              disabled={addingWhitelistIp || !newWhitelistIp.trim()}
              className="webcare-btn"
              style={{
                background: '#16a34a',
                color: '#ffffff',
                border: 'none',
                padding: '6px 16px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                cursor: (addingWhitelistIp || !newWhitelistIp.trim()) ? 'not-allowed' : 'pointer'
              }}
            >
              {addingWhitelistIp ? <Loader2 size={12} className="webcare-spin" /> : <Plus size={12} />}
              Add to Allowlist
            </button>
          </div>
        </form>

        {/* Whitelist Table */}
        <div style={{ overflowX: 'auto', marginBottom: '12px' }}>
          <table className="webcare-waf-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>IP / Subnet</th>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>Scope</th>
                <th style={{ padding: '8px 10px', fontWeight: 600 }}>Reason</th>
                <th style={{ padding: '8px 10px', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {whitelistedIpsList.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '24px 12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    No whitelisted IPs currently configured.
                  </td>
                </tr>
              ) : (
                whitelistedIpsList.map(item => (
                  <tr key={item.ip} style={{ borderBottom: '1px solid var(--webcare-border, #f1f5f9)' }}>
                    <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontWeight: 600, color: '#15803d' }}>
                      {item.ip}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10.5px' }}>
                        {item.scope === 'rule' ? 'Rule Specific' : item.scope === 'category' ? 'Category Scoped' : 'Global'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', color: 'var(--webcare-text-secondary, #475569)' }}>
                      {item.reason}
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        <button
                          type="button"
                          className="webcare-btn-micro"
                          onClick={() => handleOpenEditWhitelistModal(item)}
                          title="Modify allowlist scope"
                        >
                          <Edit2 size={11} /> Edit
                        </button>
                        <button
                          type="button"
                          className="webcare-btn-micro"
                          onClick={() => handleRemoveWhitelistIp(item.ip)}
                          disabled={removingWhitelistIp === item.ip}
                          style={{ color: '#dc2626' }}
                          title="Remove from whitelist"
                        >
                          {removingWhitelistIp === item.ip ? <Loader2 size={11} className="webcare-spin" /> : <Trash2 size={11} />} Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Cloudflare Whitelist Sync Toolbar */}
        <div className="webcare-firewall-rule-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <strong style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
              <Cloud size={14} color="#ea580c" /> Cloudflare Edge Sync for IP Whitelist
            </strong>
            <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Creates <code>mode: allow</code> IP Access Rules at Cloudflare Edge so edge rules never challenge site admins.
            </span>
          </div>
          <button
            type="button"
            className="webcare-btn"
            onClick={handleSyncWhitelistToCloudflare}
            disabled={syncingWhitelistToCf || whitelistedIpsList.length === 0}
            style={{
              background: '#ea580c',
              color: '#ffffff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: (syncingWhitelistToCf || whitelistedIpsList.length === 0) ? 'not-allowed' : 'pointer'
            }}
          >
            {syncingWhitelistToCf ? <Loader2 size={12} className="webcare-spin" /> : <RefreshCw size={12} />}
            Sync Whitelist to Cloudflare Edge
          </button>
        </div>
      </div>

      {/* 3. Allowlisted URLs / Endpoints */}
      <div className="webcare-firewall-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <h3 className="webcare-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Globe size={18} color="#0284c7" /> Allowlisted URLs / Endpoints
          </h3>
          <button
            type="button"
            className={`webcare-btn webcare-firewall-rule-save-btn ${savedSuccessKey['waf_whitelisted_urls'] ? 'is-saved' : ''}`}
            onClick={() => handleSaveSingleRule('waf_whitelisted_urls', wafSettings.waf_whitelisted_urls)}
            disabled={savingKey === 'waf_whitelisted_urls'}
          >
            {savingKey === 'waf_whitelisted_urls' ? <Loader2 size={11} className="webcare-spin-icon" /> : (savedSuccessKey['waf_whitelisted_urls'] ? <Check size={11} /> : <Save size={11} />)}
            {savedSuccessKey['waf_whitelisted_urls'] ? 'Saved' : 'Save URLs'}
          </button>
        </div>

        <p className="webcare-firewall-section-desc" style={{ marginBottom: '12px', fontSize: '12px', lineHeight: 1.4 }}>
          Requests targeting these URL paths bypass all inspection rules. Ideal for payment webhooks (Stripe, PayPal) or external APIs. Enter one relative path prefix per line.
        </p>

        <textarea
          rows={6}
          value={wafSettings.waf_whitelisted_urls}
          onChange={(e) => setWafSettings({ ...wafSettings, waf_whitelisted_urls: e.target.value })}
          placeholder="e.g.&#10;/wp-json/my-custom-plugin/v1/webhook&#10;/wc-api/v3/stripe_ipn&#10;/custom-endpoint/"
          className="webcare-firewall-textarea"
          style={{ width: '100%', padding: '10px', fontFamily: 'monospace', fontSize: '12px', marginBottom: '12px' }}
        />

        <div className="webcare-firewall-callout" style={{ fontSize: '11px', padding: '10px 12px' }}>
          <strong style={{ display: 'block', marginBottom: '2px', color: 'var(--webcare-text-primary, #0f172a)' }}>Security Note:</strong>
          URLs listed here bypass SQLi, XSS, and Traversal filtering. Only allowlist trusted external callback paths.
        </div>
      </div>

      {/* 4. Progressive Enforcement & Safety Checkpoints */}
      <div className="webcare-firewall-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <h3 className="webcare-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <AlertCircle size={18} color="#d97706" /> Progressive Enforcement &amp; Safety Checkpoints
          </h3>
          <button
            type="button"
            className={`webcare-btn webcare-firewall-rule-save-btn ${savedSuccessKey['waf_enable_progressive_warnings'] || savedSuccessKey['waf_contact_support_url'] ? 'is-saved' : ''}`}
            onClick={() => {
              handleSaveSingleRule('waf_enable_progressive_warnings', wafSettings.waf_enable_progressive_warnings);
              handleSaveSingleRule('waf_contact_support_url', wafSettings.waf_contact_support_url);
            }}
            disabled={savingKey === 'waf_enable_progressive_warnings' || savingKey === 'waf_contact_support_url'}
          >
            {savingKey === 'waf_enable_progressive_warnings' || savingKey === 'waf_contact_support_url' ? <Loader2 size={11} className="webcare-spin-icon" /> : (savedSuccessKey['waf_enable_progressive_warnings'] ? <Check size={11} /> : <Save size={11} />)}
            {savedSuccessKey['waf_enable_progressive_warnings'] ? 'Saved' : 'Save Settings'}
          </button>
        </div>

        <p className="webcare-firewall-section-desc" style={{ marginBottom: '16px', fontSize: '12px', lineHeight: 1.5 }}>
          Instead of immediately locking out paying customers or accidental visitors on low-tier violations, display an amber warning screen informing them that continued unauthorized actions will result in an IP ban, with a 1-click appeal button.
        </p>

        {/* Toggle: Progressive Warning Screen */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', marginBottom: '16px', padding: '12px 14px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
          <input
            type="checkbox"
            id="bans_waf_enable_progressive_warnings"
            checked={wafSettings.waf_enable_progressive_warnings}
            onChange={(e) => setWafSettings({ ...wafSettings, waf_enable_progressive_warnings: e.target.checked })}
            style={{ accentColor: '#4f46e5', marginTop: '3px', cursor: 'pointer' }}
          />
          <label htmlFor="bans_waf_enable_progressive_warnings" style={{ cursor: 'pointer', flex: 1 }}>
            <strong style={{ fontSize: '13px', display: 'block', color: 'var(--webcare-text-primary, #0f172a)' }}>
              Enable Progressive Warning Screen (Soft Block Mode)
            </strong>
            <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.4, display: 'block', marginTop: '2px' }}>
              Displays an amber warning screen with the visitor&apos;s unique Support Reference Code and Contact Administrator button. Critical exploits always remain strictly hard-blocked.
            </span>
          </label>
        </div>

        {/* Support URL */}
        <div style={{ marginTop: '14px' }}>
          <label htmlFor="bans_waf_contact_support_url" style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>
            Support / Contact Page URL
          </label>
          <input
            id="bans_waf_contact_support_url"
            type="text"
            value={wafSettings.waf_contact_support_url}
            onChange={(e) => setWafSettings({ ...wafSettings, waf_contact_support_url: e.target.value })}
            placeholder="e.g. /contact/ or https://example.com/support/"
            className="webcare-firewall-input"
            style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
          />
        </div>
      </div>

      {/* 5. Targeted User-Agent, Endpoint & IP Allowlist Rules */}
      <TargetedAllowlistManagerCard
        rulesJson={wafSettings.waf_targeted_allowlist_rules}
        onChange={(newJson) => setWafSettings({ ...wafSettings, waf_targeted_allowlist_rules: newJson })}
        onSave={(newJson) => handleSaveSingleRule('waf_targeted_allowlist_rules', newJson)}
        isSaving={savingKey === 'waf_targeted_allowlist_rules'}
        isSaved={!!savedSuccessKey['waf_targeted_allowlist_rules']}
        activePluginSlugs={activePluginSlugs}
      />

      {/* Edit Whitelist Modal */}
      {editWhitelistItem.isOpen && (
        <div className="webcare-modal-backdrop" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          backgroundColor: 'rgba(15, 23, 42, 0.7)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100000,
          padding: '20px'
        }}>
          <div className="webcare-modal-card" style={{
            background: 'var(--webcare-bg-surface, #ffffff)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '520px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            overflow: 'hidden',
            border: '1px solid var(--webcare-border, #cbd5e1)'
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--webcare-bg-elevated, #f8fafc)'
            }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Modify Allowlist Policy
                </h3>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                  {editWhitelistItem.ip}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setEditWhitelistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--webcare-text-muted, #94a3b8)', padding: '4px' }}
              >
                <X size={16} />
              </button>
            </div>
            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Exemption Scope:
                </label>
                <select
                  value={editWhitelistItem.scope}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, scope: e.target.value as any }))}
                  className="webcare-firewall-select"
                  style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                >
                  <option value="global">Global (Bypass All Rules)</option>
                  <option value="rule">Rule-Specific</option>
                  <option value="category">Category-Scoped</option>
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Reason / Documented Policy:
                </label>
                <input
                  type="text"
                  value={editWhitelistItem.reason}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, reason: e.target.value }))}
                  className="webcare-firewall-input"
                  style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                />
              </div>
            </div>
            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '8px',
              background: 'var(--webcare-bg-elevated, #f8fafc)'
            }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setEditWhitelistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ padding: '6px 12px', fontSize: '12px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="webcare-btn"
                onClick={handleSaveEditWhitelist}
                disabled={editWhitelistItem.isSubmitting}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 14px',
                  fontSize: '12px',
                  fontWeight: 600,
                  borderRadius: '5px'
                }}
              >
                {editWhitelistItem.isSubmitting ? <Loader2 size={12} className="webcare-spin" /> : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Blocklist Modal */}
      {editBlocklistItem.isOpen && (
        <div className="webcare-modal-backdrop" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          backgroundColor: 'rgba(15, 23, 42, 0.7)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100000,
          padding: '20px'
        }}>
          <div className="webcare-modal-card" style={{
            background: 'var(--webcare-bg-surface, #ffffff)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '500px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            overflow: 'hidden',
            border: '1px solid var(--webcare-border, #cbd5e1)'
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--webcare-bg-elevated, #f8fafc)'
            }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Edit Blocklist Policy
                </h3>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                  {editBlocklistItem.ip}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setEditBlocklistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--webcare-text-muted, #94a3b8)', padding: '4px' }}
              >
                <X size={16} />
              </button>
            </div>
            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Lockout Duration:
                </label>
                <select
                  value={editBlocklistItem.durationSeconds}
                  onChange={(e) => setEditBlocklistItem(prev => ({ ...prev, durationSeconds: Number(e.target.value) }))}
                  className="webcare-firewall-select"
                  style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                >
                  <option value={0}>Permanent Ban (Never Expires)</option>
                  <option value={3600}>1 Hour</option>
                  <option value={86400}>24 Hours (1 Day)</option>
                  <option value={604800}>7 Days</option>
                  <option value={2592000}>30 Days</option>
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Administrative Reason:
                </label>
                <input
                  type="text"
                  value={editBlocklistItem.reason}
                  onChange={(e) => setEditBlocklistItem(prev => ({ ...prev, reason: e.target.value }))}
                  className="webcare-firewall-input"
                  style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                />
              </div>
            </div>
            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '8px',
              background: 'var(--webcare-bg-elevated, #f8fafc)'
            }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setEditBlocklistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ padding: '6px 12px', fontSize: '12px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="webcare-btn"
                onClick={handleSaveEditBlocklist}
                disabled={editBlocklistItem.isSubmitting}
                style={{
                  background: '#dc2626',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 14px',
                  fontSize: '12px',
                  fontWeight: 600,
                  borderRadius: '5px'
                }}
              >
                {editBlocklistItem.isSubmitting ? <Loader2 size={12} className="webcare-spin" /> : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Dialog Modal */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        targetItem={confirmDialog.targetItem}
        confirmLabel={confirmDialog.confirmLabel}
        variant={confirmDialog.variant}
        isLoading={confirmDialog.isLoading}
        onConfirm={confirmDialog.onConfirm || (() => {})}
        onClose={() => setConfirmDialog(prev => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};

export default BansAndAllowlistsPanel;
