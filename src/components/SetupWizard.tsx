import React, { useState, useEffect } from '@wordpress/element';
import {
  ArrowLeft,
  ArrowRight,
  Sparkles,
  Loader2,
  CheckCircle2,
  Download
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import { applyWebCareTheme, getWebCareTheme } from '../utils/theme';
import { WizardTopBar } from './wizard/WizardTopBar';
import { WizardNavigationRail } from './wizard/WizardNavigationRail';
import { BlueprintModal } from './wizard/BlueprintModal';

// Step Cards
import { Step01StackArchetype } from './wizard/steps/Step01StackArchetype';
import { Step02RuntimeTelemetry } from './wizard/steps/Step02RuntimeTelemetry';
import { Step03BehavioralModularWaf } from './wizard/steps/Step03BehavioralModularWaf';
import { Step03ZeroLockoutWhitelist } from './wizard/steps/Step03ZeroLockoutWhitelist';
import { Step04CorePreloadWaf } from './wizard/steps/Step04CorePreloadWaf';
import { Step05CafWooShield } from './wizard/steps/Step05CafWooShield';
import { Step06EgressSmtpShield } from './wizard/steps/Step06EgressSmtpShield';
import { Step07BypassSeoBots } from './wizard/steps/Step07BypassSeoBots';
import { Step08CloudflareEdge } from './wizard/steps/Step08CloudflareEdge';
import { Step09Login2faPasskeys } from './wizard/steps/Step09Login2faPasskeys';
import { Step10ServerArmorHeaders } from './wizard/steps/Step10ServerArmorHeaders';
import { Step11MalwareScanner } from './wizard/steps/Step11MalwareScanner';
import { Step12ResourceEnvelope } from './wizard/steps/Step12ResourceEnvelope';
import { Step12MalwareResourceEnvelope } from './wizard/steps/Step12MalwareResourceEnvelope';
import { Step13AiCopilotAlerts } from './wizard/steps/Step13AiCopilotAlerts';
import { Step14LedgerLaunch } from './wizard/steps/Step14LedgerLaunch';

interface WizardStatus {
  client_ip: string;
  is_whitelisted: boolean;
  ip_whitelist?: Array<{ ip: string; label: string; created_at?: string }>;
  is_cloudflare_active: boolean;
  cf_ray?: string;
  admin_email: string;
  site_name: string;
  site_domain?: string;
  root_domain?: string;
  detected_archetype: 'ecommerce' | 'business' | 'blog' | 'membership';
  wizard_completed: boolean;
  support_code: string;
  waf_settings?: any;
  server_info?: any;
  active_plugin_slugs?: string[];
  settings?: any;
  cloudflare_status?: { has_saved_token: boolean; zone_id: string; is_active: boolean };
  preload_waf?: { is_active: boolean; is_compiled: boolean; auto_prepend_ini: string; target_info?: any };
  egress_status?: any;
  stack_snapshot?: any;
  capability_profile?: any;
  notification_settings?: any;
}

export const SetupWizard = () => {
  const [step, setStep] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [status, setStatus] = useState<WizardStatus | null>(null);

  // Persona Mode: 'calm' (3 steps) vs 'express' (6 steps) vs 'developer' (14 steps)
  const [wizardMode, setWizardMode] = useState<'calm' | 'express' | 'developer'>(() => {
    try {
      const saved = localStorage.getItem('webcare_wizard_mode');
      if (saved === 'calm' || saved === 'express' || saved === 'developer') return saved;
    } catch {}
    return 'calm';
  });
  const [isBlueprintModalOpen, setIsBlueprintModalOpen] = useState<boolean>(false);
  const [configuredSteps, setConfiguredSteps] = useState<Set<number>>(new Set([1]));

  // Theme Mode
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>(() => getWebCareTheme());

  const toggleThemeMode = () => {
    const next = themeMode === 'dark' ? 'light' : 'dark';
    setThemeMode(next);
    applyWebCareTheme(next);
  };

  useEffect(() => {
    applyWebCareTheme(themeMode);

    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'webcare_theme_mode' && (e.newValue === 'light' || e.newValue === 'dark')) {
        setThemeMode(e.newValue);
        applyWebCareTheme(e.newValue);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [themeMode]);

  // Step 1: Foundation & Archetype
  const [archetype, setArchetype] = useState<string>('business');
  const [adaptiveStackMonitoring, setAdaptiveStackMonitoring] = useState<boolean>(true);
  const [environmentOverride, setEnvironmentOverride] = useState<string>('auto');

  // Step 2 & 3: Telemetry & Whitelist
  const [trustedProxyIps, setTrustedProxyIps] = useState<string[]>([]);
  const [whitelistIp, setWhitelistIp] = useState<boolean>(true);
  const [ipWhitelistEntries, setIpWhitelistEntries] = useState<Array<{ ip: string; label: string; created_at?: string }>>([]);

  // Step 4 & 5: Perimeter WAF, CAF 2.0 & Woo Armor
  const [firewallToggles, setFirewallToggles] = useState({
    block_malicious_uploads: true,
    brute_force_protection: true,
    virtual_patching: true,
    bad_bot_shield: true,
  });

  const [wafAdvanced, setWafAdvanced] = useState<any>({
    waf_enabled: true,
    waf_learning_mode: false,
    waf_rasp_enabled: true,
    waf_allow_seo_bots: true,
    waf_caf_block_inactive_plugins: true,
    waf_caf_lock_dormant_rest: true,
    waf_caf_strict_guest_admin_ajax: true,
    waf_ecommerce_safe_mode: false,
    waf_woo_carding_protection: true,
    waf_woo_coupon_protection: true,
    waf_woo_registration_protection: true,
    waf_woo_cart_flood_protection: true,
    waf_woo_scraping_protection: true,
    waf_max_404_per_minute: 20,
    waf_lockout_duration_mins: 30,
    waf_woo_carding_max_attempts: 5,
    waf_woo_carding_max_declines: 3,
    waf_woo_coupon_max_failures: 8,
    waf_woo_cart_max_adds_per_min: 35,
    waf_woo_reg_max_per_hour: 5,
    waf_woo_scraping_max_reqs_per_min: 60,
    waf_404_exempt_patterns: '',
    waf_blocked_countries: '',
    waf_geo_block_mode: 'admin_only',
    cf_auto_ban_sync: true,
    cf_ddos_protection_enabled: true,
    cf_ddos_threshold: 100,
  });

  // Context-Adaptive Firewall (CAF) Profile State
  const [cafProfile, setCafProfile] = useState<string>('balanced');

  // Step 6: Outbound Egress
  const [egressMode, setEgressMode] = useState<'off' | 'monitor' | 'enforce'>('monitor');
  const [egressAllowedDomains, setEgressAllowedDomains] = useState<string[]>([]);
  const [egressBlockUnverifiedSsl, setEgressBlockUnverifiedSsl] = useState<boolean>(true);

  // Step 7: Webhook Bypasses & SEO Bots
  const [targetedRules, setTargetedRules] = useState<any[]>([]);

  // Step 8: Cloudflare Edge
  const [cfToken, setCfToken] = useState<string>('');
  const [cfZone, setCfZone] = useState<string>('');

  // Step 9: Zero-Trust Identity, 2FA & Passkeys
  const [identitySettings, setIdentitySettings] = useState<any>({
    login_max_retries: 5,
    login_lockout_duration: 60,
    login_honeypot_usernames: ['admin', 'administrator', 'root', 'test', 'wpadmin'],
    two_factor_enabled: false,
    two_factor_policy: 'grace_period',
    two_factor_grace_days: 7,
    two_factor_roles: ['administrator'],
    passkeys_enabled: true,
    strong_passwords_enabled: true,
    hibp_check_enabled: true,
    disable_xmlrpc: true,
    disable_user_enumeration: true,
    hide_wp_version: true,
  });

  // Step 10: Server Armor & HTTP Headers
  const [serverSettings, setServerSettings] = useState<any>({
    htaccess_hardening_enabled: true,
    disable_file_editing: true,
    security_headers_enabled: true,
    hsts_enabled: false,
    x_frame_options: 'SAMEORIGIN',
    referrer_policy: 'strict-origin-when-cross-origin',
  });

  // Step 11: 14-Pass Malware Scanner
  const [customScanOptions, setCustomScanOptions] = useState<{ [key: string]: boolean }>({
    scan_known_malware: true,
    scan_backdoors_heuristics: true,
    scan_core_integrity: true,
    scan_plugin_integrity: true,
    scan_theme_integrity: true,
    scan_unbundled_files: true,
    scan_vulnerable_software: true,
    scan_rogue_admins: true,
    scan_malicious_urls: true,
    scan_public_quarantine: true,
    check_domain_blocklist: true,
    monitor_firewall_status: true,
    scan_password_strength: true,
    monitor_disk_space: true,
  });

  const [scannerSettings, setScannerSettings] = useState<any>({
    auto_quarantine_high_confidence: true,
    auto_repair_core_files: true,
    excluded_paths: [],
    excluded_extensions: ['mp4', 'mov', 'avi', 'mkv', 'iso', 'tar', 'gz'],
    max_file_size_mb: 10,
  });

  // Step 12: Hardware Safety Envelope
  const [scanBatchSize, setScanBatchSize] = useState<number>(50);
  const [memoryEnvelope, setMemoryEnvelope] = useState<string>('balanced');
  const [adaptiveThrottling, setAdaptiveThrottling] = useState<boolean>(true);
  const [batchDelayMs, setBatchDelayMs] = useState<number>(0);

  // Step 13: AI Copilot & SOC Alerts
  const [scanSchedule, setScanSchedule] = useState<string>('daily');
  const [alertEmail, setAlertEmail] = useState<string>('');
  const [alerts, setAlerts] = useState<any>({
    notify_critical: true,
    notify_logins: true,
    notify_panic: true,
    notify_waf_lockout_spike: true,
    notify_plugin_vulns: true,
    weekly_digest_enabled: true,
  });
  const [slackWebhookUrl, setSlackWebhookUrl] = useState<string>('');
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState<string>('');
  const [customWebhookUrl, setCustomWebhookUrl] = useState<string>('');
  const [aiProvider, setAiProvider] = useState<string>('gemini');
  const [aiApiKey, setAiApiKey] = useState<string>('');
  const [aiModel, setAiModel] = useState<string>('gemini-3.5-flash-lite');

  // Step 14: Data Governance & Audit Ledger
  const [governanceSettings, setGovernanceSettings] = useState<any>({
    logRetentionDays: 30,
    tamperWebhookUrl: '',
    deleteDataOnUninstall: false,
    dropTablesOnUninstall: true,
    deleteOptionsOnUninstall: true,
  });

  const [savingStep, setSavingStep] = useState<boolean>(false);

  // Centralized State Hydration Engine (Used by both initial load and live re-checks)
  const hydrateFromStatus = (res: any, updateStepAndMode: boolean = false) => {
    if (!res) return;
    setStatus(res);
    if (res.detected_archetype) setArchetype(res.detected_archetype);
    if (res.admin_email) setAlertEmail(res.admin_email);
    if (res.is_whitelisted) setWhitelistIp(true);
    if (res.scan_schedule) setScanSchedule(res.scan_schedule);

    if (updateStepAndMode) {
      const urlParams = new URLSearchParams(window.location.search);
      const modeFromUrl = urlParams.get('mode');
      if (modeFromUrl === 'calm' || modeFromUrl === 'express' || modeFromUrl === 'developer') {
        setWizardMode(modeFromUrl);
      } else if (res.wizard_mode === 'calm' || res.wizard_mode === 'express' || res.wizard_mode === 'developer') {
        setWizardMode(res.wizard_mode);
      }

      const activeMode = (modeFromUrl === 'calm' || modeFromUrl === 'express' || modeFromUrl === 'developer')
        ? modeFromUrl
        : (res.wizard_mode || 'calm');
      const maxStep = activeMode === 'calm' ? 3 : (activeMode === 'express' ? 6 : 14);

      const stepFromUrl = parseInt(urlParams.get('step') || '0', 10);
      const resolvedStep = (stepFromUrl >= 1 && stepFromUrl <= maxStep)
        ? stepFromUrl
        : (res.wizard_current_step && res.wizard_current_step >= 1 && res.wizard_current_step <= maxStep ? res.wizard_current_step : 1);

      setStep(resolvedStep);

      if (resolvedStep > 1) {
        const preConfigured = new Set<number>();
        for (let i = 1; i < resolvedStep; i++) {
          preConfigured.add(i);
        }
        setConfiguredSteps(preConfigured);
      }
    }

    // State Re-Hydration: IP Whitelist
    if (Array.isArray(res.ip_whitelist) && res.ip_whitelist.length > 0) {
      setIpWhitelistEntries(res.ip_whitelist);
    }

    // State Re-Hydration: Cloudflare
    if (res.cloudflare_status) {
      if (res.cloudflare_status.has_saved_token) {
        setCfToken('••••••••');
      }
      if (res.cloudflare_status.zone_id) {
        setCfZone(res.cloudflare_status.zone_id);
      }
    }

    // State Re-Hydration: CAF Protection Profile
    if (res.caf_status?.active_profile) {
      setCafProfile(res.caf_status.active_profile);
    } else if (res.caf_status?.recommended_profile) {
      setCafProfile(res.caf_status.recommended_profile);
    } else if (res.server_info?.php?.memory_limit === '128M' || res.server_info?.is_shared_hosting) {
      setCafProfile('cpanel_shared_saver');
    }

    // State Re-Hydration: WAF Toggles & Advanced
    if (res.waf_settings && typeof res.waf_settings === 'object') {
      const isShopStack = Boolean(
        res.stack_snapshot?.detected_ecosystems?.includes('woocommerce') ||
        res.stack_snapshot?.detected_ecosystems?.includes('commerce') ||
        res.commerce_telemetry?.has_detected_plugins ||
        res.detected_archetype === 'ecommerce' ||
        res.detected_archetype === 'membership'
      );

      setFirewallToggles((prev) => ({
        ...prev,
        block_malicious_uploads: res.waf_settings.waf_block_uploads_exec !== undefined ? !!res.waf_settings.waf_block_uploads_exec : prev.block_malicious_uploads,
        brute_force_protection: res.waf_settings.waf_enable_brute_force_shield !== undefined ? !!res.waf_settings.waf_enable_brute_force_shield : prev.brute_force_protection,
        virtual_patching: res.waf_settings.waf_enable_virtual_patching !== undefined ? !!res.waf_settings.waf_enable_virtual_patching : prev.virtual_patching,
        bad_bot_shield: res.waf_settings.waf_block_bad_bots !== undefined ? !!res.waf_settings.waf_block_bad_bots : prev.bad_bot_shield,
      }));

      setWafAdvanced((prev: any) => ({
        ...prev,
        ...res.waf_settings,
        waf_ecommerce_safe_mode: res.waf_settings.waf_ecommerce_safe_mode !== undefined
          ? !!res.waf_settings.waf_ecommerce_safe_mode
          : isShopStack,
      }));
    }

    // State Re-Hydration: Egress
    if (res.egress_status?.settings) {
      const es = res.egress_status.settings;
      if (es.mode) setEgressMode(es.mode);
      if (Array.isArray(es.allowed_hosts)) setEgressAllowedDomains(es.allowed_hosts);
    }

    // State Re-Hydration: SettingsManager Safe Payload
    if (res.settings) {
      const s = res.settings;
      if (s.schedule_enabled !== undefined) {
        setScanSchedule(s.schedule_enabled ? (s.schedule_frequency || 'daily') : 'manual');
      }
      if (s.custom_scan_options && Object.keys(s.custom_scan_options).length > 0) {
        setCustomScanOptions((prev) => ({ ...prev, ...s.custom_scan_options }));
      }
      if (s.scan_batch_size) setScanBatchSize(s.scan_batch_size);
      if (s.scan_memory_safety_envelope) setMemoryEnvelope(s.scan_memory_safety_envelope);
      if (s.scan_adaptive_throttling !== undefined) setAdaptiveThrottling(s.scan_adaptive_throttling);
      if (s.scan_batch_delay_ms !== undefined) setBatchDelayMs(s.scan_batch_delay_ms);

      // Governance
      setGovernanceSettings({
        logRetentionDays: s.activity_log_settings?.retention_days || 30,
        tamperWebhookUrl: s.activity_log_settings?.tamper_webhook_url || '',
        deleteDataOnUninstall: !!s.delete_data_on_uninstall,
        dropTablesOnUninstall: s.uninstall_drop_tables !== undefined ? !!s.uninstall_drop_tables : true,
        deleteOptionsOnUninstall: s.uninstall_delete_options !== undefined ? !!s.uninstall_delete_options : true,
      });

      // Identity
      setIdentitySettings((prev: any) => ({
        ...prev,
        login_max_retries: s.login_max_retries || prev.login_max_retries,
        login_lockout_duration: s.login_lockout_duration || prev.login_lockout_duration,
        two_factor_enabled: s.auth_2fa_enabled !== undefined ? !!s.auth_2fa_enabled : prev.two_factor_enabled,
        two_factor_policy: s.auth_2fa_policy_mode || prev.two_factor_policy,
        two_factor_grace_days: s.auth_2fa_grace_days || prev.two_factor_grace_days,
        strong_passwords_enabled: s.waf_enforce_strong_passwords !== undefined ? !!s.waf_enforce_strong_passwords : prev.strong_passwords_enabled,
        hibp_check_enabled: s.waf_check_pwned_passwords !== undefined ? !!s.waf_check_pwned_passwords : prev.hibp_check_enabled,
        disable_file_editing: s.disable_file_editing !== undefined ? !!s.disable_file_editing : prev.disable_file_editing,
        hide_wp_version: s.hide_wp_version !== undefined ? !!s.hide_wp_version : prev.hide_wp_version,
        disable_user_enumeration: s.block_user_enumeration !== undefined ? !!s.block_user_enumeration : prev.disable_user_enumeration,
      }));

      // Server
      setServerSettings((prev: any) => ({
        ...prev,
        disable_file_editing: s.disable_file_editing !== undefined ? !!s.disable_file_editing : prev.disable_file_editing,
        security_headers_enabled: s.header_nosniff !== undefined ? !!s.header_nosniff : prev.security_headers_enabled,
        hsts_enabled: s.header_hsts !== undefined ? !!s.header_hsts : prev.hsts_enabled,
      }));

      // Targeted Rules
      if (s.waf_targeted_allowlist_rules) {
        try {
          const parsed = typeof s.waf_targeted_allowlist_rules === 'string'
            ? JSON.parse(s.waf_targeted_allowlist_rules)
            : s.waf_targeted_allowlist_rules;
          if (Array.isArray(parsed)) {
            setTargetedRules(parsed);
          }
        } catch (e) {}
      }

      // AI Settings Re-hydration
      if (s.ai_provider) {
        setAiProvider(s.ai_provider);
        if (s.ai_provider === 'gemini') {
          if (s.gemini_model) setAiModel(s.gemini_model);
          if (s.has_gemini_key) setAiApiKey('••••••••');
        } else if (s.ai_provider === 'openai') {
          if (s.openai_model) setAiModel(s.openai_model);
          if (s.has_openai_key) setAiApiKey('••••••••');
        } else if (s.ai_provider === 'claude') {
          if (s.claude_model) setAiModel(s.claude_model);
          if (s.has_claude_key) setAiApiKey('••••••••');
        } else if (s.ai_provider === 'deepseek') {
          if (s.deepseek_model) setAiModel(s.deepseek_model);
          if (s.has_deepseek_key) setAiApiKey('••••••••');
        } else if (s.ai_provider === 'openrouter') {
          if (s.openrouter_model) setAiModel(s.openrouter_model);
          if (s.has_openrouter_key) setAiApiKey('••••••••');
        }
      }
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await apiRequest({ path: '/wizard/status' });
      if (res) {
        hydrateFromStatus(res, false);
      }
    } catch (err) {
      console.error('Failed to fetch wizard status:', err);
    }
  };

  // Load initial status with complete state re-hydration
  useEffect(() => {
    let isMounted = true;
    (async () => {
      try {
        const res = await apiRequest({ path: '/wizard/status' });
        if (isMounted && res) {
          hydrateFromStatus(res, true);
        }
      } catch (e) {
        console.error('Failed to load wizard status', e);
      } finally {
        if (isMounted) setLoading(false);
      }
    })();
    return () => { isMounted = false; };
  }, []);

  const totalSteps = wizardMode === 'calm' ? 3 : (wizardMode === 'express' ? 6 : 14);

  // Centralized Wizard Payload Builder
  const buildWizardPayload = (targetStepNum?: number) => ({
    current_step: targetStepNum !== undefined ? targetStepNum : step,
    wizard_mode: wizardMode,
    whitelist_ip: whitelistIp,
    ip_whitelist_entries: ipWhitelistEntries,
    archetype,
    caf_profile: cafProfile,
    firewall_settings: {
      waf_enabled: wafAdvanced.waf_enabled !== false,
      waf_learning_mode: !!wafAdvanced.waf_learning_mode,
      waf_block_uploads_exec: firewallToggles.block_malicious_uploads,
      waf_enable_brute_force_shield: firewallToggles.brute_force_protection,
      waf_enable_virtual_patching: firewallToggles.virtual_patching,
      waf_block_bad_bots: firewallToggles.bad_bot_shield,
      waf_rasp_enabled: wafAdvanced.waf_rasp_enabled !== false,
      waf_allow_seo_bots: !!wafAdvanced.waf_allow_seo_bots,
      waf_caf_block_inactive_plugins: !!wafAdvanced.waf_caf_block_inactive_plugins,
      waf_caf_lock_dormant_rest: !!wafAdvanced.waf_caf_lock_dormant_rest,
      waf_caf_strict_guest_admin_ajax: !!wafAdvanced.waf_caf_strict_guest_admin_ajax,
      waf_ecommerce_safe_mode: !!wafAdvanced.waf_ecommerce_safe_mode,
      waf_woo_carding_protection: !!wafAdvanced.waf_woo_carding_protection,
      waf_woo_coupon_protection: !!wafAdvanced.waf_woo_coupon_protection,
      waf_woo_registration_protection: !!wafAdvanced.waf_woo_registration_protection,
      waf_woo_cart_flood_protection: !!wafAdvanced.waf_woo_cart_flood_protection,
      waf_woo_scraping_protection: !!wafAdvanced.waf_woo_scraping_protection,
      waf_max_404_per_minute: wafAdvanced.waf_max_404_per_minute || 20,
      waf_lockout_duration_mins: wafAdvanced.waf_lockout_duration_mins || 30,
      waf_woo_carding_max_attempts: wafAdvanced.waf_woo_carding_max_attempts || 5,
      waf_woo_carding_max_declines: wafAdvanced.waf_woo_carding_max_declines || 3,
      waf_woo_coupon_max_failures: wafAdvanced.waf_woo_coupon_max_failures || 8,
      waf_woo_cart_max_adds_per_min: wafAdvanced.waf_woo_cart_max_adds_per_min || 35,
      waf_woo_reg_max_per_hour: wafAdvanced.waf_woo_reg_max_per_hour || 5,
      waf_woo_scraping_max_reqs_per_min: wafAdvanced.waf_woo_scraping_max_reqs_per_min || 60,
      cf_auto_ban_sync: !!wafAdvanced.cf_auto_ban_sync,
      cf_ddos_protection_enabled: !!wafAdvanced.cf_ddos_protection_enabled,
      cf_ddos_threshold: wafAdvanced.cf_ddos_threshold || 100,
    },
    egress_settings: {
      mode: egressMode,
      allowed_hosts: egressAllowedDomains,
      block_ssrf_metadata: true,
      block_exfil_webhooks: true,
      block_suspicious_tld: true,
    },
    cloudflare: (cfToken.trim() && cfToken !== '••••••••') ? {
      api_token: cfToken.trim(),
      zone_id: cfZone.trim() || undefined
    } : (cfZone.trim() || status?.cloudflare_status?.has_saved_token) ? {
      zone_id: cfZone.trim() || undefined
    } : undefined,
    scan_schedule: scanSchedule,
    alerts: {
      email: alertEmail,
      ...alerts,
    },
    custom_scan_options: customScanOptions,
    scan_batch_size: scanBatchSize,
    scan_memory_safety_envelope: memoryEnvelope,
    scan_adaptive_throttling: adaptiveThrottling,
    scan_batch_delay_ms: batchDelayMs,
    delete_data_on_uninstall: governanceSettings.deleteDataOnUninstall,
    uninstall_drop_tables: governanceSettings.dropTablesOnUninstall,
    uninstall_delete_options: governanceSettings.deleteOptionsOnUninstall,
    activity_log_settings: {
      retention_days: governanceSettings.logRetentionDays,
      tamper_webhook_url: governanceSettings.tamperWebhookUrl.trim(),
    },
    waf_targeted_allowlist_rules: targetedRules,
    advanced_settings: {
      login_max_retries: identitySettings.login_max_retries,
      login_lockout_duration: identitySettings.login_lockout_duration,
      auth_2fa_enabled: identitySettings.two_factor_enabled,
      auth_2fa_enforce_admins: (identitySettings.two_factor_roles || []).includes('administrator'),
      auth_2fa_policy_mode: identitySettings.two_factor_policy,
      auth_2fa_grace_days: identitySettings.two_factor_grace_days,
      waf_enforce_strong_passwords: identitySettings.strong_passwords_enabled,
      waf_check_pwned_passwords: identitySettings.hibp_check_enabled,
      disable_file_editing: serverSettings.disable_file_editing,
      hide_wp_version: identitySettings.hide_wp_version,
      block_user_enumeration: identitySettings.disable_user_enumeration,
      header_hsts: serverSettings.hsts_enabled,
      header_nosniff: serverSettings.security_headers_enabled,
      header_x_frame_options: serverSettings.security_headers_enabled,
      header_referrer_policy: serverSettings.security_headers_enabled,
      auto_quarantine_critical: scannerSettings.auto_quarantine_high_confidence,
      ai_enabled: (aiProvider === 'wp_ai_connect') || (aiApiKey.trim() !== '' && aiApiKey !== '••••••••'),
      ai_provider: aiProvider,
      gemini_api_key: (aiProvider === 'gemini' && aiApiKey !== '••••••••') ? aiApiKey.trim() : undefined,
      openai_api_key: (aiProvider === 'openai' && aiApiKey !== '••••••••') ? aiApiKey.trim() : undefined,
      claude_api_key: (aiProvider === 'claude' && aiApiKey !== '••••••••') ? aiApiKey.trim() : undefined,
      deepseek_api_key: (aiProvider === 'deepseek' && aiApiKey !== '••••••••') ? aiApiKey.trim() : undefined,
      openrouter_api_key: (aiProvider === 'openrouter' && aiApiKey !== '••••••••') ? aiApiKey.trim() : undefined,
      gemini_model: aiProvider === 'gemini' ? (aiModel || 'gemini-3.5-flash-lite') : undefined,
      openai_model: aiProvider === 'openai' ? (aiModel || 'gpt-6.1-sol') : undefined,
      claude_model: aiProvider === 'claude' ? (aiModel || 'claude-sonnet-5-5') : undefined,
      deepseek_model: aiProvider === 'deepseek' ? (aiModel || 'deepseek-chat') : undefined,
      openrouter_model: aiProvider === 'openrouter' ? (aiModel || 'auto') : undefined,
    }
  });

  const handleSaveAndNext = async () => {
    setConfiguredSteps((prev) => new Set([...prev, step]));
    const nextStep = step < totalSteps ? step + 1 : step;

    setSavingStep(true);
    try {
      await apiRequest({
        path: '/wizard/save',
        method: 'POST',
        data: {
          ...buildWizardPayload(nextStep),
          is_intermediate_step: true,
        },
      });
    } catch (e) {
      console.warn('Silent save on step advance warning', e);
    } finally {
      setSavingStep(false);
    }

    if (step < totalSteps) {
      setStep(nextStep);
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('step', String(nextStep));
        window.history.replaceState(null, '', url.toString());
      } catch (err) {}
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handleBack = () => {
    if (step > 1) {
      const prevStep = step - 1;
      // Quietly persist settings with target step so refresh stays on prevStep
      apiRequest({
        path: '/wizard/save',
        method: 'POST',
        data: {
          ...buildWizardPayload(prevStep),
          is_intermediate_step: true,
        },
      }).catch(() => {});

      setStep(prevStep);
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('step', String(prevStep));
        window.history.replaceState(null, '', url.toString());
      } catch (err) {}
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  // Dynamic Security Posture Score Calculation
  const calculatePostureScore = () => {
    let score = 0;
    let armedCount = 0;

    if (whitelistIp || (status?.is_whitelisted ?? false) || ipWhitelistEntries.length > 0) {
      score += 5;
      armedCount += 1;
    }
    if (firewallToggles.virtual_patching && firewallToggles.block_malicious_uploads) {
      score += 15;
      armedCount += 4;
    } else {
      score += 5;
    }
    if (status?.preload_waf?.is_active || status?.preload_waf?.is_compiled) {
      score += 12;
      armedCount += 1;
    }
    if (cfToken.trim() || status?.cloudflare_status?.has_saved_token) {
      score += 15;
      armedCount += 4;
    }
    score += 8;
    armedCount += 3;
    if (archetype === 'ecommerce' || archetype === 'membership') {
      score += 7;
      armedCount += 5;
    } else {
      score += 7;
      armedCount += 2;
    }
    if (egressMode === 'enforce') {
      score += 8;
      armedCount += 1;
    } else if (egressMode === 'monitor') {
      score += 4;
      armedCount += 1;
    }
    if (identitySettings.two_factor_enabled || identitySettings.passkeys_enabled) {
      score += 10;
      armedCount += 3;
    } else {
      score += 5;
      armedCount += 1;
    }
    if (serverSettings.security_headers_enabled) {
      score += 7;
      armedCount += 3;
    }
    const activePasses = Object.values(customScanOptions).filter(Boolean).length;
    if (activePasses >= 10 && scanSchedule !== 'manual') {
      score += 8;
      armedCount += activePasses;
    } else {
      score += 4;
      armedCount += activePasses;
    }
    if (alertEmail || alerts.notify_critical) {
      score += 5;
      armedCount += 2;
    }

    return {
      score: Math.min(100, score),
      controlsArmed: armedCount,
    };
  };

  const { score: currentPostureScore, controlsArmed: currentControlsArmed } = calculatePostureScore();

  // Save Everything Handler
  const handleCompleteWizard = async (launchAudit: boolean = true) => {
    setSaving(true);
    try {
      await apiRequest({
        path: '/wizard/save',
        method: 'POST',
        data: {
          ...buildWizardPayload(step),
          is_intermediate_step: false,
        }
      });

      if (launchAudit) {
        window.location.href = 'admin.php?page=webcare-pro-scanner&autorun=1';
      } else {
        window.location.href = 'admin.php?page=webcare-pro-security';
      }
    } catch (e) {
      console.error('Failed to complete wizard', e);
      window.location.href = 'admin.php?page=webcare-pro-security';
    } finally {
      setSaving(false);
    }
  };

  // Blueprint Export / Import Handlers
  const currentBlueprintConfig = {
    archetype,
    caf_profile: cafProfile,
    firewall_settings: {
      ...firewallToggles,
      ...wafAdvanced,
    },
    egress_settings: {
      mode: egressMode,
      allowed_hosts: egressAllowedDomains,
    },
    identity_settings: identitySettings,
    server_settings: serverSettings,
    custom_scan_options: customScanOptions,
    scan_batch_size: scanBatchSize,
    scan_memory_safety_envelope: memoryEnvelope,
    scan_adaptive_throttling: adaptiveThrottling,
    scan_batch_delay_ms: batchDelayMs,
    governance_settings: governanceSettings,
    targeted_rules: targetedRules,
    alerts,
  };

  const handleImportBlueprint = (imported: any) => {
    if (!imported || typeof imported !== 'object') return;
    if (imported.archetype) setArchetype(imported.archetype);
    if (imported.caf_profile) setCafProfile(imported.caf_profile);
    if (imported.firewall_settings) {
      setWafAdvanced((prev: any) => ({ ...prev, ...imported.firewall_settings }));
    }
    if (imported.egress_settings?.mode) {
      setEgressMode(imported.egress_settings.mode);
    }
    if (Array.isArray(imported.egress_settings?.allowed_hosts)) {
      setEgressAllowedDomains(imported.egress_settings.allowed_hosts);
    }
    if (imported.identity_settings) {
      setIdentitySettings((prev: any) => ({ ...prev, ...imported.identity_settings }));
    }
    if (imported.server_settings) {
      setServerSettings((prev: any) => ({ ...prev, ...imported.server_settings }));
    }
    if (imported.custom_scan_options) {
      setCustomScanOptions((prev) => ({ ...prev, ...imported.custom_scan_options }));
    }
    if (imported.scan_batch_size) setScanBatchSize(imported.scan_batch_size);
    if (imported.scan_memory_safety_envelope) setMemoryEnvelope(imported.scan_memory_safety_envelope);
    if (imported.scan_adaptive_throttling !== undefined) setAdaptiveThrottling(imported.scan_adaptive_throttling);
    if (imported.scan_batch_delay_ms !== undefined) setBatchDelayMs(imported.scan_batch_delay_ms);
    if (imported.governance_settings) {
      setGovernanceSettings((prev: any) => ({ ...prev, ...imported.governance_settings }));
    }
    if (Array.isArray(imported.targeted_rules)) {
      setTargetedRules(imported.targeted_rules);
    }
    if (imported.alerts) {
      setAlerts((prev: any) => ({ ...prev, ...imported.alerts }));
    }
  };

  const handleArchetypeSelect = (newArch: string) => {
    setArchetype(newArch);
    if (newArch === 'ecommerce') {
      setCafProfile('ecommerce_hardened');
      setWafAdvanced((prev: any) => ({ ...prev, waf_ecommerce_safe_mode: true }));
    } else if (newArch === 'membership') {
      setCafProfile('membership_lms');
      setWafAdvanced((prev: any) => ({ ...prev, waf_ecommerce_safe_mode: true }));
    } else if (newArch === 'business' || newArch === 'blog') {
      const isShop = Boolean(
        status?.stack_snapshot?.detected_ecosystems?.includes('woocommerce') ||
        status?.stack_snapshot?.detected_ecosystems?.includes('commerce') ||
        status?.commerce_telemetry?.has_detected_plugins
      );
      if (!isShop) {
        setWafAdvanced((prev: any) => ({ ...prev, waf_ecommerce_safe_mode: false }));
      }
      if (cafProfile === 'ecommerce_hardened' || cafProfile === 'membership_lms') {
        const isLowMem = status?.server_info?.php?.memory_limit === '128M' || status?.server_info?.is_shared_hosting;
        setCafProfile(isLowMem ? 'cpanel_shared_saver' : 'balanced');
      }
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '16px' }}>
        <Loader2 size={36} className="webcare-spin" color="var(--webcare-primary, #4f46e5)" />
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)' }}>
          Preparing your protection quickstart environment...
        </div>
      </div>
    );
  }

  // Developer Mode Step Renderer
  const renderDeveloperStep = () => {
    switch (step) {
      case 1:
        return (
          <Step01StackArchetype
            archetype={archetype}
            setArchetype={handleArchetypeSelect}
            status={status}
            adaptiveStackMonitoring={adaptiveStackMonitoring}
            setAdaptiveStackMonitoring={setAdaptiveStackMonitoring}
            environmentOverride={environmentOverride}
            setEnvironmentOverride={setEnvironmentOverride}
          />
        );
      case 2:
        return (
          <Step02RuntimeTelemetry
            status={status}
            trustedProxyIps={trustedProxyIps}
            setTrustedProxyIps={setTrustedProxyIps}
            onRefreshStatus={fetchStatus}
          />
        );
      case 3:
        return (
          <Step03BehavioralModularWaf
            status={status}
            onRefreshStatus={fetchStatus}
            onContinueInBackground={() => setStep(4)}
          />
        );
      case 4:
        return (
          <Step03ZeroLockoutWhitelist
            status={status}
            whitelistIp={whitelistIp}
            setWhitelistIp={setWhitelistIp}
            ipWhitelistEntries={ipWhitelistEntries}
            setIpWhitelistEntries={setIpWhitelistEntries}
          />
        );
      case 5:
        return (
          <Step04CorePreloadWaf
            status={status}
            firewallToggles={firewallToggles}
            setFirewallToggles={setFirewallToggles}
            wafAdvanced={wafAdvanced}
            setWafAdvanced={setWafAdvanced}
          />
        );
      case 6:
        return (
          <Step05CafWooShield
            archetype={archetype}
            status={status}
            wafAdvanced={wafAdvanced}
            setWafAdvanced={setWafAdvanced}
            cafProfile={cafProfile}
            setCafProfile={setCafProfile}
          />
        );
      case 7:
        return (
          <Step06EgressSmtpShield
            status={status}
            egressMode={egressMode}
            setEgressMode={setEgressMode}
            egressAllowedDomains={egressAllowedDomains}
            setEgressAllowedDomains={setEgressAllowedDomains}
            egressBlockUnverifiedSsl={egressBlockUnverifiedSsl}
            setEgressBlockUnverifiedSsl={setEgressBlockUnverifiedSsl}
          />
        );
      case 8:
        return (
          <Step07BypassSeoBots
            status={status}
            targetedRules={targetedRules}
            setTargetedRules={setTargetedRules}
            wafAdvanced={wafAdvanced}
            setWafAdvanced={setWafAdvanced}
          />
        );
      case 9:
        return (
          <Step08CloudflareEdge
            status={status}
            cfToken={cfToken}
            setCfToken={setCfToken}
            cfZone={cfZone}
            setCfZone={setCfZone}
            wafAdvanced={wafAdvanced}
            setWafAdvanced={setWafAdvanced}
          />
        );
      case 10:
        return (
          <Step09Login2faPasskeys
            identitySettings={identitySettings}
            setIdentitySettings={setIdentitySettings}
          />
        );
      case 11:
        return (
          <Step10ServerArmorHeaders
            serverSettings={serverSettings}
            setServerSettings={setServerSettings}
          />
        );
      case 12:
        return (
          <Step12MalwareResourceEnvelope
            status={status}
            customScanOptions={customScanOptions}
            setCustomScanOptions={setCustomScanOptions}
            scannerSettings={scannerSettings}
            setScannerSettings={setScannerSettings}
            scanBatchSize={scanBatchSize}
            setScanBatchSize={setScanBatchSize}
            memoryEnvelope={memoryEnvelope}
            setMemoryEnvelope={setMemoryEnvelope}
            adaptiveThrottling={adaptiveThrottling}
            setAdaptiveThrottling={setAdaptiveThrottling}
            batchDelayMs={batchDelayMs}
            setBatchDelayMs={setBatchDelayMs}
            cafProfile={cafProfile}
            setCafProfile={setCafProfile}
          />
        );
      case 13:
        return (
          <Step13AiCopilotAlerts
            scanSchedule={scanSchedule}
            setScanSchedule={setScanSchedule}
            alertEmail={alertEmail}
            setAlertEmail={setAlertEmail}
            alerts={alerts}
            setAlerts={setAlerts}
            slackWebhookUrl={slackWebhookUrl}
            setSlackWebhookUrl={setSlackWebhookUrl}
            discordWebhookUrl={discordWebhookUrl}
            setDiscordWebhookUrl={setDiscordWebhookUrl}
            customWebhookUrl={customWebhookUrl}
            setCustomWebhookUrl={setCustomWebhookUrl}
            aiProvider={aiProvider}
            setAiProvider={setAiProvider}
            aiApiKey={aiApiKey}
            setAiApiKey={setAiApiKey}
            aiModel={aiModel}
            setAiModel={setAiModel}
          />
        );
      case 14:
        return (
          <Step14LedgerLaunch
            postureScore={currentPostureScore}
            controlsArmed={currentControlsArmed}
            archetype={archetype}
            isCfActive={!!(cfToken.trim() || status?.cloudflare_status?.has_saved_token)}
            isPreloadActive={!!(status?.preload_waf?.is_active || status?.preload_waf?.is_compiled)}
            onLaunchAudit={() => handleCompleteWizard(true)}
            onOpenDashboard={() => handleCompleteWizard(false)}
            onExportBlueprint={() => setIsBlueprintModalOpen(true)}
            saving={saving}
            governanceSettings={governanceSettings}
            setGovernanceSettings={setGovernanceSettings}
          />
        );
      default:
        return null;
    }
  };

  // 60-Second Calm Setup Step Renderer (3 Steps)
  const renderCalmStep = () => {
    switch (step) {
      case 1:
        // Step 1: Site Archetype Selection
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <div
              style={{
                padding: '16px 20px',
                borderRadius: '12px',
                background: 'rgba(79, 70, 229, 0.04)',
                border: '1px solid rgba(79, 70, 229, 0.15)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}
            >
              <Sparkles size={20} color="var(--webcare-primary, #4f46e5)" style={{ flexShrink: 0 }} />
              <div>
                <strong style={{ fontSize: '13px', color: 'var(--webcare-text-title, #0f172a)' }}>
                  60-Second Calm Setup (Step 1 of 3)
                </strong>
                <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Select your website type. WebCare Pro automatically applies the optimal conflict-free protection preset tailored to your plugins.
                </p>
              </div>
            </div>
            <Step01StackArchetype
              archetype={archetype}
              setArchetype={handleArchetypeSelect}
              status={status}
              adaptiveStackMonitoring={adaptiveStackMonitoring}
              setAdaptiveStackMonitoring={setAdaptiveStackMonitoring}
              environmentOverride={environmentOverride}
              setEnvironmentOverride={setEnvironmentOverride}
            />
          </div>
        );
      case 2:
        // Step 2: Alerts & Guided Learning Mode + Verified Admin IP Confirmation
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <div
              style={{
                padding: '16px 20px',
                borderRadius: '12px',
                background: 'rgba(16, 185, 129, 0.04)',
                border: '1px solid rgba(16, 185, 129, 0.2)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}
            >
              <CheckCircle2 size={20} color="#10b981" style={{ flexShrink: 0 }} />
              <div>
                <strong style={{ fontSize: '13px', color: 'var(--webcare-text-title, #0f172a)' }}>
                  60-Second Calm Setup (Step 2 of 3): Alerts &amp; Zero-Lockout Safety
                </strong>
                <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                  Confirm your alert email, safe Learning Mode, and explicitly verify your detected admin IP address so you can never be locked out.
                </p>
              </div>
            </div>

            {/* Zero-Lockout IP Allowlist (Requires Explicit Confirmation) */}
            <Step03ZeroLockoutWhitelist
              status={status}
              whitelistIp={whitelistIp}
              setWhitelistIp={setWhitelistIp}
              ipWhitelistEntries={ipWhitelistEntries}
              setIpWhitelistEntries={setIpWhitelistEntries}
            />

            {/* Alert Email & Learning Mode Card */}
            <div
              className="webcare-firewall-rule-card"
              style={{
                padding: '20px',
                borderRadius: '12px',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
              }}
            >
              <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Security Notifications &amp; Safe Learning Mode
              </h3>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-secondary, #475569)', marginBottom: '6px' }}>
                  Admin Notification Email
                </label>
                <input
                  type="email"
                  value={alertEmail}
                  onChange={(e) => setAlertEmail(e.target.value)}
                  placeholder="admin@example.com"
                  className="webcare-input"
                  style={{
                    width: '100%',
                    maxWidth: '400px',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    background: 'var(--webcare-bg-surface, #ffffff)',
                    color: 'var(--webcare-text-primary, #0f172a)',
                  }}
                />
                <span style={{ display: 'block', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                  Instant email alerts for critical vulnerabilities and brute-force surges.
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingTop: '8px', borderTop: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <input
                  type="checkbox"
                  id="calm_learning_mode"
                  checked={!!wafAdvanced.waf_learning_mode}
                  onChange={(e) => setWafAdvanced({ ...wafAdvanced, waf_learning_mode: e.target.checked })}
                  style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                />
                <label htmlFor="calm_learning_mode" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', cursor: 'pointer' }}>
                  Guided Learning Mode (Recommended for first 48 hours)
                </label>
              </div>
              <p style={{ margin: '0 0 0 26px', fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Monitors and profiles genuine visitor traffic to eliminate false alarms before enforcing strict blocks.
              </p>
            </div>
          </div>
        );
      case 3:
        // Step 3: Confirmation & Launch with links
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step14LedgerLaunch
              postureScore={currentPostureScore}
              controlsArmed={currentControlsArmed}
              archetype={archetype}
              isCfActive={!!(cfToken.trim() || status?.cloudflare_status?.has_saved_token)}
              isPreloadActive={!!(status?.preload_waf?.is_active || status?.preload_waf?.is_compiled)}
              onLaunchAudit={() => handleCompleteWizard(true)}
              onOpenDashboard={() => handleCompleteWizard(false)}
              onExportBlueprint={() => setIsBlueprintModalOpen(true)}
              saving={saving}
              governanceSettings={governanceSettings}
              setGovernanceSettings={setGovernanceSettings}
            />

            {/* Advanced Wizard Link */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '14px 20px',
                borderRadius: '10px',
                background: 'var(--webcare-bg-surface, #f8fafc)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
              }}
            >
              <button
                type="button"
                onClick={() => {
                  setWizardMode('developer');
                  setStep(1);
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--webcare-primary, #4f46e5)',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textDecoration: 'underline',
                }}
              >
                Want granular control? Open Advanced 14-Step Pro Hardening Wizard →
              </button>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  // Express Mode Step Renderer (6 Steps)
  const renderExpressStep = () => {
    switch (step) {
      case 1:
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step01StackArchetype
              archetype={archetype}
              setArchetype={handleArchetypeSelect}
              status={status}
              adaptiveStackMonitoring={adaptiveStackMonitoring}
              setAdaptiveStackMonitoring={setAdaptiveStackMonitoring}
              environmentOverride={environmentOverride}
              setEnvironmentOverride={setEnvironmentOverride}
            />
            <Step03ZeroLockoutWhitelist
              status={status}
              whitelistIp={whitelistIp}
              setWhitelistIp={setWhitelistIp}
              ipWhitelistEntries={ipWhitelistEntries}
              setIpWhitelistEntries={setIpWhitelistEntries}
            />
          </div>
        );
      case 2:
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step02RuntimeTelemetry
              status={status}
              trustedProxyIps={trustedProxyIps}
              setTrustedProxyIps={setTrustedProxyIps}
              onRefreshStatus={fetchStatus}
            />
            <Step04CorePreloadWaf
              status={status}
              firewallToggles={firewallToggles}
              setFirewallToggles={setFirewallToggles}
              wafAdvanced={wafAdvanced}
              setWafAdvanced={setWafAdvanced}
            />
          </div>
        );
      case 3:
        return (
          <Step03BehavioralModularWaf
            status={status}
            onRefreshStatus={fetchStatus}
            onContinueInBackground={() => setStep(4)}
          />
        );
      case 4:
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step05CafWooShield
              archetype={archetype}
              status={status}
              wafAdvanced={wafAdvanced}
              setWafAdvanced={setWafAdvanced}
              cafProfile={cafProfile}
              setCafProfile={setCafProfile}
            />
            <Step06EgressSmtpShield
              status={status}
              egressMode={egressMode}
              setEgressMode={setEgressMode}
              egressAllowedDomains={egressAllowedDomains}
              setEgressAllowedDomains={setEgressAllowedDomains}
              egressBlockUnverifiedSsl={egressBlockUnverifiedSsl}
              setEgressBlockUnverifiedSsl={setEgressBlockUnverifiedSsl}
            />
            <Step08CloudflareEdge
              status={status}
              cfToken={cfToken}
              setCfToken={setCfToken}
              cfZone={cfZone}
              setCfZone={setCfZone}
              wafAdvanced={wafAdvanced}
              setWafAdvanced={setWafAdvanced}
            />
          </div>
        );
      case 5:
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step09Login2faPasskeys
              identitySettings={identitySettings}
              setIdentitySettings={setIdentitySettings}
            />
            <Step10ServerArmorHeaders
              serverSettings={serverSettings}
              setServerSettings={setServerSettings}
            />
            <Step12MalwareResourceEnvelope
              status={status}
              customScanOptions={customScanOptions}
              setCustomScanOptions={setCustomScanOptions}
              scannerSettings={scannerSettings}
              setScannerSettings={setScannerSettings}
              scanBatchSize={scanBatchSize}
              setScanBatchSize={setScanBatchSize}
              memoryEnvelope={memoryEnvelope}
              setMemoryEnvelope={setMemoryEnvelope}
              adaptiveThrottling={adaptiveThrottling}
              setAdaptiveThrottling={setAdaptiveThrottling}
              batchDelayMs={batchDelayMs}
              setBatchDelayMs={setBatchDelayMs}
              cafProfile={cafProfile}
              setCafProfile={setCafProfile}
            />
          </div>
        );
      case 6:
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
            <Step13AiCopilotAlerts
              scanSchedule={scanSchedule}
              setScanSchedule={setScanSchedule}
              alertEmail={alertEmail}
              setAlertEmail={setAlertEmail}
              alerts={alerts}
              setAlerts={setAlerts}
              slackWebhookUrl={slackWebhookUrl}
              setSlackWebhookUrl={setSlackWebhookUrl}
              discordWebhookUrl={discordWebhookUrl}
              setDiscordWebhookUrl={setDiscordWebhookUrl}
              customWebhookUrl={customWebhookUrl}
              setCustomWebhookUrl={setCustomWebhookUrl}
              aiProvider={aiProvider}
              setAiProvider={setAiProvider}
              aiApiKey={aiApiKey}
              setAiApiKey={setAiApiKey}
              aiModel={aiModel}
              setAiModel={setAiModel}
            />
            <Step14LedgerLaunch
              postureScore={currentPostureScore}
              controlsArmed={currentControlsArmed}
              archetype={archetype}
              isCfActive={!!(cfToken.trim() || status?.cloudflare_status?.has_saved_token)}
              isPreloadActive={!!(status?.preload_waf?.is_active || status?.preload_waf?.is_compiled)}
              onLaunchAudit={() => handleCompleteWizard(true)}
              onOpenDashboard={() => handleCompleteWizard(false)}
              onExportBlueprint={() => setIsBlueprintModalOpen(true)}
              saving={saving}
              governanceSettings={governanceSettings}
              setGovernanceSettings={setGovernanceSettings}
            />
          </div>
        );
      default:
        return null;
    }
  };

  const isFinalStep = step === totalSteps;

  return (
    <div className={`webcare-scanner-app ${themeMode === 'dark' ? 'webcare-theme-dark' : 'webcare-theme-light'}`} style={{ minHeight: '100vh', padding: '24px 28px 50px' }}>
      <div className="webcare-wizard-wrapper" style={{ width: '100%', maxWidth: '100%', margin: '0', boxSizing: 'border-box' }}>
        
        {/* TOP COMMAND BAR */}
        <WizardTopBar
          mode={wizardMode}
          onToggleMode={(newMode) => {
            setWizardMode(newMode);
            try { localStorage.setItem('webcare_wizard_mode', newMode); } catch {}
            const maxForNew = newMode === 'express' ? 6 : 14;
            const updatedStep = step > maxForNew ? maxForNew : step;
            if (step > maxForNew) setStep(maxForNew);
            try {
              const url = new URL(window.location.href);
              url.searchParams.set('mode', newMode);
              url.searchParams.set('step', String(updatedStep));
              window.history.replaceState(null, '', url.toString());
            } catch (err) {}
          }}
          themeMode={themeMode}
          onToggleTheme={toggleThemeMode}
          onOpenBlueprint={() => setIsBlueprintModalOpen(true)}
        />

        {/* TWO-COLUMN STUDIO GRID */}
        <div
          className="webcare-wizard-grid"
          style={{
            display: 'grid',
            gridTemplateColumns: '280px minmax(0, 1fr)',
            width: '100%',
            boxSizing: 'border-box',
            background: 'var(--webcare-bg-panel, #ffffff)',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            borderTop: 'none',
            borderRadius: '0 0 18px 18px',
            overflow: 'hidden',
            minHeight: '780px',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.05)',
          }}
        >
          {/* LEFT TELEMETRY & FREE-JUMP NAVIGATION RAIL */}
          <WizardNavigationRail
            currentStep={step}
            mode={wizardMode}
            onSelectStep={(targetStep) => {
              setConfiguredSteps((prev) => new Set([...prev, step]));
              // Quietly persist settings with target step so refresh stays on targetStep
              apiRequest({
                path: '/wizard/save',
                method: 'POST',
                data: {
                  ...buildWizardPayload(targetStep),
                  is_intermediate_step: true,
                },
              }).catch(() => {});

              setStep(targetStep);
              try {
                const url = new URL(window.location.href);
                url.searchParams.set('step', String(targetStep));
                window.history.replaceState(null, '', url.toString());
              } catch (err) {}
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            configuredSteps={configuredSteps}
            postureScore={currentPostureScore}
            controlsArmed={currentControlsArmed}
            detectedEcosystems={status?.stack_snapshot?.detected_ecosystems || []}
          />

          {/* MAIN INTERACTIVE CONFIGURATION STAGE */}
          <main
            className="webcare-wizard-stage-main"
            style={{
              padding: '32px 36px',
              overflowY: 'auto',
              minWidth: 0,
              width: '100%',
              boxSizing: 'border-box',
              background: 'var(--webcare-bg-panel, #ffffff)',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <div key={`step-stage-${wizardMode}-${step}`} style={{ flex: 1, width: '100%', minWidth: 0 }}>
              {/* 30-Second Express Fast-Track Card (Shown on Step 1) */}
              {step === 1 && (
                <div
                  style={{
                    marginBottom: '24px',
                    padding: '20px 24px',
                    background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.06) 0%, rgba(16, 185, 129, 0.06) 100%)',
                    border: '1px solid rgba(79, 70, 229, 0.2)',
                    borderRadius: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div
                        style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '8px',
                          background: 'linear-gradient(135deg, #4f46e5 0%, #10b981 100%)',
                          color: '#ffffff',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0,
                        }}
                      >
                        <Sparkles size={18} />
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                            Choose Your Setup Journey
                          </h3>
                          <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px', padding: '1px 6px' }}>
                            Smart Fast-Track
                          </span>
                        </div>
                        <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--webcare-text-secondary, #64748b)' }}>
                          Select how you want to configure your security foundation today.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
                    {/* Path A: Express Fast-Track */}
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => {
                        setWizardMode('express');
                        try { localStorage.setItem('webcare_wizard_mode', 'express'); } catch {}
                        setStep(6);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          setWizardMode('express');
                          try { localStorage.setItem('webcare_wizard_mode', 'express'); } catch {}
                          setStep(6);
                        }
                      }}
                      style={{
                        padding: '16px',
                        borderRadius: '10px',
                        background: 'var(--webcare-bg-surface, #ffffff)',
                        border: '2px solid var(--webcare-primary, #4f46e5)',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: '10px',
                        transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <strong style={{ fontSize: '14px', color: 'var(--webcare-text-title, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span>⚡ Express Setup</span>
                            <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px', padding: '1px 5px' }}>~30 sec</span>
                          </strong>
                          <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 700 }}>Recommended</span>
                        </div>
                        <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)', lineHeight: 1.4 }}>
                          Auto-detects your server stack &amp; WooCommerce, activates calm non-breaking shields, and jumps directly to Launch Summary.
                        </p>
                      </div>
                      <button
                        type="button"
                        className="webcare-btn webcare-btn-primary"
                        style={{
                          fontSize: '12px',
                          padding: '6px 14px',
                          borderRadius: '6px',
                          width: '100%',
                          justifyContent: 'center',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}
                      >
                        <span>Jump to Express Review &amp; Activate</span>
                        <ArrowRight size={13} />
                      </button>
                    </div>

                    {/* Path B: Custom Step-by-Step */}
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => {
                        setWizardMode('developer');
                        try { localStorage.setItem('webcare_wizard_mode', 'developer'); } catch {}
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          setWizardMode('developer');
                          try { localStorage.setItem('webcare_wizard_mode', 'developer'); } catch {}
                        }
                      }}
                      style={{
                        padding: '16px',
                        borderRadius: '10px',
                        background: 'var(--webcare-bg-surface, #ffffff)',
                        border: '1px solid var(--webcare-border, #e2e8f0)',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: '10px',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <strong style={{ fontSize: '14px', color: 'var(--webcare-text-title, #0f172a)' }}>
                            🛠️ Custom Step-by-Step
                          </strong>
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #94a3b8)' }}>Power User</span>
                        </div>
                        <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)', lineHeight: 1.4 }}>
                          Fine-tune all 14 layers manually: granular Cloudflare edge sync, 2FA enforcement, egress policies, and AST rule engine.
                        </p>
                      </div>
                      <span
                        style={{
                          fontSize: '12px',
                          color: 'var(--webcare-primary, #4f46e5)',
                          fontWeight: 600,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        Continue with Granular Controls →
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {wizardMode === 'calm' ? renderCalmStep() : (wizardMode === 'express' ? renderExpressStep() : renderDeveloperStep())}
            </div>

            {/* STUDIO STAGE FOOTER CONTROLS */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                paddingTop: '24px',
                marginTop: '36px',
                borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                flexWrap: 'wrap',
                gap: '12px'
              }}
            >
              <button
                type="button"
                onClick={handleBack}
                disabled={step <= 1}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '10px 18px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: step <= 1 ? 'not-allowed' : 'pointer',
                  background: 'none',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  color: step <= 1 ? 'var(--webcare-text-muted, #94a3b8)' : 'var(--webcare-text-title, #0f172a)',
                  opacity: step <= 1 ? 0.5 : 1
                }}
              >
                <ArrowLeft size={16} /> Previous Step
              </button>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setIsBlueprintModalOpen(true)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '10px 16px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: 'none',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    color: 'var(--webcare-text-secondary, #475569)',
                  }}
                >
                  <Download size={14} /> Blueprint
                </button>

                {!isFinalStep ? (
                  <button
                    key="btn-stage-next-step"
                    type="button"
                    onClick={handleSaveAndNext}
                    disabled={savingStep}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '10px 22px',
                      borderRadius: '8px',
                      fontSize: '13px',
                      fontWeight: 700,
                      cursor: savingStep ? 'not-allowed' : 'pointer',
                      background: 'var(--webcare-primary, #4f46e5)',
                      color: '#ffffff',
                      border: 'none',
                      boxShadow: '0 4px 14px rgba(79, 70, 229, 0.25)',
                      opacity: savingStep ? 0.75 : 1,
                    }}
                  >
                    {savingStep ? (
                      <>
                        <Loader2 size={16} className="webcare-spin" /> Saving...
                      </>
                    ) : (
                      <>
                        Save and Next Step <ArrowRight size={16} />
                      </>
                    )}
                  </button>
                ) : (
                  <button
                    key="btn-stage-complete-audit"
                    type="button"
                    onClick={() => handleCompleteWizard(true)}
                    disabled={saving}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '10px 24px',
                      borderRadius: '8px',
                      fontSize: '13px',
                      fontWeight: 800,
                      cursor: 'pointer',
                      background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                      color: '#ffffff',
                      border: 'none',
                      boxShadow: '0 4px 16px rgba(16, 185, 129, 0.3)',
                      opacity: saving ? 0.7 : 1
                    }}
                  >
                    {saving ? <Loader2 size={16} className="webcare-spin" /> : <Sparkles size={16} />}
                    Launch Security Audit 🚀
                  </button>
                )}
              </div>
            </div>
          </main>
        </div>
      </div>

      {/* 1-Click Agency Blueprint Modal */}
      <BlueprintModal
        isOpen={isBlueprintModalOpen}
        onClose={() => setIsBlueprintModalOpen(false)}
        currentConfig={currentBlueprintConfig}
        onImportConfig={handleImportBlueprint}
      />
    </div>
  );
};
