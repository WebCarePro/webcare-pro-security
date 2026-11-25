import React, { useState, useEffect, useMemo, useRef } from 'react';
import { generateStandardLogFilename } from './exportUtils';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Search,
  Filter,
  Trash2,
  RefreshCw,
  Download,
  Calendar,
  Clock,
  Globe,
  Radio,
  FileText,
  FileCode,
  Terminal,
  Copy,
  Check,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Maximize2,
  Minimize2,
  Lock,
  Unlock,
  Sliders,
  Target,
  Sparkles,
  BarChart3,
  TrendingUp,
  Cpu,
  Layers,
  Info,
  Zap,
  Server,
  UserX,
  FileSpreadsheet,
  Printer,
  Columns,
  Eye,
  X,
  Cloud,
  Loader2,
  Plus,
  HelpCircle,
  Lightbulb,
  AlertCircle,
  UserCheck,
  ShoppingBag,
  Bot
} from 'lucide-react';
import { useWorkspaceMode } from './hooks/useWorkspaceMode';
import { ConfirmDialog } from './components/ConfirmDialog';
import { BansAndAllowlistsPanel } from './components/BansAndAllowlistsPanel';
import { EmptyStateCard } from './components/ui/EmptyStateCard';
import { formatRelativeTime, formatTelemetryDateFull } from './timeUtils';
import { toast } from './utils/dialog';

export interface CloudflareEdgeEvent {
  ray_id: string;
  datetime: string;
  action: string;
  rule_id?: string;
  ruleset_id?: string;
  rule_name: string;
  description?: string;
  source: string;
  client_ip: string;
  host?: string;
  method: string;
  protocol?: string;
  path: string;
  query?: string;
  user_agent?: string;
  referer?: string;
  country?: string;
  asn?: string | number;
  asn_desc?: string;
}

export interface WafIncident {
  id: string | number;
  incident_id?: string;
  ref_code?: string | null;
  timestamp?: number;
  ip_address: string;
  request_uri: string;
  request_method: string;
  http_status_code?: number;
  http_referer?: string;
  rule_id?: string;
  rule_name?: string;
  rule_category: string;
  rule_description: string;
  payload_sample?: string;
  user_agent?: string;
  action_taken: 'blocked' | 'detected' | 'allowed';
  matched_param?: string | null;
  matched_param_key?: string | null;
  matched_value?: string | null;
  created_at: string;
  created_at_gmt?: string;
  user_id?: number;
  username?: string;
  user_role?: string;
  is_authenticated?: boolean;
  hostname?: string;
  ban_reason?: string | null;
  ban_source?: string | null;
  matching_entry?: string | null;
  is_banned?: boolean;
  cf_synced?: boolean;
  ban_scope?: 'edge_synced' | 'local' | 'none';
  cf_sync_enabled?: boolean;
  cf_connected?: boolean;
  ban_meta?: {
    reason?: string;
    banned_at?: string;
    expires_at?: string;
    rule_id?: string;
  };
  is_last_hit_for_ip?: boolean;
  ip_total_hits?: number;
  ip_first_seen?: number;
  ip_last_seen?: number;
  ip_distinct_vectors?: string[];
  ip_distinct_targets?: string[];
}

/**
 * Intelligent Forensic Engine: Extracts structured deep-dive insights
 * so WordPress developers and administrators understand exact root cause,
 * attack classification, defense layer, and precise remediation actions.
 */
function analyzeIncidentForensics(log: WafIncident) {
  const cat = (log.rule_category || '').toLowerCase();
  const desc = (log.rule_description || '').toLowerCase();
  const ruleId = (log.rule_id || '').toUpperCase();
  const uri = log.request_uri || '';
  const payload = log.payload_sample || '';
  const ua = log.user_agent || '';

  let engine = 'Core WAF Engine';
  let severity: 'Critical' | 'High' | 'Medium' | 'Informational' = 'High';
  let badgeClass = 'webcare-badge-high';
  let plainEnglish = 'An inbound request matched a behavioral firewall pattern or suspicious signature and was safely intercepted.';
  let attackType = 'Web Application Attack';
  let techDetails: Array<{ label: string; value: string }> = [];
  let recommendation = 'Review the client IP and targeted URI. If this is an automated scanner, no action is needed as the WAF successfully neutralized the threat.';
  let suggestedAction: 'block_ip' | 'allow_ip' | 'delete_component' | 'none' = 'none';
  let suggestedActionText = '';

  // 1. Context-Adaptive Firewall (CAF) - Dormant Attack Surface
  if (cat.includes('dormant') || desc.includes('inactive theme') || desc.includes('inactive plugin') || ruleId.includes('DORMANT')) {
    engine = 'Context-Adaptive Firewall (CAF)';
    severity = 'Medium';
    badgeClass = 'webcare-badge-info';
    attackType = 'Dormant Attack Surface Reconnaissance';

    const isTheme = desc.includes('theme') || uri.includes('/themes/') || payload.includes('twentytwenty');
    const compType = isTheme ? 'theme' : 'plugin';
    
    // Extract component slug if possible
    let compSlug = '';
    const match = uri.match(/\/(?:themes|plugins)\/([a-zA-Z0-9_-]+)/i) || payload.match(/(?:theme|plugin)["']?\s*[:=]?\s*["']?([a-zA-Z0-9_-]+)/i);
    if (match && match[1]) compSlug = match[1];

    plainEnglish = `A client probed for ${compSlug ? `the "${compSlug}" ${compType}` : `an inactive ${compType}`}, which is installed on your server but currently deactivated. CAF strictly blocks direct external requests to dormant extensions to prevent attackers from exploiting unpatched vulnerabilities in unused code.`;
    techDetails = [
      { label: 'Defensive Layer', value: 'Context-Adaptive Firewall (CAF Layer 1)' },
      { label: 'Surface Status', value: `Deactivated / Dormant ${compType.toUpperCase()}` },
      { label: 'Inspection Logic', value: 'Dynamic stack snapshot comparison against active runtime components' },
    ];
    if (compSlug) {
      techDetails.push({ label: 'Identified Component', value: `${compSlug} (wp-content/${compType}s/${compSlug}/)` });
    }
    recommendation = compSlug
      ? `If you do not plan to use "${compSlug}", permanently delete it from WordPress Admin > ${isTheme ? 'Appearance > Themes' : 'Plugins'} to eliminate the attack surface entirely.`
      : `Delete unused plugins and themes from your server to reduce your site's exploitable footprint.`;
    suggestedAction = 'delete_component';
    suggestedActionText = compSlug ? `Delete Inactive ${isTheme ? 'Theme' : 'Plugin'} (${compSlug})` : 'Inspect Inactive Extensions';
  }
  // 2. SQL Injection
  else if (cat.includes('sql') || ruleId.includes('SQLI') || desc.includes('sql injection')) {
    engine = 'Execution Armor / SQL Shield';
    severity = 'Critical';
    badgeClass = 'webcare-badge-danger';
    attackType = 'SQL Injection (SQLi) Attempt';
    plainEnglish = 'The visitor attempted to inject raw SQL syntax (e.g. UNION, SELECT, SLEEP, benchmark, or boolean operators) into input parameters to manipulate the WordPress database.';
    techDetails = [
      { label: 'Vulnerability Class', value: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command' },
      { label: 'Impact Risk', value: 'Database exfiltration, credential leakage, administrative auth bypass' },
      { label: 'Defense Mechanism', value: 'Multi-vector AST SQL tokenize & keyword barrier' },
    ];
    recommendation = 'The SQL injection payload was blocked before database execution. If this IP persists across multiple endpoints, permanently ban the IP address.';
    suggestedAction = 'block_ip';
    suggestedActionText = 'Permanently Ban Hostile IP';
  }
  // 3. Cross-Site Scripting (XSS)
  else if (cat.includes('xss') || ruleId.includes('XSS') || desc.includes('scripting')) {
    engine = 'XSS Armor / Sanitization Filter';
    severity = 'High';
    badgeClass = 'webcare-badge-high';
    attackType = 'Cross-Site Scripting (Reflected / Stored XSS)';
    plainEnglish = 'The request payload contains hostile HTML tags, script elements (<script>), or inline JavaScript event handlers (onerror, onload) intended to execute malicious code in visitor browsers.';
    techDetails = [
      { label: 'Vulnerability Class', value: 'CWE-79: Cross-Site Scripting (XSS)' },
      { label: 'Target Layer', value: 'Client DOM & Session Storage' },
      { label: 'Defense Filter', value: 'HTML context-aware payload parser & attribute scanner' },
    ];
    recommendation = 'Neutralized safely. No user session was compromised. Verify any custom themes or plugins properly sanitize input with esc_html() or esc_attr().';
  }
  // 4. Path Traversal & LFI/RFI
  else if (cat.includes('traversal') || ruleId.includes('TRAVERSAL') || desc.includes('traversal') || desc.includes('stream')) {
    engine = 'Filesystem Armor / LFI Shield';
    severity = 'Critical';
    badgeClass = 'webcare-badge-danger';
    attackType = 'Directory Traversal & Local File Inclusion (LFI)';
    plainEnglish = 'The attacker attempted to navigate outside the web root or read server configuration files (such as wp-config.php or /etc/passwd) using directory climbing sequences (../) or PHP stream wrappers (php://filter).';
    techDetails = [
      { label: 'Vulnerability Class', value: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory' },
      { label: 'Target Artifacts', value: 'System /etc files, wp-config.php DB credentials, source files' },
      { label: 'Defense Mechanism', value: 'Canonical path resolution & stream wrapper denial' },
    ];
    recommendation = 'Immediate block enforced. wp-config.php and root system files remain completely protected. Hostile reconnaissance tool detected.';
    suggestedAction = 'block_ip';
    suggestedActionText = 'Permanently Ban Attacker IP';
  }
  // 5. Bot & Automated Reconnaissance / Scrapers
  else if (cat.includes('bot') || ruleId.includes('BOT') || desc.includes('bot') || desc.includes('scraper')) {
    engine = 'Bot & Threat Intel Sentinel';
    severity = 'Medium';
    badgeClass = 'webcare-badge-muted';
    attackType = 'Automated Bot / AI Scraper / Crawler Spoof';
    plainEnglish = ua.includes('ClaudeBot') || ua.includes('GPTBot') || ua.includes('Bytespider') || desc.includes('ai')
      ? 'An automated AI crawler or content scraper attempted to scrape your website pages to harvest intellectual property or train language models.'
      : 'An automated scanner or fake search crawler attempted to index or probe your site while spoofing official search engine User-Agents.';
    techDetails = [
      { label: 'Classification', value: 'Automated Crawler / Reconnaissance Bot' },
      { label: 'User-Agent Fingerprint', value: ua || 'Missing or spoofed HTTP header' },
      { label: 'Enforcement Action', value: 'Early HTTP 403 / Dynamic robots.txt restriction' },
    ];
    recommendation = 'Scrapers consume server bandwidth and unmetered PHP worker processes. The firewall safely prevented backend resource exhaustion.';
  }
  // 6. Identity & Honeypot Defense
  else if (cat.includes('identity') || cat.includes('customipblocklist') || ruleId.includes('USERNAME-TRAP') || desc.includes('honeypot') || desc.includes('admin')) {
    engine = 'Identity Defense & Honeypot Trap';
    severity = 'Critical';
    badgeClass = 'webcare-badge-danger';
    attackType = 'Brute-Force & Honeypot Credential Attack';
    plainEnglish = 'An attacker attempted to authenticate using a known honeypot username (such as "admin", "administrator", or "root"). The firewall trapped the credential spray and permanently blacklisted the offending IP address.';
    techDetails = [
      { label: 'Defense Type', value: 'Zero-Trust Honeypot Trap' },
      { label: 'Username Targeted', value: log.username || 'admin (High-Risk Default)' },
      { label: 'Escalation', value: 'Automatic Permanent IP Ban + Fail2ban Sync' },
    ];
    recommendation = 'Client IP has already been permanently banned by WebCare Pro Security & Firewall. No further action needed.';
  }
  // 7. Sensitive File Probes & Backups
  else if (cat.includes('reconnaissance') || cat.includes('sensitive') || ruleId.includes('SENSITIVE') || uri.includes('.env') || uri.includes('.git')) {
    engine = 'Perimeter Hardening Shield';
    severity = 'High';
    badgeClass = 'webcare-badge-high';
    attackType = 'Sensitive Environment & Source Reconnaissance';
    plainEnglish = 'An automated scanner requested sensitive server environment files (.env, .git/config, backup.sql, or config.json) looking for exposed API credentials or source code.';
    techDetails = [
      { label: 'Target Probe', value: uri },
      { label: 'Risk Factor', value: 'Environment variable exfiltration, API secret exposure' },
      { label: 'Policy Enforced', value: 'Zero-tolerance file probe suppression' },
    ];
    recommendation = 'Access was denied instantly. Ensure hidden dotfiles (.env, .git) are also blocked in your Nginx/Apache server configuration.';
  }
  // 8. Virtual Patch (CVE Shield)
  else if (cat.includes('patch') || cat.includes('cve') || ruleId.includes('VPATCH')) {
    engine = 'Virtual Patch (CVE Shield)';
    severity = 'Critical';
    badgeClass = 'webcare-badge-info';
    attackType = 'Known CVE Zero-Day Exploit Attempt';
    plainEnglish = `A zero-day exploit payload matching a known WordPress plugin/theme CVE vulnerability was detected and neutralized via in-memory bytecode inspection before vulnerable component code was reached.`;
    techDetails = [
      { label: 'Exploit Identifier', value: log.rule_name || log.rule_id || 'Virtual Patch Signature' },
      { label: 'Mitigation Status', value: 'Active Virtual Shield (0-Day In-Memory Neutralization)' },
    ];
    recommendation = 'Check the Plugin & Theme Safety tab to update any outdated plugins to their official patched versions.';
  }

  return {
    engine,
    severity,
    badgeClass,
    plainEnglish,
    attackType,
    techDetails,
    recommendation,
    suggestedAction,
    suggestedActionText,
  };
}

export interface WafLogFile {
  filename: string;
  date: string;
  size_bytes: number;
  size_human: string;
  modified_at: string;
}

export interface WafLogStats {
  total_intercepted: number;
  blocked_24h: number;
  detected_learning: number;
  unique_attack_ips: number;
  top_categories: Array<{ rule_category: string; count: number }>;
  top_ips: Array<{ ip_address: string; count: number; last_seen: string; primary_reason: string }>;
  top_targets: Array<{ request_uri: string; count: number }>;
  methods_breakdown: Array<{ request_method: string; count: number }>;
  hourly_trend: Array<{ hour_slot: string; count: number }>;
}

interface WafLogsPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToFirewallRules?: () => void;
  onNavigateToDashboard?: () => void;
  onNavigateToFirewall?: (subTab?: string) => void;
}

export const WafLogsPage: React.FC<WafLogsPageProps> = ({
  apiRequest,
  onNavigateToFirewallRules,
  onNavigateToDashboard,
  onNavigateToFirewall,
}) => {
  const { isSimpleMode } = useWorkspaceMode();

  // Data state
  const [logs, setLogs] = useState<WafIncident[]>([]);
  const [stats, setStats] = useState<WafLogStats | null>(null);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [currentClientIp, setCurrentClientIp] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Firewall Navigation Dropdown & Cloudflare Status State
  const [isMoreMenuOpen, setIsMoreMenuOpen] = useState<boolean>(false);
  const moreMenuRef = useRef<HTMLDivElement | null>(null);
  const [cfStatus, setCfStatus] = useState<any>(null);

  useEffect(() => {
    const handleMoreClickOutside = (e: MouseEvent) => {
      if (moreMenuRef.current && !moreMenuRef.current.contains(e.target as Node)) {
        setIsMoreMenuOpen(false);
      }
    };
    if (isMoreMenuOpen) {
      document.addEventListener('mousedown', handleMoreClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleMoreClickOutside);
  }, [isMoreMenuOpen]);

  useEffect(() => {
    let isMounted = true;
    apiRequest({ path: '/cloudflare/status', method: 'GET' })
      .then((res: any) => {
        if (isMounted && res && res.status) {
          setCfStatus(res.status);
        }
      })
      .catch(() => {});
    return () => {
      isMounted = false;
    };
  }, []);

  const handleFirewallNavigation = (tab: string) => {
    setIsMoreMenuOpen(false);
    if (onNavigateToFirewall) {
      onNavigateToFirewall(tab);
    } else {
      window.location.href = `admin.php?page=webcare-pro-firewall&tab=${tab}`;
    }
  };

  // Pagination, Range & Filtering State
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(100);
  const [timeRange, setTimeRange] = useState<'today' | 'daily' | '7days' | '30days' | '6months' | 'all'>('today');
  const [selectedDayFile, setSelectedDayFile] = useState<string>('');
  const [availableFiles, setAvailableFiles] = useState<WafLogFile[]>([]);
  const [retentionDays, setRetentionDays] = useState<number>(30);
  const [updatingRetention, setUpdatingRetention] = useState<boolean>(false);
  const [pruningLogs, setPruningLogs] = useState<boolean>(false);

  // Sorting State
  const [sortBy, setSortBy] = useState<string>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [debouncedSearch, setDebouncedSearch] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedAction, setSelectedAction] = useState<string>('all');
  const [selectedMethod, setSelectedMethod] = useState<string>('all');
  const [selectedStatusCode, setSelectedStatusCode] = useState<string>('all');
  const [filterIp, setFilterIp] = useState<string>('');

  // Confirmation Dialog State
  const [wafConfirmDialog, setWafConfirmDialog] = useState<{
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

  const requestWafConfirm = ({
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
    setWafConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setWafConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setWafConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setWafConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  // Column Customization with LocalStorage Persistence
  const DEFAULT_VISIBLE_COLUMNS = {
    timestamp: true,
    status_code: true,
    ip: true,
    user: true,
    category: true,
    uri: true,
    method: false,
    referer: false,
    user_agent: false,
    action: true,
    controls: true,
  };

  const [visibleColumns, setVisibleColumns] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem('webcare_waf_logs_columns');
      if (saved) {
        return { ...DEFAULT_VISIBLE_COLUMNS, ...JSON.parse(saved) };
      }
    } catch (e) {
      // fallback
    }
    return DEFAULT_VISIBLE_COLUMNS;
  });

  const [columnMenuOpen, setColumnMenuOpen] = useState<boolean>(false);
  const columnMenuRef = useRef<HTMLDivElement | null>(null);

  const toggleColumn = (key: string) => {
    setVisibleColumns(prev => {
      const updated = { ...prev, [key]: !prev[key] };
      try {
        localStorage.setItem('webcare_waf_logs_columns', JSON.stringify(updated));
      } catch (e) {
        // storage disabled
      }
      return updated;
    });
  };

  // UI Interactive State
  const [expandedLogId, setExpandedLogId] = useState<string | number | null>(null);
  const [inspectedLog, setInspectedLog] = useState<WafIncident | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isLiveAutoRefresh, setIsLiveAutoRefresh] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(10); // 10s default
  const [exportMenuOpen, setExportMenuOpen] = useState<boolean>(false);
  const [selectedLogIds, setSelectedLogIds] = useState<(string | number)[]>([]);

  // Export Modal State
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [exportScope, setExportScope] = useState<'all' | 'date' | 'filtered'>('all');
  const [exportDate, setExportDate] = useState<string>(() => new Date().toISOString().slice(0, 10));
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json');
  const [includeSystemInfo, setIncludeSystemInfo] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('webcare_export_include_system_info');
      return saved !== null ? saved === 'true' : true; // Default to true
    } catch (e) {
      return true;
    }
  });
  const [isExporting, setIsExporting] = useState<boolean>(false);

  // Sub-Tab Navigation: 'local' (Server WAF Incidents) vs 'cloudflare' (Cloudflare Edge Block Events) vs 'rules' (Bans & Allowlists)
  const getInitialLogTab = (): 'local' | 'cloudflare' | 'rules' => {
    try {
      const params = new URLSearchParams(window.location.search);
      const tab = params.get('tab') || params.get('subtab') || params.get('section');
      if (tab === 'cloudflare-waf-logs' || tab === 'cloudflare' || tab === 'edge') {
        return 'cloudflare';
      }
      if (tab === 'bans-allow-lists' || tab === 'bans-allowlists' || tab === 'bans' || tab === 'rules' || tab === 'allowlist' || tab === 'allowlists') {
        return 'rules';
      }
    } catch (e) {}
    return 'local';
  };

  const [activeLogTab, setActiveLogTab] = useState<'local' | 'cloudflare' | 'rules'>(getInitialLogTab);

  const switchLogTab = (tab: 'local' | 'cloudflare' | 'rules') => {
    setActiveLogTab(tab);
    try {
      const url = new URL(window.location.href);
      if (tab === 'cloudflare') {
        url.searchParams.set('tab', 'cloudflare-waf-logs');
      } else if (tab === 'rules') {
        url.searchParams.set('tab', 'bans-allow-lists');
      } else {
        url.searchParams.delete('tab');
      }
      url.searchParams.delete('subtab');
      url.searchParams.delete('section');
      window.history.pushState({ tab }, '', url.toString());
    } catch (e) {}
  };

  useEffect(() => {
    const handlePopState = () => {
      setActiveLogTab(getInitialLogTab());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Modals
  const [ipInspectModal, setIpInspectModal] = useState<{ isOpen: boolean; ip: string | null }>({
    isOpen: false,
    ip: null,
  });

  // Granular Rule-Scoped Allowlist Modal State
  const [allowlistModal, setAllowlistModal] = useState<{
    isOpen: boolean;
    ip: string;
    ruleId: string;
    ruleCategory: string;
    ruleName: string;
    endpoint: string;
    scope: 'rule' | 'category' | 'global';
    endpointScoped: boolean;
    expiresIn: number;
    reason: string;
    isSubmitting: boolean;
  }>({
    isOpen: false,
    ip: '',
    ruleId: '',
    ruleCategory: '',
    ruleName: '',
    endpoint: '',
    scope: 'rule',
    endpointScoped: false,
    expiresIn: 86400,
    reason: '',
    isSubmitting: false,
  });

  // Cloudflare Edge Events Sub-Tab & Vault Cache State
  const [cfEvents, setCfEvents] = useState<CloudflareEdgeEvent[]>([]);
  const [cfLastSynced, setCfLastSynced] = useState<string | null>(null);
  const [cfZoneName, setCfZoneName] = useState<string>('');
  const [cfZoneId, setCfZoneId] = useState<string>('');
  const [cfLoading, setCfLoading] = useState<boolean>(false);
  const [cfFetchingNew, setCfFetchingNew] = useState<boolean>(false);
  const [cfClearingLogs, setCfClearingLogs] = useState<boolean>(false);
  const [cfError, setCfError] = useState<string | null>(null);
  const [cfMissingPerm, setCfMissingPerm] = useState<boolean>(false);
  const [cfSearch, setCfSearch] = useState<string>('');
  const [cfActionFilter, setCfActionFilter] = useState<string>('all');
  const [cfExpandedRay, setCfExpandedRay] = useState<string | null>(null);
  const [cfWhitelistingIp, setCfWhitelistingIp] = useState<string | null>(null);
  const [cfWhitelistSuccess, setCfWhitelistSuccess] = useState<string | null>(null);

  const loadStoredCfEvents = async () => {
    try {
      setCfLoading(true);
      setCfError(null);
      const res = await apiRequest({ path: '/cloudflare/firewall-events', method: 'GET' });
      if (res && res.success) {
        setCfEvents(res.events || []);
        setCfLastSynced(res.last_synced || null);
        setCfZoneName(res.zone_name || '');
        setCfZoneId(res.zone_id || '');
      } else {
        setCfError(res?.message || 'Failed to load stored Cloudflare events.');
      }
    } catch (err: any) {
      setCfError(err?.message || 'Network error reading stored events from WebCare Vault.');
    } finally {
      setCfLoading(false);
    }
  };

  const handleClearCfLogs = async () => {
    setWafConfirmDialog({
      isOpen: true,
      title: 'Clear Stored Cloudflare Edge Logs',
      message: 'Are you sure you want to completely clear all cached Cloudflare edge security events from your local JSON vault? This will remove the local cached events without affecting your Cloudflare dashboard.',
      confirmLabel: 'Clear Cloudflare JSON Logs',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setCfClearingLogs(true);
          const res = await apiRequest({ path: '/cloudflare/clear-firewall-events', method: 'POST' });
          if (res && res.success) {
            setCfEvents([]);
            setCfLastSynced(null);
            setActionMessage({ type: 'success', text: 'All stored Cloudflare edge logs cleared from local JSON vault.' });
          } else {
            setActionMessage({ type: 'error', text: res?.message || 'Failed to clear Cloudflare JSON logs.' });
          }
        } catch (err: any) {
          setActionMessage({ type: 'error', text: err?.message || 'Network error clearing Cloudflare logs.' });
        } finally {
          setCfClearingLogs(false);
          setWafConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        }
      }
    });
  };

  const handleFetchNewCfEvents = async () => {
    try {
      setCfFetchingNew(true);
      setCfError(null);
      setCfMissingPerm(false);
      const res = await apiRequest({
        path: '/cloudflare/fetch-firewall-events',
        method: 'POST',
        data: { limit: 150 }
      });
      if (res && res.success) {
        setCfEvents(res.events || []);
        setCfLastSynced(res.last_synced || null);
        setCfZoneName(res.zone_name || '');
        if (res.zone_id) {
          setCfZoneId(res.zone_id);
        }
        setActionMessage({
          type: 'success',
          text: `Fetched ${res.new_fetched || 0} new Cloudflare edge security events! Total stored: ${res.total_stored || 0}.`
        });
      } else {
        if (res?.missing_permission) {
          setCfMissingPerm(true);
        }
        setCfError(res?.message || 'Failed to fetch fresh events from Cloudflare API.');
      }
    } catch (err: any) {
      setCfError(err?.message || 'Network error fetching fresh events from Cloudflare.');
    } finally {
      setCfFetchingNew(false);
    }
  };

  const handleSwitchToCloudflareTab = () => {
    switchLogTab('cloudflare');
    if (cfEvents.length === 0 && !cfLoading) {
      loadStoredCfEvents();
    }
  };

  useEffect(() => {
    if (activeLogTab === 'cloudflare' && cfEvents.length === 0 && !cfLoading) {
      loadStoredCfEvents();
    }
  }, [activeLogTab]);

  const handleWhitelistCfIp = async (ip: string) => {
    try {
      setCfWhitelistingIp(ip);
      const res = await apiRequest({
        path: '/cloudflare/whitelist-ip',
        method: 'POST',
        data: {
          ip,
          notes: 'Whitelisted from Cloudflare Edge Events forensic modal'
        }
      });
      if (res && res.success) {
        setCfWhitelistSuccess(ip);
        toast.success(`IP ${ip} successfully allowlisted on Cloudflare Edge.`);
        setTimeout(() => setCfWhitelistSuccess(null), 4000);
      } else {
        toast.error(res?.message || `Failed to whitelist IP ${ip} on Cloudflare.`);
      }
    } catch (err: any) {
      toast.error(`Error whitelisting IP: ` + (err?.message || 'Network error'));
    } finally {
      setCfWhitelistingIp(null);
    }
  };

  const exportMenuRef = useRef<HTMLDivElement | null>(null);

  // Click outside column dropdown
  useEffect(() => {
    const handleColClickOutside = (e: MouseEvent) => {
      if (columnMenuRef.current && !columnMenuRef.current.contains(e.target as Node)) {
        setColumnMenuOpen(false);
      }
    };
    if (columnMenuOpen) {
      document.addEventListener('mousedown', handleColClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleColClickOutside);
  }, [columnMenuOpen]);

  // Debounce search
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchQuery);
      setPage(1);
    }, 350);
    return () => clearTimeout(handler);
  }, [searchQuery]);

  // Click outside export dropdown
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    if (exportMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [exportMenuOpen]);

  // Load stats based on selected time range
  const fetchStats = async () => {
    try {
      const res = await apiRequest({
        path: `/firewall/logs/stats?range=${timeRange}`,
        method: 'GET'
      });
      if (res && res.stats) {
        setStats(res.stats);
      }
      if (res && res.retention_days) {
        setRetentionDays(res.retention_days);
      }
    } catch (err) {
      console.warn('WebCare: Failed to fetch WAF log stats', err);
    }
  };

  // Fetch available files list
  const fetchFiles = async () => {
    try {
      const res = await apiRequest({ path: '/firewall/logs/files', method: 'GET' });
      if (res && res.files) {
        setAvailableFiles(res.files);
        if (res.retention_days) {
          setRetentionDays(res.retention_days);
        }
      }
    } catch (err) {
      console.warn('WebCare: Failed to fetch WAF log files', err);
    }
  };

  // Load paginated logs
  const fetchLogs = async (silent: boolean = false) => {
    if (!silent) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    try {
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      params.append('limit', String(pageSize));
      params.append('offset', String(offset));
      params.append('range', timeRange);
      if (timeRange === 'daily' && selectedDayFile) {
        params.append('date', selectedDayFile);
      }
      params.append('sort_by', sortBy);
      params.append('sort_order', sortOrder);

      if (debouncedSearch) params.append('search', debouncedSearch);
      if (selectedCategory && selectedCategory !== 'all') params.append('category', selectedCategory);
      if (selectedAction && selectedAction !== 'all') params.append('action', selectedAction);
      if (selectedMethod && selectedMethod !== 'all') params.append('method', selectedMethod);
      if (selectedStatusCode && selectedStatusCode !== 'all') params.append('status_code', selectedStatusCode);
      if (filterIp) params.append('ip', filterIp);

      const path = `/firewall/logs?${params.toString()}`;
      const res = await apiRequest({ path, method: 'GET' });

      if (res && res.logs) {
        setLogs(res.logs);
        setTotalCount(res.total || 0);
        if (res.available_files) {
          setAvailableFiles(res.available_files);
        }
        if (res.retention_days) {
          setRetentionDays(res.retention_days);
        }
        if (res.current_client_ip) {
          setCurrentClientIp(res.current_client_ip);
        }
      }
    } catch (err: any) {
      console.error('WebCare: Failed to fetch WAF incident logs', err);
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to load firewall logs from server.',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Handle column header sort toggle
  const handleSort = (columnKey: string) => {
    if (sortBy === columnKey) {
      setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(columnKey);
      setSortOrder('desc');
    }
    setPage(1);
  };

  // Save log retention policy
  const handleSaveRetention = async (days: number) => {
    try {
      setUpdatingRetention(true);
      const res = await apiRequest({
        path: '/firewall/logs/retention',
        method: 'POST',
        data: { retention_days: days }
      });
      if (res && res.success) {
        setRetentionDays(days);
        setActionMessage({
          type: 'success',
          text: `WAF log retention period updated to ${days === 0 ? 'Unlimited (Keep Forever)' : `${days} days`}.`
        });
      } else {
        setActionMessage({
          type: 'error',
          text: res?.message || 'Failed to update retention period.'
        });
      }
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Network error updating retention period.'
      });
    } finally {
      setUpdatingRetention(false);
    }
  };

  // Manual log pruning trigger
  const handlePruneLogs = async () => {
    requestWafConfirm({
      title: 'Prune Expired WAF Logs',
      message: 'Prune expired WAF daily log files according to current retention policy? Older logs beyond the retention window will be permanently removed.',
      confirmLabel: 'Prune Expired Logs',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setPruningLogs(true);
          const res = await apiRequest({ path: '/firewall/logs/prune', method: 'POST' });
          if (res && res.success) {
            setActionMessage({
              type: 'success',
              text: res.message || 'Expired WAF log files pruned successfully.'
            });
            fetchFiles();
            fetchLogs();
            fetchStats();
          } else {
            setActionMessage({
              type: 'error',
              text: res?.message || 'Failed to prune logs.'
            });
          }
        } catch (err: any) {
          setActionMessage({
            type: 'error',
            text: err?.message || 'Network error pruning logs.'
          });
        } finally {
          setPruningLogs(false);
          setTimeout(() => setActionMessage(null), 4000);
        }
      },
    });
  };

  // Download raw daily JSON file
  const handleDownloadFile = async (filename: string) => {
    try {
      const res = await apiRequest({
        path: `/firewall/logs/download?filename=${encodeURIComponent(filename)}`,
        method: 'GET'
      });
      if (res && res.records) {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(res.records, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute('href', dataStr);
        downloadAnchor.setAttribute('download', filename);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        setActionMessage({
          type: 'success',
          text: `Downloaded ${filename} (${res.count} records).`
        });
        toast.success(`Downloaded ${filename} (${res.count} records).`);
      } else {
        toast.error(res?.message || 'Failed to download daily log file.');
      }
    } catch (err: any) {
      toast.error(err?.message || 'Error downloading log file.');
    }
  };

  // Refresh on filter/page/range/sort change
  useEffect(() => {
    fetchLogs();
  }, [page, pageSize, timeRange, selectedDayFile, sortBy, sortOrder, debouncedSearch, selectedCategory, selectedAction, selectedMethod, selectedStatusCode, filterIp]);

  // Initial stats and files fetch
  useEffect(() => {
    fetchStats();
    fetchFiles();
  }, [timeRange]);

  // Live Auto-Refresh poller
  useEffect(() => {
    if (!isLiveAutoRefresh) return;
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      fetchLogs(true);
      fetchStats();
    }, autoRefreshInterval * 1000);
    return () => clearInterval(timer);
  }, [isLiveAutoRefresh, autoRefreshInterval, page, pageSize, debouncedSearch, selectedCategory, selectedAction, selectedMethod, selectedStatusCode, filterIp]);

  // Action: Clear all logs
  const handleClearAllLogs = async () => {
    requestWafConfirm({
      title: 'Clear All WAF Incident Records',
      message: 'Are you sure you want to completely clear all WAF incident logs? This will purge all recorded attack packets and forensic telemetry from your database. This action cannot be reversed.',
      confirmLabel: 'Clear All WAF Logs',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setLoading(true);
          const res = await apiRequest({ path: '/firewall/clear-logs', method: 'POST' });
          if (res && res.success) {
            setActionMessage({ type: 'success', text: 'All WAF incident records successfully purged.' });
            setLogs([]);
            setTotalCount(0);
            setSelectedLogIds([]);
            setStats({
              total_intercepted: 0,
              blocked_24h: 0,
              detected_learning: 0,
              unique_attack_ips: 0,
              top_categories: [],
              top_ips: [],
              top_targets: [],
              methods_breakdown: [],
              hourly_trend: [],
            });
            await fetchStats();
          }
        } catch (err: any) {
          setActionMessage({ type: 'error', text: err?.message || 'Failed to clear logs.' });
        } finally {
          setLoading(false);
          setTimeout(() => setActionMessage(null), 4000);
        }
      },
    });
  };

  // Action: Delete single log
  const handleDeleteSingleLog = async (id: number, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    try {
      const res = await apiRequest({
        path: '/firewall/logs/delete',
        method: 'POST',
        data: { id }
      });
      if (res && res.success) {
        setLogs(prev => prev.filter(item => item.id !== id));
        setTotalCount(prev => Math.max(0, prev - 1));
        if (expandedLogId === id) setExpandedLogId(null);
        if (inspectedLog?.id === id) setInspectedLog(null);
        setSelectedLogIds(prev => prev.filter(x => x !== id));
        setActionMessage({ type: 'success', text: `Log record #${id} removed.` });
        fetchStats();
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to delete log entry.' });
    }
    setTimeout(() => setActionMessage(null), 3000);
  };

  // State & Action: 1-Click Allow Action / Route in Rule #36 / Rule #37
  const [allowingTarget, setAllowingTarget] = useState<string | null>(null);

  // 1-Click "Trust This Customer Action" scoped to (route_path + param_key + user_role)
  const handleTrustCustomerAction = async (log: WafIncident) => {
    const rawUri = (log.request_uri || '').split('?')[0] || '/';
    // Use canonical parameter key strictly; never fall back to legacy matched_param or raw payload values
    const paramKey = log.matched_param_key || '';
    const userRole = log.user_role || (log.username ? 'customer' : '');
    const ruleId = log.rule_id || '';
    const method = (log.request_method || '').toUpperCase();
    const incidentId = String(log.incident_id || log.id || '');
    const key = `${rawUri}:${paramKey || ruleId}`;

    if (!incidentId) {
      setActionMessage({ type: 'error', text: 'Cannot trust action: incident ID is missing from audit log.' });
      setTimeout(() => setActionMessage(null), 4000);
      return;
    }

    if (!method) {
      setActionMessage({ type: 'error', text: 'Cannot trust action: incident request method is missing.' });
      setTimeout(() => setActionMessage(null), 4000);
      return;
    }

    try {
      setAllowingTarget(key);
      const res = await apiRequest({
        path: '/firewall/logs/trust-action',
        method: 'POST',
        data: {
          uri: rawUri,
          rule_id: ruleId,
          param_key: paramKey,
          user_role: userRole,
          method: method,
          incident_id: incidentId,
          ip: log.ip_address,
          label: `1-Click Trusted Action for ${log.username || 'Customer'} on ${rawUri}${paramKey ? ` (param: ${paramKey})` : ''}`,
        }
      });
      if (res && res.success) {
        setActionMessage({
          type: 'success',
          text: res.message || `Customer action trusted! Scoped exemption created for ${rawUri}${paramKey ? ` (param: ${paramKey})` : ''}. All SQLi/RCE rules remain 100% active.`
        });
      } else {
        setActionMessage({ type: 'error', text: res?.message || 'Failed to apply scoped exemption.' });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to trust customer action.' });
    } finally {
      setAllowingTarget(null);
      setTimeout(() => setActionMessage(null), 5000);
    }
  };

  const handleAllowlistRuleTarget = async (rule: 36 | 37, target: string, method?: string) => {
    const key = method ? `${method} ${target}` : target;
    try {
      setAllowingTarget(key);
      const res = await apiRequest({
        path: '/firewall/allowlist-rule-target',
        method: 'POST',
        data: { rule, target, method }
      });
      if (res && res.success) {
        setActionMessage({ type: 'success', text: res.message || 'Allowlist successfully updated.' });
      } else {
        setActionMessage({ type: 'error', text: res?.message || 'Failed to update allowlist.' });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Error updating allowlist.' });
    } finally {
      setAllowingTarget(null);
      setTimeout(() => setActionMessage(null), 4000);
    }
  };

  // Action: Block IP at local WAF
  const handleBlockIp = async (ip: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    try {
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: { ip }
      });
      if (res && res.success) {
        setActionMessage({
          type: 'success',
          text: `IP ${ip} permanently added to custom WAF blocklist.`
        });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to block IP.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  // Open Rule-Scoped Allowlist Modal from WAF log row
  const openAllowlistModal = (log: WafIncident, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const endpointPath = log.request_uri ? (log.request_uri.split('?')[0] || '/') : '/';
    setAllowlistModal({
      isOpen: true,
      ip: log.ip_address,
      ruleId: log.rule_id || '',
      ruleCategory: log.rule_category || 'Firewall Defense',
      ruleName: log.rule_name || log.rule_description || 'Firewall Rule',
      endpoint: endpointPath,
      scope: log.rule_id ? 'rule' : 'category',
      endpointScoped: false,
      expiresIn: 86400,
      reason: `Allowed from WAF Logs for ${log.rule_category}${log.rule_id ? ` (${log.rule_id})` : ''}`,
      isSubmitting: false,
    });
  };

  // Submit Granular Rule-Scoped Allowlist
  const handleSubmitAllowlist = async () => {
    if (!allowlistModal.ip) return;
    setAllowlistModal(prev => ({ ...prev, isSubmitting: true }));
    try {
      const payload: any = {
        ip: allowlistModal.ip,
        scope: allowlistModal.scope,
        reason: allowlistModal.reason.trim() || 'Administrator allowlist policy',
        expires_in: allowlistModal.expiresIn,
      };

      if (allowlistModal.scope === 'rule' && allowlistModal.ruleId) {
        payload.allowed_rules = [allowlistModal.ruleId];
      } else if (allowlistModal.scope === 'category' && allowlistModal.ruleCategory) {
        payload.allowed_cats = [allowlistModal.ruleCategory];
      }

      if (allowlistModal.endpointScoped && allowlistModal.endpoint) {
        payload.endpoint = allowlistModal.endpoint;
      }

      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: payload
      });

      if (res && res.success) {
        setActionMessage({
          type: 'success',
          text: res.message || `IP ${allowlistModal.ip} successfully allowlisted.`
        });
        setAllowlistModal(prev => ({ ...prev, isOpen: false, isSubmitting: false }));
      } else {
        setActionMessage({ type: 'error', text: res?.message || 'Failed to allowlist IP.' });
        setAllowlistModal(prev => ({ ...prev, isSubmitting: false }));
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to allowlist IP.' });
      setAllowlistModal(prev => ({ ...prev, isSubmitting: false }));
    }
    setTimeout(() => setActionMessage(null), 5000);
  };

  // Action: Unblock IP (remove from blocklist & clear active lockouts, with optional temporary duration in seconds)
  const handleUnblockIp = async (ip: string, e?: React.MouseEvent, durationSeconds: number = 0) => {
    if (e) e.stopPropagation();
    try {
      const res = await apiRequest({
        path: '/firewall/logs/unblock-ip',
        method: 'POST',
        data: { ip, duration: durationSeconds }
      });
      if (res && res.success) {
        setActionMessage({
          type: 'success',
          text: res.message || (durationSeconds > 0
            ? `IP ${ip} temporarily unblocked for ${Math.round(durationSeconds / 60)} minutes. Standard WAF protection remains active.`
            : `IP ${ip} has been unblocked. Standard WAF protection remains active.`)
        });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to unblock IP.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  // Action: Copy text
  const copyToClipboard = (text: string, label: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedKey(label);
      setTimeout(() => setCopiedKey(null), 2500);
    } catch {}
  };

  // Helper: Trigger File Download in browser
  const triggerLogDownload = (dataBlob: Blob, filename: string) => {
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }, 250);
  };

  // Convert array of WAF records into safe CSV
  const formatWafRecordsAsCsv = (records: any[]): string => {
    const escapeCell = (val: any): string => {
      if (val === null || val === undefined) return '""';
      let str = typeof val === 'object' ? JSON.stringify(val) : String(val);
      const trimmed = str.trim();
      if (trimmed.length > 0 && ['=', '+', '-', '@', '\t', '\r'].includes(trimmed[0])) {
        str = `'` + str;
      }
      return `"${str.replace(/"/g, '""')}"`;
    };

    const headers = [
      'ID',
      'Incident ID',
      'Timestamp',
      'IP Address',
      'Is Banned',
      'Cloudflare Synced',
      'Ban Scope',
      'Method',
      'URI',
      'Status Code',
      'Category',
      'Description',
      'Action Taken',
      'Ban Reason',
      'User Agent',
      'Username',
      'User Role',
      'Payload Sample',
      'Hostname'
    ];

    const rows = records.map(l => [
      escapeCell(l.id),
      escapeCell(l.incident_id || ''),
      escapeCell(l.created_at || ''),
      escapeCell(l.ip_address || ''),
      escapeCell(l.is_banned ? 'YES' : 'NO'),
      escapeCell(l.cf_synced ? 'YES' : 'NO'),
      escapeCell(l.ban_scope || 'none'),
      escapeCell(l.request_method || ''),
      escapeCell(l.request_uri || ''),
      escapeCell(l.http_status_code || ''),
      escapeCell(l.rule_category || ''),
      escapeCell(l.rule_description || ''),
      escapeCell(l.action_taken || ''),
      escapeCell(l.ban_reason || ''),
      escapeCell(l.user_agent || ''),
      escapeCell(l.username || ''),
      escapeCell(l.user_role || ''),
      escapeCell(l.payload_sample || ''),
      escapeCell(l.hostname || '')
    ].join(','));

    // Prepend UTF-8 BOM for Microsoft Excel
    const csvBody = [headers.map(escapeCell).join(','), ...rows].join('\r\n');
    return '\uFEFF' + csvBody;
  };

  const formatWafCsvWithTelemetry = (records: WafIncident[], telemetry: any) => {
    const baseCsv = formatWafRecordsAsCsv(records);
    if (!telemetry) return baseCsv;

    const cfText = telemetry?.edge_network?.powered_by_cloudflare
      ? `YES (${telemetry?.edge_network?.cloudflare_status || 'Cloudflare Edge'})`
      : 'NO (Direct Origin)';
    const actPlugins = telemetry?.plugins?.active_plugins || [];
    const actPluginsStr = actPlugins.slice(0, 15).map((p: any) => p.name).join(', ') +
      (actPlugins.length > 15 ? ` ... (+${actPlugins.length - 15} more)` : '');

    const preamble = [
      '# =============================================================================',
      '# WebCare Pro Security & Firewall - WAF INCIDENT LOGS & ATTACK FORENSICS',
      `# Site Domain: ${telemetry?.site?.domain || 'Unknown'} | Real Server IP: ${telemetry?.server?.real_ip || 'Unknown'}`,
      `# Cloudflare Edge: ${cfText}`,
      `# Cloudflare Integration: ${telemetry?.edge_network?.cloudflare_connected ? 'CONNECTED' : 'NOT CONNECTED'} | Auto-Ban Sync: ${telemetry?.edge_network?.cf_auto_sync_bans_enabled ? 'ENABLED' : 'DISABLED'} | Active Edge Bans: ${telemetry?.edge_network?.cf_active_edge_bans_count || 0} | Local Blocks: ${telemetry?.edge_network?.local_active_blocks_count || 0}`,
      `# Server Software: ${telemetry?.server?.software || 'Unknown'} | PHP: ${telemetry?.server?.php_version || 'Unknown'} | WP Core: ${telemetry?.wordpress?.core_version || 'Unknown'}`,
      `# Active Theme: ${telemetry?.theme?.active_theme?.name || 'Unknown'} (v${telemetry?.theme?.active_theme?.version || 'Unknown'})`,
      `# Active Plugins (${actPlugins.length}): ${actPluginsStr}`,
      `# Exported At (UTC): ${telemetry?.exported_at_utc || new Date().toISOString()}`,
      '# ============================================================================='
    ].join('\r\n');

    // Retain BOM at absolute front
    return '\uFEFF' + preamble + '\r\n' + baseCsv.replace(/^\uFEFF/, '');
  };

  // Execute full modal export
  const executeWafExport = async () => {
    setIsExporting(true);
    try {
      const filename = generateStandardLogFilename('waf-logs', exportFormat, exportScope === 'date' ? exportDate : undefined);

      let targetRecords: any[] = [];

      if (exportScope === 'filtered') {
        // Export current table view
        targetRecords = logs;
      } else {
        // Query backend for full records
        const params = new URLSearchParams();
        params.append('limit', '10000');
        params.append('offset', '0');
        params.append('is_export', '1');

        if (exportScope === 'all') {
          params.append('range', 'all');
        } else if (exportScope === 'date') {
          params.append('range', 'daily');
          params.append('date', exportDate);
        }

        if (includeSystemInfo) {
          params.append('include_system_info', '1');
        }

        const res = await apiRequest({
          path: `/firewall/logs?${params.toString()}`,
          method: 'GET'
        });

        if (res && res.logs) {
          targetRecords = res.logs;
        } else {
          throw new Error(res?.message || 'Failed to retrieve WAF logs for export.');
        }
      }

      if (targetRecords.length === 0) {
        toast.warning('No incident logs found matching the selected export scope.');
        setIsExporting(false);
        return;
      }

      // Fetch environment telemetry snapshot if requested and not yet available
      let envSnapshot: any = null;
      if (includeSystemInfo) {
        try {
          const snapRes = await apiRequest({
            path: '/telemetry/snapshot',
            method: 'GET'
          });
          if (snapRes && snapRes.snapshot) {
            envSnapshot = snapRes.snapshot;
          }
        } catch (snapErr) {
          console.warn('WebCare: Could not fetch telemetry snapshot for WAF export', snapErr);
        }
      }

      if (exportFormat === 'json') {
        const payload: any = {
          report_generator: 'WebCare Pro Security & Firewall - Web Application Firewall',
          specialist: 'Mir Alamin (WebCare Pro)',
          specialist_role: 'Senior Linux SysAdmin & WordPress Security Engineer',
          site_url: (window as any).webcareScannerSettings?.siteUrl || window.location.origin,
          exported_at: new Date().toISOString(),
          scope: exportScope,
          date_filter: exportScope === 'date' ? exportDate : null,
          total_records: targetRecords.length,
          records: targetRecords
        };

        if (includeSystemInfo && envSnapshot) {
          payload.environment_snapshot = envSnapshot;
          payload.edge_telemetry = envSnapshot.edge_network || null;
        }

        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
        triggerLogDownload(blob, filename);
      } else {
        const csv = (includeSystemInfo && envSnapshot)
          ? formatWafCsvWithTelemetry(targetRecords, envSnapshot)
          : formatWafRecordsAsCsv(targetRecords);
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        triggerLogDownload(blob, filename);
      }

      setActionMessage({
        type: 'success',
        text: `Successfully exported ${targetRecords.length} WAF log incidents as ${filename}.`
      });
      toast.success(`Successfully exported ${targetRecords.length} WAF log incidents as ${filename}.`);
      setIsExportModalOpen(false);
    } catch (err: any) {
      console.error('WebCare: WAF log export error', err);
      toast.error(err?.message || 'Error occurred during WAF log export.');
    } finally {
      setIsExporting(false);
    }
  };

  const handlePrintLogs = () => {
    window.print();
    setExportMenuOpen(false);
  };

  // Total pages
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  // Toggle selection
  const handleToggleSelectAll = () => {
    if (selectedLogIds.length === logs.length && logs.length > 0) {
      setSelectedLogIds([]);
    } else {
      setSelectedLogIds(logs.map(l => l.id));
    }
  };

  const handleToggleSelectLog = (id: number) => {
    setSelectedLogIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  // Bulk delete selected
  const handleBulkDeleteSelected = async () => {
    if (selectedLogIds.length === 0) return;
    requestWafConfirm({
      title: 'Delete Selected Incident Logs',
      message: `Are you sure you want to delete ${selectedLogIds.length} selected incident records? They will be permanently removed from your log archive.`,
      targetItem: `${selectedLogIds.length} incident logs`,
      confirmLabel: 'Delete Selected',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setLoading(true);
          for (const id of selectedLogIds) {
            await apiRequest({ path: '/firewall/logs/delete', method: 'POST', data: { id } });
          }
          setActionMessage({ type: 'success', text: `Successfully deleted ${selectedLogIds.length} incident records.` });
          setSelectedLogIds([]);
          fetchLogs();
          fetchStats();
        } catch (err: any) {
          setActionMessage({ type: 'error', text: err?.message || 'Failed to delete selected logs.' });
        } finally {
          setLoading(false);
          setTimeout(() => setActionMessage(null), 3500);
        }
      },
    });
  };

  const formatActionMessage = (text: string) => {
    if (!text) return '';
    if (text.includes('<') && text.includes('>')) {
      try {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        return doc.body.textContent || doc.body.innerText || text;
      } catch (e) {
        return text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      }
    }
    return text;
  };

  return (
    <div className="webcare-page-container webcare-waf-logs-page" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Quick-Switch Cross-Link Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 16px',
          marginBottom: '12px',
          borderRadius: '8px',
          background: 'var(--webcare-bg-surface, #f8fafc)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          fontSize: '12.5px',
          color: 'var(--webcare-text-secondary, #475569)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={() => handleFirewallNavigation('rules')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              color: 'var(--webcare-text-primary, #0f172a)',
              cursor: 'pointer'
            }}
          >
            <span>← Firewall Rules &amp; Presets</span>
          </button>
          <span style={{ color: 'var(--webcare-border, #cbd5e1)' }}>|</span>
          <button
            type="button"
            onClick={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=custom-waf-rules'; }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'transparent',
              border: 'none',
              color: '#6366f1',
              cursor: 'pointer'
            }}
          >
            <span>Visual Rule Builder</span>
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={() => { window.location.href = 'admin.php?page=webcare-pro-logs&tab=activity'; }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'transparent',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              color: 'var(--webcare-text-primary, #0f172a)',
              cursor: 'pointer'
            }}
          >
            <span>Activity Logs →</span>
          </button>
        </div>
      </div>

      {/* 1. Header Banner & Title */}
      <div className="webcare-waf-hero-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div className="webcare-waf-hero-icon-box">
              <ShieldAlert size={28} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 className="webcare-waf-hero-title">WAF Incident Logs &amp; Threat Intelligence</h2>
                <span className="webcare-badge-pill webcare-badge-danger">
                  Live Perimeter Audit
                </span>
                {isLiveAutoRefresh && (
                  <span className="webcare-badge-pill webcare-badge-pulse" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                    ● Polling Every {autoRefreshInterval}s
                  </span>
                )}
              </div>
              <p className="webcare-waf-hero-desc">
                High-fidelity forensic audit of all intercepted exploit payloads, SQL injections, path traversals, zero-day virtual patches, and botnet incursions.
              </p>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {/* Live Poller Toggle (for Server WAF logs) */}
            {activeLogTab === 'local' && (
              <button
                type="button"
                className={`webcare-btn ${isLiveAutoRefresh ? 'webcare-btn-success' : 'webcare-btn-secondary'}`}
                onClick={() => setIsLiveAutoRefresh(!isLiveAutoRefresh)}
                title="Toggle automatic live polling of new blocked events"
                style={{ fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <Radio size={14} className={isLiveAutoRefresh ? 'webcare-spin-slow' : ''} />
                <span>{isLiveAutoRefresh ? 'Auto-Refresh: ON' : 'Live Auto-Refresh'}</span>
              </button>
            )}

            {/* Fetch New Cloudflare Events button (when on cloudflare subtab) */}
            {activeLogTab === 'cloudflare' && (
              <button
                type="button"
                className="webcare-btn"
                onClick={handleFetchNewCfEvents}
                disabled={cfFetchingNew}
                style={{
                  fontSize: '13px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#ea580c',
                  color: '#ffffff',
                  border: 'none',
                  fontWeight: 600,
                  boxShadow: '0 2px 4px rgba(234, 88, 12, 0.2)'
                }}
              >
                {cfFetchingNew ? <Loader2 size={14} className="webcare-spin" /> : <RefreshCw size={14} />}
                <span>{cfFetchingNew ? 'Fetching from Edge...' : 'Fetch New Cloudflare Events'}</span>
              </button>
            )}

            {/* Refresh */}
            {activeLogTab !== 'rules' && (
              <button
                type="button"
                className="webcare-btn webcare-btn-secondary"
                onClick={() => {
                  if (activeLogTab === 'cloudflare') {
                    loadStoredCfEvents();
                  } else {
                    fetchLogs(true);
                    fetchStats();
                  }
                }}
                disabled={activeLogTab === 'cloudflare' ? cfLoading : (refreshing || loading)}
                style={{ fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <RefreshCw size={14} className={(activeLogTab === 'cloudflare' ? cfLoading : refreshing) ? 'webcare-spin-icon' : ''} />
                <span>Refresh</span>
              </button>
            )}

            {/* Export Logs Button (for Local Logs) */}
            {activeLogTab === 'local' && (
              <button
                type="button"
                className="webcare-btn webcare-btn-secondary"
                onClick={() => setIsExportModalOpen(true)}
                style={{ fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}
                title="Configure and download WAF incident logs"
              >
                <Download size={14} />
                <span>Export Logs</span>
              </button>
            )}

            {/* Column Customizer Dropdown (for Local Logs) */}
            {activeLogTab === 'local' && (
              <div style={{ position: 'relative' }} ref={columnMenuRef}>
                <button
                  type="button"
                  className="webcare-btn webcare-btn-secondary"
                  onClick={() => setColumnMenuOpen(!columnMenuOpen)}
                  style={{ fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                  title="Customize table columns"
                >
                  <Columns size={14} />
                  <span>Columns</span>
                  <ChevronDown size={14} />
                </button>

                {columnMenuOpen && (
                  <div className="webcare-dropdown-menu" style={{
                    position: 'absolute',
                    right: 0,
                    top: '100%',
                    marginTop: '6px',
                    background: 'var(--webcare-bg-panel, #ffffff)',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    borderRadius: '8px',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.15)',
                    minWidth: '220px',
                    zIndex: 100,
                    padding: '8px 0'
                  }}>
                    <div style={{ padding: '6px 14px', fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', borderBottom: '1px solid var(--webcare-border, #f1f5f9)' }}>
                      Customize Visible Columns
                    </div>
                    {[
                      { key: 'timestamp', label: 'Timestamp' },
                      { key: 'status_code', label: 'HTTP Status Code' },
                      { key: 'ip', label: 'Client IP' },
                      { key: 'category', label: 'Attack Vector / Category' },
                      { key: 'uri', label: 'Target URI Endpoint' },
                      { key: 'method', label: 'HTTP Method' },
                      { key: 'referer', label: 'HTTP Referer' },
                      { key: 'user_agent', label: 'User-Agent Fingerprint' },
                      { key: 'action', label: 'Action Taken' },
                      { key: 'controls', label: 'Forensic Controls' },
                    ].map((col) => (
                      <label
                        key={col.key}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          padding: '7px 14px',
                          cursor: 'pointer',
                          fontSize: '12px',
                          color: 'var(--webcare-text-primary, #0f172a)'
                        }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="checkbox"
                          checked={!!visibleColumns[col.key]}
                          onChange={() => toggleColumn(col.key)}
                        />
                        <span>{col.label}</span>
                      </label>
                    ))}
                    <div style={{ padding: '6px 14px', borderTop: '1px solid var(--webcare-border, #f1f5f9)', display: 'flex', justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        className="webcare-btn-micro"
                        onClick={() => {
                          setVisibleColumns(DEFAULT_VISIBLE_COLUMNS);
                          try {
                            localStorage.removeItem('webcare_waf_logs_columns');
                          } catch (e) {}
                        }}
                      >
                        Reset Defaults
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Clear All Logs */}
            {activeLogTab === 'local' && totalCount > 0 && (
              <button
                type="button"
                className="webcare-btn webcare-btn-danger-soft"
                style={{
                  fontSize: '13px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
                onClick={handleClearAllLogs}
              >
                <Trash2 size={14} />
                <span>Clear All Logs</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs & Dropdown (Synchronized with Firewall Page) */}
      <div className="webcare-tabs-bar" style={{ alignItems: 'center', position: 'relative', marginTop: '16px', marginBottom: '16px' }}>
        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('stream')}
        >
          <Activity size={16} /> Live Incident Stream
        </button>

        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('rules')}
        >
          <Sliders size={16} /> Firewall Rules &amp; Controls
        </button>

        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('caf')}
        >
          <Sparkles size={16} color="#0284c7" />
          <span>Adaptive Firewall (CAF)</span>
          <span className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '10px', padding: '1px 6px', marginLeft: '4px' }}>
            StackGuard
          </span>
        </button>

        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('cloudflare')}
        >
          <Cloud
            size={16}
            style={{
              color: cfStatus?.configured ? '#F38020' : '#94a3b8',
              strokeWidth: 2.5
            }}
          />
          <span>Cloudflare Edge Defense</span>
          {cfStatus?.configured && (
            <span style={{ color: '#10b981', fontSize: '11px', fontWeight: 700, marginLeft: '2px' }}>
              ● Connected
            </span>
          )}
        </button>

        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('behavioral')}
        >
          <Sliders size={16} /> Behavioral WAF &amp; Bot Traps
        </button>

        <button
          type="button"
          className="webcare-tab-link"
          onClick={() => handleFirewallNavigation('ai_defense')}
        >
          <Sparkles size={16} /> 2026 AI Defense &amp; Decoy Traps
        </button>

        {/* More Security Tools Dropdown */}
        <div ref={moreMenuRef} style={{ position: 'relative', display: 'inline-block' }}>
          <button
            type="button"
            className="webcare-tab-link"
            onClick={() => setIsMoreMenuOpen(!isMoreMenuOpen)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            aria-expanded={isMoreMenuOpen}
          >
            <Layers size={16} />
            <span>Advanced Modules</span>
            <ChevronDown size={14} style={{ transform: isMoreMenuOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease' }} />
          </button>

          {isMoreMenuOpen && (
            <div
              className="webcare-dropdown-menu"
              style={{
                position: 'absolute',
                top: 'calc(100% + 4px)',
                left: 0,
                zIndex: 100,
                minWidth: '240px',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                borderRadius: '8px',
                boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
                padding: '6px 0',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              <button
                type="button"
                onClick={() => handleFirewallNavigation('drill')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: 'transparent',
                  color: 'inherit',
                  fontWeight: 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Target size={15} color="#dc2626" />
                <span>Red Team Attack Drill</span>
              </button>

              <button
                type="button"
                onClick={() => handleFirewallNavigation('supply_chain')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: 'transparent',
                  color: 'inherit',
                  fontWeight: 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Layers size={15} color="#7c3aed" />
                <span>Supply-Chain &amp; SBOM</span>
              </button>

              <button
                type="button"
                onClick={() => handleFirewallNavigation('server_sec')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: 'transparent',
                  color: 'inherit',
                  fontWeight: 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Server size={15} color="#0284c7" />
                <span>Server Security (Nginx / Apache)</span>
              </button>

              <button
                type="button"
                onClick={() => handleFirewallNavigation('intel')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: 'transparent',
                  color: 'inherit',
                  fontWeight: 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Globe size={15} color="#059669" />
                <span>Cloud Threat Intel &amp; Feeds</span>
              </button>

              <button
                type="button"
                onClick={() => handleFirewallNavigation('vpatch')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: 'transparent',
                  color: 'inherit',
                  fontWeight: 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <ShieldAlert size={15} color="#ea580c" />
                <span>Virtual Patching &amp; 0-Day Shield</span>
              </button>
            </div>
          )}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <button
            type="button"
            className={`webcare-tab-link ${activeLogTab === 'local' ? 'is-active' : ''}`}
            style={{ color: activeLogTab === 'local' ? undefined : 'var(--webcare-status-info, #4f46e5)', fontWeight: 600 }}
            onClick={() => { setIsMoreMenuOpen(false); switchLogTab('local'); }}
            title="Dedicated Full-Page Server WAF Incident Logs"
          >
            <FileText size={16} /> Server WAF Logs ({totalCount.toLocaleString()})
          </button>

          <button
            type="button"
            className={`webcare-tab-link ${activeLogTab === 'cloudflare' ? 'is-active' : ''}`}
            style={{ color: activeLogTab === 'cloudflare' ? undefined : '#ea580c', fontWeight: 600 }}
            onClick={() => { setIsMoreMenuOpen(false); handleSwitchToCloudflareTab(); }}
            title="Cloudflare Anycast Edge Firewall Block Events"
          >
            <Cloud size={16} style={{ color: cfStatus?.configured ? '#F38020' : '#94a3b8' }} />
            <span>Cloudflare Edge Logs</span>
            {cfEvents.length > 0 && (
              <span style={{
                fontSize: '11px',
                padding: '1px 6px',
                borderRadius: '10px',
                background: activeLogTab === 'cloudflare' ? 'rgba(234, 88, 12, 0.15)' : 'var(--webcare-bg-surface-elevated, var(--webcare-bg-elevated))',
                color: activeLogTab === 'cloudflare' ? '#ea580c' : 'var(--webcare-text-muted, #64748b)',
                fontWeight: 700,
                marginLeft: '4px'
              }}>
                {cfEvents.length}
              </span>
            )}
          </button>

          <button
            type="button"
            className={`webcare-tab-link ${activeLogTab === 'rules' ? 'is-active' : ''}`}
            style={{ color: activeLogTab === 'rules' ? undefined : '#dc2626', fontWeight: 600 }}
            onClick={() => { setIsMoreMenuOpen(false); switchLogTab('rules'); }}
            title="Bans, Block & Allowlist Rules: Blocked IPs, Whitelists, URL Allowlist & Progressive Enforcement"
          >
            <Shield size={16} style={{ color: activeLogTab === 'rules' ? undefined : '#dc2626' }} />
            <span>Bans &amp; Allowlists</span>
          </button>
        </div>
      </div>

      {/* Action Notification Alert Bar */}
      {actionMessage && (
        <div className={`webcare-alert-banner ${actionMessage.type === 'error' ? 'webcare-alert-banner-error' : (actionMessage.type === 'success' ? 'webcare-alert-banner-success' : 'webcare-alert-banner-info')}`} style={{
          marginTop: '16px',
          padding: '12px 16px',
          borderRadius: '8px',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, overflow: 'hidden' }}>
            {actionMessage.type === 'error' ? <AlertTriangle size={16} style={{ flexShrink: 0 }} /> : <Check size={16} style={{ flexShrink: 0 }} />}
            <span style={{ wordBreak: 'break-word' }}>{formatActionMessage(actionMessage.text)}</span>
          </div>
          <button
            type="button"
            onClick={() => setActionMessage(null)}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'inherit',
              padding: '2px 4px',
              display: 'inline-flex',
              alignItems: 'center',
              borderRadius: '4px',
              opacity: 0.8
            }}
            title="Dismiss notification"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* 2. TAB CONTENT: LOCAL SERVER WAF LOGS */}
      {activeLogTab === 'local' && (
        <>
          {/* Real-Time Telemetry & Metric Cards (4 KPIs) */}
          <div className="webcare-waf-kpi-grid">
        {/* KPI 1: Total Intercepted */}
        <div className="webcare-waf-kpi-card">
          <div className="webcare-waf-kpi-card-inner">
            <div>
              <div className="webcare-waf-kpi-label">Total Incursions Blocked</div>
              <div className="webcare-waf-kpi-value" style={{ color: '#dc2626' }}>
                {stats?.total_intercepted !== undefined ? stats.total_intercepted.toLocaleString() : (loading ? '...' : totalCount.toLocaleString())}
              </div>
              <div className="webcare-waf-kpi-caption">Interceptions since installation</div>
            </div>
            <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-danger">
              <ShieldAlert size={22} />
            </div>
          </div>
        </div>

        {/* KPI 2: Past 24 Hours */}
        <div className="webcare-waf-kpi-card">
          <div className="webcare-waf-kpi-card-inner">
            <div>
              <div className="webcare-waf-kpi-label">Active Threat Surge (24h)</div>
              <div className="webcare-waf-kpi-value" style={{ color: '#ea580c' }}>
                {stats?.blocked_24h !== undefined ? stats.blocked_24h.toLocaleString() : (loading ? '...' : '0')}
              </div>
              <div className="webcare-waf-kpi-caption">Blocked in past 24 hours</div>
            </div>
            <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-orange">
              <Zap size={22} />
            </div>
          </div>
        </div>

        {/* KPI 3: Unique Offending IPs */}
        <div className="webcare-waf-kpi-card">
          <div className="webcare-waf-kpi-card-inner">
            <div>
              <div className="webcare-waf-kpi-label">Distinct Attack IPs</div>
              <div className="webcare-waf-kpi-value" style={{ color: '#4f46e5' }}>
                {stats?.unique_attack_ips !== undefined ? stats.unique_attack_ips.toLocaleString() : (loading ? '...' : '0')}
              </div>
              <div className="webcare-waf-kpi-caption">Hostile source IPs indexed</div>
            </div>
            <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-indigo">
              <Globe size={22} />
            </div>
          </div>
        </div>

        {/* KPI 4: Monitored / Learning */}
        <div className="webcare-waf-kpi-card">
          <div className="webcare-waf-kpi-card-inner">
            <div>
              <div className="webcare-waf-kpi-label">Simulation / Learning Mode</div>
              <div className="webcare-waf-kpi-value" style={{ color: '#0284c7' }}>
                {stats?.detected_learning !== undefined ? stats.detected_learning.toLocaleString() : '0'}
              </div>
              <div className="webcare-waf-kpi-caption">Probes monitored without drop</div>
            </div>
            <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-cyan">
              <Activity size={22} />
            </div>
          </div>
        </div>
      </div>

      {/* 3. Attack Analytics & Threat Breakdown Panels */}
      {stats && (stats.top_categories.length > 0 || stats.top_ips.length > 0) && (
        <div className="webcare-waf-analytics-grid">
          {/* Top Threat Vectors Card */}
          <div className="webcare-waf-panel-card">
            <div className="webcare-waf-panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <BarChart3 size={16} color="#4f46e5" />
                <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Top Attack Vectors Intercepted
                </h4>
              </div>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Categorical distribution</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {stats.top_categories.map((cat, idx) => {
                const total = stats.total_intercepted || 1;
                const percent = Math.min(100, Math.round((cat.count / total) * 100));
                return (
                  <div key={idx} style={{ fontSize: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontWeight: 600 }}>
                      <span style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{cat.rule_category}</span>
                      <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>{cat.count} blocks ({percent}%)</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--webcare-bg-surface, #e2e8f0)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${percent}%`,
                        background: idx === 0 ? '#dc2626' : (idx === 1 ? '#ea580c' : (idx === 2 ? '#4f46e5' : '#0284c7')),
                        borderRadius: '3px'
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top Attackers Directory Card */}
          <div className="webcare-waf-panel-card">
            <div className="webcare-waf-panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <TrendingUp size={16} color="#dc2626" />
                <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Frequent Offending IP Addresses
                </h4>
              </div>
              <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Repeat botnet probes</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto' }}>
              {stats.top_ips.map((ipItem, idx) => (
                <div key={idx} className="webcare-waf-ip-row" style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 700, color: '#dc2626', width: '22px' }}>#{idx + 1}</span>
                    <code style={{ fontWeight: 600, color: 'var(--webcare-text-code, #0284c7)' }}>{ipItem.ip_address}</code>
                    <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>({ipItem.primary_reason})</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="webcare-badge-pill webcare-badge-danger" style={{ fontSize: '11px' }}>
                      {ipItem.count} hits
                    </span>
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      onClick={() => {
                        setFilterIp(ipItem.ip_address);
                        setPage(1);
                      }}
                      title="Filter table by this IP"
                    >
                      Filter
                    </button>
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      onClick={(e) => handleBlockIp(ipItem.ip_address, e)}
                      title="Add to permanent blocklist"
                      style={{ color: '#dc2626' }}
                    >
                      Block
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. Filter Toolbar & Search Bar */}
      <div className="webcare-waf-toolbar-card">
        {/* 1-Click Quick-Filter Pills */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            flexWrap: 'wrap',
            paddingBottom: '12px',
            marginBottom: '12px',
            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
          }}
        >
          <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--webcare-text-muted, #64748b)', marginRight: '4px' }}>
            Quick Filter:
          </span>
          {[
            { id: 'all', label: 'All Incidents', count: stats?.total_incidents, icon: <Shield size={12} /> },
            { id: 'blocked', label: 'Blocked', count: stats?.blocked_today, icon: <ShieldAlert size={12} /> },
            { id: 'warned', label: 'Warned', count: undefined, icon: <AlertTriangle size={12} /> },
            { id: 'challenged', label: 'Challenged', count: undefined, icon: <Zap size={12} /> },
            { id: 'detected', label: 'Observed / Safe-Passed', count: undefined, icon: <ShieldCheck size={12} /> },
          ].map((pill) => {
            const isActive = selectedAction === pill.id;
            return (
              <button
                key={pill.id}
                type="button"
                onClick={() => {
                  setSelectedAction(pill.id);
                  setPage(1);
                }}
                className={`webcare-btn-micro ${isActive ? 'webcare-filter-pill-active' : ''}`}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '5px 12px',
                  borderRadius: '20px',
                  fontSize: '12px',
                  fontWeight: isActive ? 700 : 500,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  border: isActive
                    ? '1px solid var(--webcare-primary, #4f46e5)'
                    : '1px solid var(--webcare-border, #cbd5e1)',
                  background: isActive
                    ? 'var(--webcare-primary, #4f46e5)'
                    : 'var(--webcare-bg-card, #ffffff)',
                  color: isActive
                    ? '#ffffff'
                    : 'var(--webcare-text-primary, #0f172a)',
                }}
              >
                {pill.icon}
                <span>{pill.label}</span>
                {typeof pill.count === 'number' && (
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '1px 6px',
                      borderRadius: '10px',
                      background: isActive ? 'rgba(255, 255, 255, 0.25)' : 'var(--webcare-bg-surface, #f1f5f9)',
                      color: isActive ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
                      fontWeight: 700,
                    }}
                  >
                    {pill.count.toLocaleString()}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', justifyContent: 'space-between' }}>
          {/* Left search */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '260px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '380px' }}>
              <Search size={15} color="#94a3b8" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                placeholder="Search Incident ID, Support Code (WEBCARE-...), IP, Rule ID, or URI..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="webcare-input"
                style={{ paddingLeft: '32px', fontSize: '13px', width: '100%' }}
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8' }}
                >
                  ✕
                </button>
              )}
            </div>

            {/* Active IP filter chip */}
            {filterIp && (
              <span className="webcare-badge-pill webcare-badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <span>IP: <strong>{filterIp}</strong></span>
                <button
                  type="button"
                  onClick={() => setFilterIp('')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: '0 2px' }}
                >
                  ✕
                </button>
              </span>
            )}
          </div>

          {/* Right Select Dropdowns */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {/* Time Window Dropdown with Label */}
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748b', whiteSpace: 'nowrap' }}>Time Window:</span>
              <select
                id="webcare-waf-time-window-select"
                value={timeRange}
                onChange={(e) => {
                  const val = e.target.value as any;
                  setTimeRange(val);
                  if (val === 'daily' && !selectedDayFile && availableFiles.length > 0) {
                    setSelectedDayFile(availableFiles[0].filename);
                  }
                  setPage(1);
                }}
                className="webcare-input"
                style={{ fontSize: '12px', padding: '6px 10px', minWidth: '145px', fontWeight: 600 }}
                title="Filter WAF incidents by time range"
              >
                <option value="today">Today (Recent)</option>
                <option value="daily">Select Specific Day</option>
                <option value="7days">Last 7 Days</option>
                <option value="30days">Last 1 Month</option>
                <option value="6months">Last 6 Months</option>
                <option value="all">All Retained Logs</option>
              </select>
            </div>

            {/* Category Filter */}
            <select
              value={selectedCategory}
              onChange={(e) => {
                setSelectedCategory(e.target.value);
                setPage(1);
              }}
              className="webcare-input"
              style={{ fontSize: '12px', padding: '6px 10px', minWidth: '170px' }}
            >
              <option value="all">All Events &amp; Categories</option>
              <option value="authentication">🔐 All Authentication Events</option>
              <option value="auth_failed">❌ Failed Login Attempts</option>
              <option value="auth_success">✅ Successful Login Events</option>
              <option value="SQL Injection">SQL Injection</option>
              <option value="Cross-Site Scripting (XSS)">XSS Probes</option>
              <option value="Path Traversal & LFI">Path Traversal &amp; LFI</option>
              <option value="Remote Code / PHP Injection">PHP Execution Injections</option>
              <option value="Virtual Patch">Virtual Patch Exploits</option>
              <option value="Bad Bot & AI Scraper">Hostile Botnet &amp; Scraper</option>
              <option value="XML-RPC Disabled">XML-RPC Probes</option>
              <option value="Threat Intelligence">Botnet Reputation Match</option>
              <option value="404 Scanner Rate Limit">404 Scanner Rate Limit</option>
              <option value="Custom IP Blocklist">Custom Blocklist</option>
              <option value="targeted_allowlist">Targeted Allowlist Bypasses</option>
            </select>

            {/* Action Filter */}
            <select
              value={selectedAction}
              onChange={(e) => {
                setSelectedAction(e.target.value);
                setPage(1);
              }}
              className="webcare-input"
              style={{ fontSize: '12px', padding: '6px 10px' }}
            >
              <option value="all">All Actions</option>
              <option value="blocked">Blocked (Dropped / Failed)</option>
              <option value="allowed">Allowed (Logins &amp; Clean Bypass)</option>
              <option value="bypassed">Bypassed (IP Whitelist)</option>
              <option value="detected">Simulated (Learning)</option>
            </select>

            {/* HTTP Method */}
            <select
              value={selectedMethod}
              onChange={(e) => {
                setSelectedMethod(e.target.value);
                setPage(1);
              }}
              className="webcare-input"
              style={{ fontSize: '12px', padding: '6px 10px' }}
            >
              <option value="all">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
              <option value="TRACE">TRACE</option>
            </select>

            {/* HTTP Status Code Filter */}
            <select
              value={selectedStatusCode}
              onChange={(e) => {
                setSelectedStatusCode(e.target.value);
                setPage(1);
              }}
              className="webcare-input"
              style={{ fontSize: '12px', padding: '6px 10px' }}
            >
              <option value="all">All Status Codes</option>
              <option value="403">403 Forbidden</option>
              <option value="404">404 Rate Limited</option>
              <option value="405">405 Method Block</option>
              <option value="200">200 Simulated</option>
            </select>

            {/* Page Size */}
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="webcare-input"
              style={{ fontSize: '12px', padding: '6px 10px' }}
            >
              <option value={100}>100 rows</option>
              <option value={200}>200 rows</option>
              <option value={500}>500 rows</option>
            </select>

            {/* Clear All Filters */}
            {(searchQuery || selectedCategory !== 'all' || selectedAction !== 'all' || selectedMethod !== 'all' || selectedStatusCode !== 'all' || filterIp) && (
              <button
                type="button"
                className="webcare-btn-micro"
                onClick={() => {
                  setSearchQuery('');
                  setSelectedCategory('all');
                  setSelectedAction('all');
                  setSelectedMethod('all');
                  setSelectedStatusCode('all');
                  setFilterIp('');
                  setPage(1);
                }}
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>

        {/* Specific Day Partition Picker (Sub-row when 'daily' is selected) */}
        {timeRange === 'daily' && (
          <div style={{
            marginTop: '12px',
            paddingTop: '12px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                Select Daily Partition File:
              </span>
              <select
                value={selectedDayFile}
                onChange={(e) => {
                  setSelectedDayFile(e.target.value);
                  setPage(1);
                }}
                className="webcare-input"
                style={{ fontSize: '12px', padding: '5px 10px', minWidth: '240px' }}
              >
                {availableFiles.length === 0 ? (
                  <option value="">No daily JSON log files created yet</option>
                ) : (
                  availableFiles.map((f, idx) => (
                    <option key={idx} value={f.filename}>
                      {f.filename} ({f.size_human})
                    </option>
                  ))
                )}
              </select>
            </div>
            {selectedDayFile && (
              <button
                type="button"
                className="webcare-btn-micro"
                onClick={() => handleDownloadFile(selectedDayFile)}
                title="Download this day's complete JSON log file"
                style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#4f46e5' }}
              >
                <Download size={13} /> Download {selectedDayFile}
              </button>
            )}
          </div>
        )}

        {/* Bulk Action Controls */}
        {selectedLogIds.length > 0 && (
          <div style={{
            marginTop: '12px',
            padding: '8px 12px',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            border: '1px solid var(--webcare-border, #e2e8f0)',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px'
          }}>
            <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
              {selectedLogIds.length} incident record{selectedLogIds.length > 1 ? 's' : ''} selected
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="button"
                className="webcare-btn webcare-btn-danger-soft"
                style={{ fontSize: '12px', padding: '4px 10px' }}
                onClick={handleBulkDeleteSelected}
              >
                <Trash2 size={13} /> Delete Selected
              </button>
              <button
                type="button"
                className="webcare-btn-micro"
                onClick={() => setSelectedLogIds([])}
              >
                Deselect All
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 5. Main WAF Incident Log Table */}
      <div className="webcare-waf-table-card">
        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
            <Activity size={36} className="webcare-spin-icon" style={{ margin: '0 auto 12px auto', color: '#4f46e5' }} />
            <div style={{ fontSize: '14px', fontWeight: 600 }}>Querying WAF incident forensic database...</div>
            <div style={{ fontSize: '12px', marginTop: '4px' }}>Aggregating payload signatures and client telemetry</div>
          </div>
        ) : logs.length === 0 ? (
          <EmptyStateCard
            icon={ShieldCheck}
            title={selectedAction !== 'all' || searchQuery || selectedCategory !== 'all' || filterIp || selectedMethod !== 'all' || selectedStatusCode !== 'all'
              ? 'No Incident Logs Match Criteria'
              : 'All quiet — no blocked requests match your filters.'}
            description={selectedAction !== 'all' || searchQuery || selectedCategory !== 'all' || filterIp || selectedMethod !== 'all' || selectedStatusCode !== 'all'
              ? 'No events match your active search keyword or filter pills. Try resetting your filters to view historic entries.'
              : 'Zero malicious probes intercepted. Your server application perimeter is clean and actively monitoring web traffic.'}
            badge="Perimeter Clean"
            badgeType="clean"
            actionLabel={(selectedAction !== 'all' || searchQuery || selectedCategory !== 'all' || filterIp || selectedMethod !== 'all' || selectedStatusCode !== 'all') ? 'Reset All Filters' : undefined}
            onAction={() => {
              setSelectedAction('all');
              setSearchQuery('');
              setSelectedCategory('all');
              setSelectedMethod('all');
              setSelectedStatusCode('all');
              setFilterIp('');
              setPage(1);
            }}
            actionIcon={RefreshCw}
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--webcare-border, #e2e8f0)' }}>
                  <th style={{ padding: '10px 12px', width: '36px' }}>
                    <input
                      type="checkbox"
                      checked={selectedLogIds.length === logs.length && logs.length > 0}
                      onChange={handleToggleSelectAll}
                      title="Select / Deselect All on page"
                    />
                  </th>
                  {visibleColumns.timestamp && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('created_at')}
                      title="Sort by Timestamp"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Timestamp</span>
                        {sortBy === 'created_at' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.status_code && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('http_status_code')}
                      title="Sort by HTTP Status Code"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>HTTP Status</span>
                        {sortBy === 'http_status_code' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.ip && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('ip_address')}
                      title="Sort by Client IP"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Client IP</span>
                        {sortBy === 'ip_address' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.user && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('username')}
                      title="Sort by WordPress User"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>WP User</span>
                        {sortBy === 'username' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.category && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('rule_category')}
                      title="Sort by Attack Category"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Attack Vector / Category</span>
                        {sortBy === 'rule_category' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.uri && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('request_uri')}
                      title="Sort by Target URI"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Target URI Endpoint</span>
                        {sortBy === 'request_uri' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.method && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('request_method')}
                      title="Sort by HTTP Method"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Method</span>
                        {sortBy === 'request_method' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.referer && <th style={{ padding: '10px 12px' }}>HTTP Referer</th>}
                  {visibleColumns.user_agent && <th style={{ padding: '10px 12px' }}>User-Agent</th>}
                  {visibleColumns.action && (
                    <th
                      style={{ padding: '10px 12px', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => handleSort('action_taken')}
                      title="Sort by Action Taken"
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <span>Action Taken</span>
                        {sortBy === 'action_taken' && (
                          <span style={{ fontSize: '10px', color: '#4f46e5' }}>{sortOrder === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {visibleColumns.controls && <th style={{ padding: '10px 12px', textAlign: 'right' }}>Forensic Controls</th>}
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const isExpanded = expandedLogId === log.id;
                  const isSelected = selectedLogIds.includes(log.id);
                  const statusCode = log.http_status_code || (log.action_taken === 'detected' ? 200 : (log.rule_category === '404 Scanner Rate Limit' ? 404 : 403));
                  
                  // Count total active columns for colSpan calculation
                  const visibleColCount = 1 + Object.values(visibleColumns).filter(Boolean).length;

                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        style={{
                          borderBottom: isExpanded ? 'none' : '1px solid var(--webcare-border, #f1f5f9)',
                          background: isSelected ? 'rgba(79, 70, 229, 0.04)' : undefined,
                          cursor: 'pointer'
                        }}
                        onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                      >
                        {/* Checkbox */}
                        <td style={{ padding: '10px 12px' }} onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleToggleSelectLog(log.id)}
                          />
                        </td>

                        {/* Timestamp */}
                        {visibleColumns.timestamp && (
                          <td style={{ padding: '10px 12px', whiteSpace: 'nowrap', color: 'var(--webcare-text-muted, #64748b)', fontSize: '12px' }} title={formatTelemetryDateFull(log.created_at_gmt || log.created_at) || log.created_at}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <Clock size={13} />
                              <span style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                {formatRelativeTime(log.created_at_gmt ? (log.created_at_gmt.endsWith('Z') ? log.created_at_gmt : `${log.created_at_gmt}Z`) : (log.timestamp ? new Date(log.timestamp * 1000) : log.created_at))}
                              </span>
                              <span style={{ fontSize: '11px', opacity: 0.75 }}>({log.created_at})</span>
                            </div>
                          </td>
                        )}

                        {/* HTTP Status Code */}
                        {visibleColumns.status_code && (
                          <td style={{ padding: '10px 12px' }}>
                            <span className={`webcare-badge-pill ${statusCode === 403 ? 'webcare-badge-danger' : (statusCode === 404 ? 'webcare-badge-warn' : (statusCode === 405 ? 'webcare-badge-purple' : 'webcare-badge-info'))}`} style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 800,
                              fontFamily: 'monospace'
                            }}>
                              <span>{statusCode}</span>
                              <span style={{ fontSize: '9px', fontWeight: 600, opacity: 0.85 }}>
                                {statusCode === 403 ? 'FORBIDDEN' : (statusCode === 404 ? 'NOT FOUND' : (statusCode === 405 ? 'METHOD BLOCKED' : 'OK'))}
                              </span>
                            </span>
                          </td>
                        )}

                        {/* Client IP */}
                        {visibleColumns.ip && (
                          <td style={{ padding: '10px 12px' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '3px' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <code style={{
                                  fontWeight: 700,
                                  fontSize: '12px',
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  color: 'var(--webcare-text-code, #0284c7)',
                                  background: 'var(--webcare-bg-surface, #f1f5f9)'
                                }}>
                                  {log.ip_address}
                                </code>
                                <button
                                  type="button"
                                  className="webcare-btn-micro"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyToClipboard(log.ip_address, `ip_${log.id}`);
                                  }}
                                  title="Copy IP address"
                                >
                                  {copiedKey === `ip_${log.id}` ? <Check size={11} color="#10b981" /> : <Copy size={11} />}
                                </button>
                              </div>

                              {/* Active Enforcement / Cloudflare Ban Indicator (Last Hit Only) */}
                              {log.is_last_hit_for_ip && log.is_banned && (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
                                  {(log.ban_scope === 'edge_synced' || log.cf_synced) ? (
                                    <span
                                      className="webcare-badge-pill webcare-badge-warn"
                                      style={{
                                        fontSize: '9px',
                                        padding: '1px 6px',
                                        fontWeight: 800,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '3px'
                                      }}
                                      title="Terminal recorded hit: IP ban is synchronized and actively enforced at Cloudflare Anycast Edge & Local Origin WAF"
                                    >
                                      <Cloud size={9} /> CF BAN
                                    </span>
                                  ) : (log.ban_scope === 'edge_queued' || log.cf_queued) ? (
                                    <span
                                      className="webcare-badge-pill webcare-badge-info"
                                      style={{
                                        fontSize: '9px',
                                        padding: '1px 6px',
                                        fontWeight: 800,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '3px'
                                      }}
                                      title="Terminal recorded hit: IP is banned locally and queued for immediate Cloudflare Edge synchronization"
                                    >
                                      <Cloud size={9} /> BANNED • CF SYNCING
                                    </span>
                                  ) : (
                                    <span
                                      className="webcare-badge-pill webcare-badge-danger"
                                      style={{
                                        fontSize: '9px',
                                        padding: '1px 5px',
                                        fontWeight: 800,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '3px'
                                      }}
                                      title="Terminal recorded hit: IP is actively banned locally on Origin Server WAF"
                                    >
                                      <ShieldAlert size={9} /> BANNED
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          </td>
                        )}

                        {/* WP User Account (if authenticated or attempted username) */}
                        {visibleColumns.user && (
                          <td style={{ padding: '10px 12px' }}>
                            {log.username ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <span className={`webcare-badge-pill ${log.is_authenticated ? 'webcare-badge-info' : 'webcare-badge-muted'}`} style={{
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  padding: '2px 6px'
                                }}>
                                  {log.username} {log.user_id ? `(#${log.user_id})` : ''}
                                </span>
                                {log.user_role && (
                                  <span style={{ fontSize: '10px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                    ({log.user_role})
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #94a3b8)' }}>Guest</span>
                            )}
                          </td>
                        )}

                        {/* Category */}
                        {visibleColumns.category && (() => {
                          const cat = log.rule_category.toLowerCase();
                          const isVPatch = cat.includes('patch') || cat.includes('cve');
                          const isSQL = cat.includes('sql');
                          const isXSS = cat.includes('xss');
                          const isTraversal = cat.includes('traversal');
                          const isPHP = cat.includes('php') || cat.includes('execution');
                          const isBot = cat.includes('bot');
                          const isIdentity = cat.includes('identity');
                          const isAuth = cat.includes('auth');

                          let label = log.rule_category;
                          if (isVPatch) label = 'Virtual Patch (CVE Shield)';
                          else if (isSQL) label = 'SQL Injection';
                          else if (isXSS) label = 'Cross-Site Scripting (XSS)';
                          else if (isTraversal) label = 'Path Traversal';
                          else if (isPHP) label = 'PHP Injection Armor';
                          else if (isBot) label = 'Botnet / Recon Defense';
                          else if (isIdentity) label = 'Identity & Honeypot Trap';
                          else if (isAuth) {
                            label = log.action_taken === 'allowed' ? 'User Login (Success)' : 'Auth Attempt (Failed)';
                          }

                          const badgeClass = isVPatch
                            ? 'webcare-badge-info'
                            : (isSQL || isPHP)
                            ? 'webcare-badge-danger'
                            : (isXSS || isTraversal)
                            ? 'webcare-badge-high'
                            : (isAuth ? (log.action_taken === 'allowed' ? 'webcare-badge-clean' : 'webcare-badge-danger') : 'webcare-badge-muted');

                          return (
                            <td style={{ padding: '10px 12px' }}>
                              <span className={`webcare-badge-pill ${badgeClass}`} style={{
                                padding: '3px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px'
                              }}>
                                {isVPatch && <Shield size={11} />}
                                {isAuth && (log.action_taken === 'allowed' ? <CheckCircle2 size={11} /> : <Lock size={11} />)}
                                <span>{label}</span>
                              </span>
                            </td>
                          );
                        })()}

                        {/* Target URI */}
                        {visibleColumns.uri && (
                          <td style={{ padding: '10px 12px', maxWidth: '320px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span className={`webcare-badge-pill ${log.request_method === 'POST' ? 'webcare-badge-warn' : 'webcare-badge-info'}`} style={{
                                fontSize: '10px',
                                fontWeight: 800,
                                padding: '1px 5px',
                                borderRadius: '3px'
                              }}>
                                {log.request_method}
                              </span>
                              <span
                                style={{
                                  fontFamily: 'monospace',
                                  fontSize: '12px',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                  color: 'var(--webcare-text-primary, #0f172a)'
                                }}
                                title={log.request_uri}
                              >
                                {log.request_uri}
                              </span>
                            </div>
                          </td>
                        )}

                        {/* Standalone HTTP Method Column (if enabled) */}
                        {visibleColumns.method && (
                          <td style={{ padding: '10px 12px' }}>
                            <span className={`webcare-badge-pill ${log.request_method === 'POST' ? 'webcare-badge-warn' : 'webcare-badge-info'}`} style={{
                              fontSize: '11px',
                              fontWeight: 800,
                              fontFamily: 'monospace',
                              padding: '2px 6px',
                              borderRadius: '4px'
                            }}>
                              {log.request_method}
                            </span>
                          </td>
                        )}

                        {/* HTTP Referer Column (if enabled) */}
                        {visibleColumns.referer && (
                          <td style={{ padding: '10px 12px', maxWidth: '220px' }}>
                            <span
                              style={{
                                fontSize: '12px',
                                color: log.http_referer ? 'var(--webcare-text-secondary, #475569)' : 'var(--webcare-text-muted, #94a3b8)',
                                fontStyle: log.http_referer ? 'normal' : 'italic',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                display: 'block'
                              }}
                              title={log.http_referer || 'Direct connection (No referer)'}
                            >
                              {log.http_referer || 'Direct / None'}
                            </span>
                          </td>
                        )}

                        {/* User-Agent Column (if enabled) */}
                        {visibleColumns.user_agent && (
                          <td style={{ padding: '10px 12px', maxWidth: '240px' }}>
                            <span
                              style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                color: 'var(--webcare-text-secondary, #475569)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                display: 'block'
                              }}
                              title={log.user_agent || 'Missing / Socket'}
                            >
                              {log.user_agent || 'None / Raw Socket'}
                            </span>
                          </td>
                        )}

                        {/* Action Taken */}
                        {visibleColumns.action && (
                          <td style={{ padding: '10px 12px' }}>
                            {isSimpleMode ? (
                              <span
                                className={`webcare-badge-pill ${
                                  log.action_taken === 'blocked' || log.is_banned
                                    ? 'webcare-badge-danger'
                                    : log.action_taken === 'warned'
                                    ? 'webcare-badge-warn'
                                    : log.action_taken === 'challenged'
                                    ? 'webcare-badge-info'
                                    : 'webcare-badge-clean'
                                }`}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '3px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                }}
                              >
                                {log.action_taken === 'blocked' || log.is_banned ? (
                                  <>
                                    <ShieldAlert size={12} />
                                    <span>Blocked</span>
                                  </>
                                ) : log.action_taken === 'warned' ? (
                                  <>
                                    <AlertTriangle size={12} />
                                    <span>Warning Sent</span>
                                  </>
                                ) : log.action_taken === 'challenged' ? (
                                  <>
                                    <Zap size={12} />
                                    <span>Browser Check</span>
                                  </>
                                ) : (
                                  <>
                                    <CheckCircle2 size={12} />
                                    <span>Allowed Safely</span>
                                  </>
                                )}
                              </span>
                            ) : log.is_last_hit_for_ip && log.action_taken === 'blocked' && log.is_banned && (log.cf_synced || log.ban_scope === 'edge_synced') ? (
                              <span
                                className="webcare-badge-pill webcare-badge-danger"
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 800,
                                  textTransform: 'uppercase'
                                }}
                                title="Terminal recorded hit from this IP. Active IP ban is synchronized to Cloudflare Edge."
                              >
                                <Cloud size={12} />
                                <span>CF Ban</span>
                              </span>
                            ) : log.is_last_hit_for_ip && log.action_taken === 'blocked' && log.is_banned && (log.cf_queued || log.ban_scope === 'edge_queued') ? (
                              <span
                                className="webcare-badge-pill webcare-badge-danger"
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 800,
                                  textTransform: 'uppercase'
                                }}
                                title="Blocked & banned locally. Synchronizing IP ban to Cloudflare Edge in background."
                              >
                                <Cloud size={12} />
                                <span>Blocked (CF Syncing)</span>
                              </span>
                            ) : log.is_last_hit_for_ip && log.is_banned ? (
                              <span
                                className="webcare-badge-pill webcare-badge-danger"
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 800,
                                  textTransform: 'uppercase'
                                }}
                                title="Terminal recorded hit from this IP. Active IP ban enforced on Origin WAF."
                              >
                                <ShieldAlert size={12} />
                                <span>Blocked (Local Ban)</span>
                              </span>
                            ) : (
                              <span className={`webcare-badge-pill ${
                                log.action_taken === 'blocked'
                                  ? 'webcare-badge-danger'
                                  : (log.action_taken === 'bypassed'
                                    ? 'webcare-badge-info'
                                    : (log.action_taken === 'allowed' ? 'webcare-badge-clean' : 'webcare-badge-warn'))
                              }`} style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 800,
                                textTransform: 'uppercase'
                              }}>
                                {log.action_taken === 'blocked' ? (
                                  <ShieldAlert size={12} />
                                ) : (log.action_taken === 'bypassed' ? (
                                  <ShieldCheck size={12} color="#4f46e5" />
                                ) : (log.action_taken === 'allowed' ? (
                                  <CheckCircle2 size={12} />
                                ) : (
                                  <Activity size={12} />
                                )))}
                                <span>{log.action_taken === 'bypassed' ? 'BYPASSED' : log.action_taken}</span>
                              </span>
                            )}
                          </td>
                        )}

                        {/* Forensic Controls */}
                        {visibleColumns.controls && (
                          <td style={{ padding: '10px 12px', textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                                style={{ fontWeight: 600 }}
                              >
                                {isExpanded ? 'Hide Payload' : 'Inspect'}
                                {isExpanded ? <ChevronUp size={12} style={{ marginLeft: '2px' }} /> : <ChevronDown size={12} style={{ marginLeft: '2px' }} />}
                              </button>
                              {currentClientIp && log.ip_address === currentClientIp ? (
                                <span
                                  className="webcare-btn-micro"
                                  title="Safety Guard: This is your active administrator connection. You cannot block your own IP to prevent site lockout."
                                  style={{ color: '#94a3b8', cursor: 'not-allowed', opacity: 0.6 }}
                                >
                                  Your IP
                                </span>
                              ) : log.is_banned ? (
                                <span
                                  className="webcare-btn-micro"
                                  style={{
                                    color: (log.ban_scope === 'edge_synced' || log.cf_synced) ? '#ea580c' : '#dc2626',
                                    fontWeight: 700,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '3px',
                                    opacity: 0.9
                                  }}
                                  title={(log.ban_scope === 'edge_synced' || log.cf_synced) ? 'IP actively banned at Cloudflare Edge & Origin WAF' : 'IP actively banned on Origin WAF'}
                                >
                                  {(log.ban_scope === 'edge_synced' || log.cf_synced) ? <Cloud size={10} /> : <ShieldAlert size={10} />}
                                  Banned
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  className="webcare-btn-micro"
                                  onClick={() => handleBlockIp(log.ip_address)}
                                  title="Add IP to custom blocklist"
                                  style={{ color: '#dc2626' }}
                                >
                                  Block IP
                                </button>
                              )}
                              {log.rule_category === 'Custom IP Blocklist' ? (
                                <button
                                  type="button"
                                  className="webcare-btn-micro"
                                  onClick={() => handleUnblockIp(log.ip_address)}
                                  title="Remove from blocklist and restore normal visitor access (Firewall rules remain active)"
                                  style={{ color: '#0284c7', fontWeight: 600 }}
                                >
                                  Unblock
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  className="webcare-btn-micro webcare-action-btn-clean"
                                  onClick={(e) => openAllowlistModal(log, e)}
                                  title="Configure granular rule allowlist or bypass for this IP"
                                  style={{ color: '#16a34a', fontWeight: 600 }}
                                >
                                  Allow
                                </button>
                              )}
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  const rawUri = (log.request_uri || '').split('?')[0] || '/';
                                  const conds: any[] = [
                                    { field: 'http.request.uri.path', op: 'eq', value: rawUri },
                                  ];
                                  if (log.method) {
                                    conds.push({ field: 'http.request.method', op: 'eq', value: log.method });
                                  }
                                  if (log.user_agent) {
                                    conds.push({ field: 'http.user_agent', op: 'contains', value: log.user_agent.slice(0, 60) });
                                  }
                                  try {
                                    sessionStorage.setItem(
                                      'webcare_visual_rule_draft',
                                      JSON.stringify({
                                        title: `Block probe to ${rawUri}`,
                                        description: `Synthesized from WAF Incident (${log.rule_id || 'WAF'}) by IP ${log.ip_address}`,
                                        action_type: 'block_and_ban',
                                        ban_ttl: 86400,
                                        sync_cloudflare: true,
                                        conditions: [{ logic: 'AND', rules: conds }],
                                      })
                                    );
                                  } catch {}
                                  window.location.href = 'admin.php?page=webcare-pro-firewall&tab=custom-waf-rules';
                                }}
                                title="Create Custom Firewall Rule from this request"
                                style={{ color: 'var(--webcare-primary, #4f46e5)', fontWeight: 700 }}
                              >
                                + Rule
                              </button>
                              <button
                                type="button"
                                className="webcare-btn-micro"
                                onClick={(e) => handleDeleteSingleLog(log.id, e)}
                                title="Delete log record"
                                style={{ color: '#94a3b8' }}
                              >
                                <Trash2 size={13} />
                              </button>
                            </div>
                          </td>
                        )}
                      </tr>

                      {/* Expandable Forensic Deep-Dive Accordion Row */}
                      {isExpanded && (() => {
                        const forensics = analyzeIncidentForensics(log);
                        return (
                        <tr className="webcare-waf-expanded-row">
                          <td colSpan={visibleColCount} style={{ padding: '16px 20px' }}>
                            <div className="webcare-waf-forensic-accordion">
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                  <FileCode size={16} color="#4f46e5" />
                                  <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                    Payload Signature &amp; Request Telemetry (#{log.id})
                                  </strong>
                                  {log.incident_id && (
                                    <span style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '2px 8px',
                                      borderRadius: '4px',
                                      fontSize: '11px',
                                      fontWeight: 700,
                                      fontFamily: 'monospace',
                                      background: 'rgba(79, 70, 229, 0.08)',
                                      color: '#4f46e5',
                                      border: '1px solid rgba(79, 70, 229, 0.2)'
                                    }}>
                                      <span>Incident ID: <strong>{log.incident_id}</strong></span>
                                      <button
                                        type="button"
                                        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'inline-flex', alignItems: 'center' }}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          copyToClipboard(log.incident_id || '', `inc_${log.id}`);
                                        }}
                                        title="Copy Incident ID"
                                      >
                                        {copiedKey === `inc_${log.id}` ? <Check size={11} color="#10b981" /> : <Copy size={11} color="#4f46e5" />}
                                      </button>
                                    </span>
                                  )}
                                  {log.ref_code && (
                                    <span className="webcare-badge-pill webcare-badge-info" style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '2px 8px',
                                      borderRadius: '4px',
                                      fontSize: '11px',
                                      fontWeight: 700,
                                      fontFamily: 'monospace'
                                    }}>
                                      <span>Support Code: <strong>{log.ref_code}</strong></span>
                                      <button
                                        type="button"
                                        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'inline-flex', alignItems: 'center' }}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          copyToClipboard(log.ref_code || '', `ref_${log.id}`);
                                        }}
                                        title="Copy Support Reference Code"
                                      >
                                        {copiedKey === `ref_${log.id}` ? <Check size={11} color="#10b981" /> : <Copy size={11} color="#0284c7" />}
                                      </button>
                                    </span>
                                  )}
                                  <span className={`webcare-badge-pill ${forensics.badgeClass}`} style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px' }}>
                                    {forensics.severity} Threat
                                  </span>
                                  <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', background: 'var(--webcare-bg-surface, #f1f5f9)', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
                                    Engine: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{forensics.engine}</strong>
                                  </span>
                                </div>
                                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                                  <button
                                    type="button"
                                    className="webcare-btn-micro"
                                    onClick={() => copyToClipboard(JSON.stringify(log, null, 2), `json_${log.id}`)}
                                  >
                                    {copiedKey === `json_${log.id}` ? 'Copied JSON!' : 'Copy Incident JSON'}
                                  </button>
                                  <button
                                    type="button"
                                    className="webcare-btn-micro"
                                    onClick={() => {
                                      setFilterIp(log.ip_address);
                                      setPage(1);
                                    }}
                                  >
                                    Filter All Hits from {log.ip_address}
                                  </button>
                                </div>
                              </div>

                              {/* "Was This a Real Customer?" Guided Recovery Card */}
                              {(() => {
                                const ua = (log.user_agent || '').toLowerCase();
                                const uri = (log.request_uri || '').toLowerCase();
                                const isShop = uri.includes('cart') || uri.includes('checkout') || uri.includes('wc-ajax') || uri.includes('shop') || uri.includes('my-account');
                                const isSearchEngine = ua.includes('googlebot') || ua.includes('bingbot') || ua.includes('duckduckbot') || ua.includes('yandex') || ua.includes('baiduspider');
                                const isKnownBot = isSearchEngine || ua.includes('bot') || ua.includes('spider') || ua.includes('crawler') || ua.includes('curl') || ua.includes('python');

                                let visitorType = 'Unknown Automated Client / Guest';
                                let visitorIcon = <Bot size={16} color="#64748b" />;
                                let visitorDesc = 'Unauthenticated client browsing store assets.';

                                if (log.is_authenticated || log.username) {
                                  visitorType = `Logged-in User (${log.username || 'Authenticated'})`;
                                  visitorIcon = <UserCheck size={16} color="#10b981" />;
                                  visitorDesc = `Verified registered WordPress user${log.user_role ? ` (${log.user_role})` : ''}.`;
                                } else if (isShop) {
                                  visitorType = 'Active WooCommerce Shopper';
                                  visitorIcon = <ShoppingBag size={16} color="#4f46e5" />;
                                  visitorDesc = 'Visitor attempting store actions (cart, checkout, or account).';
                                } else if (isSearchEngine) {
                                  visitorType = 'Claims to be Search Engine (unverified)';
                                  visitorIcon = <Globe size={16} color="#0284c7" />;
                                  visitorDesc = 'User-Agent indicates crawler, but remote IP is not verified.';
                                } else if (!isKnownBot) {
                                  visitorType = 'Human Browser / Potential Customer';
                                  visitorIcon = <HelpCircle size={16} color="#f59e0b" />;
                                  visitorDesc = 'Standard desktop or mobile browser requesting site pages.';
                                }

                                const isZeroToleranceExploit = forensics.severity === 'Critical' && (
                                  forensics.attackType.includes('SQL') ||
                                  forensics.attackType.includes('RCE') ||
                                  forensics.attackType.includes('Command') ||
                                  forensics.attackType.includes('Traversal')
                                );

                                return (
                                  <div style={{
                                    padding: '14px 16px',
                                    borderRadius: '8px',
                                    background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                                    border: '1px solid var(--webcare-border, #e2e8f0)',
                                    marginBottom: '14px'
                                  }}>
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <HelpCircle size={16} color="#4f46e5" />
                                        <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                          Was this a real customer?
                                        </strong>
                                        <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                          Guided Incident Review &amp; Safe 1-Click Recovery
                                        </span>
                                      </div>
                                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>
                                        {visitorIcon}
                                        <span>{visitorType}</span>
                                      </div>
                                    </div>

                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '12px', fontSize: '12px' }}>
                                      <div style={{ lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)' }}>
                                        <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '3px' }}>
                                          Visitor &amp; Intent:
                                        </div>
                                        <div>{visitorDesc}</div>
                                        <div style={{ marginTop: '4px' }}>
                                          <strong>Target URI:</strong> <code style={{ fontSize: '11px' }}>{(log.request_uri || '').split('?')[0] || '/'}</code>
                                        </div>
                                      </div>

                                      <div style={{ lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)' }}>
                                        <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '3px' }}>
                                          What happened:
                                        </div>
                                        <div>{forensics.plainEnglish}</div>
                                        <div style={{ marginTop: '4px' }}>
                                          <strong>Trigger:</strong> <span>{log.rule_name || log.rule_category}</span>
                                        </div>
                                      </div>
                                    </div>

                                    {/* 1-Click Recovery Action Buttons */}
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', paddingTop: '10px', borderTop: '1px solid var(--webcare-border, #e2e8f0)' }}>
                                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                        {isZeroToleranceExploit ? (
                                          <span style={{ color: '#dc2626', fontWeight: 600 }}>
                                            ⚠️ Confirmed SQLi/RCE exploit pattern detected. Scoped exemption disabled; temporary unblock will still challenge exploits.
                                          </span>
                                        ) : (
                                          <span>
                                            🛡️ Scoped exemption creates a safe route-and-param rule. Core SQLi/RCE zero-tolerance protection remains 100% active.
                                          </span>
                                        )}
                                      </div>

                                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                        <button
                                          type="button"
                                          className="webcare-btn-micro"
                                          onClick={(e) => handleUnblockIp(log.ip_address, e, 900)}
                                          style={{
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: '5px',
                                            fontWeight: 700,
                                            padding: '5px 10px',
                                            background: 'rgba(16, 185, 129, 0.1)',
                                            color: '#059669',
                                            border: '1px solid rgba(16, 185, 129, 0.3)'
                                          }}
                                          title="Unblock this IP address for 15 minutes to let the customer finish checkout or verify access"
                                        >
                                          <Clock size={12} />
                                          Temporarily Unblock IP (15 min)
                                        </button>

                                        {!isZeroToleranceExploit && (
                                          <button
                                            type="button"
                                            className="webcare-btn-micro"
                                            onClick={() => handleTrustCustomerAction(log)}
                                            disabled={allowingTarget === `${(log.request_uri || '').split('?')[0] || '/'}:${log.matched_param_key || log.rule_id || ''}`}
                                            style={{
                                              display: 'inline-flex',
                                              alignItems: 'center',
                                              gap: '5px',
                                              fontWeight: 700,
                                              padding: '5px 10px',
                                              background: 'rgba(79, 70, 229, 0.1)',
                                              color: '#4f46e5',
                                              border: '1px solid rgba(79, 70, 229, 0.3)'
                                            }}
                                            title="Trust this specific customer action permanently across its URI and parameter without lowering SQLi/RCE defenses"
                                          >
                                            {allowingTarget === `${(log.request_uri || '').split('?')[0] || '/'}:${log.matched_param_key || log.rule_id || ''}` ? (
                                              <Loader2 size={12} className="webcare-spin" />
                                            ) : (
                                              <ShieldCheck size={12} />
                                            )}
                                            Trust This Customer Action
                                          </button>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })()}

                              {/* Plain-English Incident Analysis Banner for WP Admins & Non-Technical Users */}
                              <div style={{
                                padding: '12px 14px',
                                borderRadius: '8px',
                                background: 'rgba(79, 70, 229, 0.04)',
                                border: '1px solid rgba(79, 70, 229, 0.18)',
                                marginBottom: '14px',
                                display: 'flex',
                                alignItems: 'flex-start',
                                gap: '10px'
                              }}>
                                <Info size={16} color="#4f46e5" style={{ flexShrink: 0, marginTop: '2px' }} />
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ fontSize: '12px', fontWeight: 700, color: '#4f46e5', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
                                    Security Analysis: {forensics.attackType}
                                  </div>
                                  <div style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', lineHeight: 1.5 }}>
                                    {forensics.plainEnglish}
                                  </div>
                                </div>
                              </div>

                              {/* Cloudflare Edge & Origin Enforcement Status Strip */}
                              <div style={{
                                padding: '10px 14px',
                                borderRadius: '8px',
                                background: (log.ban_scope === 'edge_synced' || log.cf_synced)
                                  ? 'rgba(249, 115, 22, 0.05)'
                                  : log.is_banned
                                    ? 'rgba(239, 68, 68, 0.04)'
                                    : 'var(--webcare-bg-surface-elevated, #f8fafc)',
                                border: `1px solid ${(log.ban_scope === 'edge_synced' || log.cf_synced)
                                  ? 'rgba(249, 115, 22, 0.25)'
                                  : log.is_banned
                                    ? 'rgba(239, 68, 68, 0.2)'
                                    : 'var(--webcare-border, #e2e8f0)'}`,
                                marginBottom: '14px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                flexWrap: 'wrap',
                                gap: '10px'
                              }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  {(log.ban_scope === 'edge_synced' || log.cf_synced) ? (
                                    <Cloud size={16} color="#ea580c" />
                                  ) : log.is_banned ? (
                                    <ShieldAlert size={16} color="#dc2626" />
                                  ) : (
                                    <ShieldCheck size={16} color="#10b981" />
                                  )}
                                  <div>
                                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                      {(log.ban_scope === 'edge_synced' || log.cf_synced)
                                        ? 'Enforced at Cloudflare Anycast Edge & Origin Server'
                                        : log.is_banned
                                          ? 'Enforced on Origin Server WAF Only (Not Synced to Cloudflare Edge)'
                                          : 'Origin WAF Monitored (Not Blocklisted)'}
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                      Cloudflare Auto-Ban Sync: <strong style={{ color: log.cf_sync_enabled ? '#10b981' : '#64748b' }}>{log.cf_sync_enabled ? 'Active / Enabled' : 'Disabled'}</strong>
                                      {log.cf_connected && ' • Edge API: Connected'}
                                      {log.ban_meta?.reason && ` • Reason: ${log.ban_meta.reason}`}
                                    </div>
                                  </div>
                                </div>

                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  {log.is_banned && !(log.ban_scope === 'edge_synced' || log.cf_synced) && log.cf_connected && (
                                    <button
                                      type="button"
                                      className="webcare-btn-micro"
                                      style={{
                                        background: '#ea580c',
                                        color: '#ffffff',
                                        border: 'none',
                                        fontWeight: 700,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '4px',
                                        padding: '4px 8px'
                                      }}
                                      onClick={async () => {
                                        try {
                                          const res = await apiRequest({
                                            path: '/cloudflare/sync-ip',
                                            method: 'POST',
                                            body: { ip: log.ip_address, reason: `WAF Incident: ${log.rule_name || log.rule_category}` }
                                          });
                                          if (res && res.success) {
                                            setActionMessage({ type: 'success', text: `IP ${log.ip_address} successfully pushed to Cloudflare Edge!` });
                                            toast.success(`IP ${log.ip_address} successfully pushed to Cloudflare Edge!`);
                                            loadLogs();
                                          } else {
                                            toast.error(res?.message || 'Failed to sync IP to Cloudflare Edge.');
                                          }
                                        } catch (e: any) {
                                          toast.error(e?.message || 'Error syncing to Cloudflare.');
                                        }
                                      }}
                                    >
                                      <Cloud size={11} />
                                      Sync Ban to Cloudflare Edge
                                    </button>
                                  )}
                                </div>
                              </div>

                              {/* Attacker Activity Timeline & Forensic Scope Dossier */}
                              <div style={{
                                padding: '12px 14px',
                                borderRadius: '8px',
                                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                                border: '1px solid var(--webcare-border, #e2e8f0)',
                                marginBottom: '14px'
                              }}>
                                {/* Header with Title and External Threat Intelligence Links */}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Target size={15} color="#4f46e5" />
                                    <span style={{ fontSize: '12px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.03em', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                      Attacker Activity Dossier &amp; Timeline Scope
                                    </span>
                                    {log.is_last_hit_for_ip ? (
                                      <span className="webcare-badge-pill webcare-badge-danger" style={{ fontSize: '10px', fontWeight: 800, padding: '2px 6px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                        <Zap size={10} />
                                        Terminal Hit (Final Incursion)
                                      </span>
                                    ) : (
                                      <span className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px' }}>
                                        Multi-Stage Surge Hit
                                      </span>
                                    )}
                                  </div>

                                  {/* External Threat Intelligence Check Links */}
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                    <a
                                      href={`https://www.abuseipdb.com/check/${encodeURIComponent(log.ip_address)}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-btn-micro"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none', color: '#dc2626' }}
                                      title="Check IP reputation and abuse reports on AbuseIPDB"
                                    >
                                      <span>AbuseIPDB</span>
                                      <ExternalLink size={10} />
                                    </a>
                                    <a
                                      href={`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(log.ip_address)}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-btn-micro"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none', color: '#4f46e5' }}
                                      title="Lookup IP address on VirusTotal"
                                    >
                                      <span>VirusTotal</span>
                                      <ExternalLink size={10} />
                                    </a>
                                    <a
                                      href={`https://ipinfo.io/${encodeURIComponent(log.ip_address)}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="webcare-btn-micro"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none', color: '#0284c7' }}
                                      title="Inspect ASN, ISP, and Geolocation on IPinfo"
                                    >
                                      <span>IPinfo / ASN</span>
                                      <ExternalLink size={10} />
                                    </a>
                                  </div>
                                </div>

                                {/* Terminal Hit / Ban Sequence Context Banner */}
                                <div style={{
                                  fontSize: '12px',
                                  lineHeight: 1.5,
                                  padding: '8px 12px',
                                  borderRadius: '6px',
                                  background: log.is_last_hit_for_ip && (log.cf_synced || log.ban_scope === 'edge_synced')
                                    ? 'rgba(249, 115, 22, 0.08)'
                                    : (log.is_last_hit_for_ip && log.is_banned ? 'rgba(239, 68, 68, 0.07)' : 'rgba(79, 70, 229, 0.04)'),
                                  borderLeft: `3px solid ${log.is_last_hit_for_ip && (log.cf_synced || log.ban_scope === 'edge_synced')
                                    ? '#ea580c'
                                    : (log.is_last_hit_for_ip && log.is_banned ? '#dc2626' : '#4f46e5')}`,
                                  marginBottom: '10px',
                                  color: 'var(--webcare-text-primary, #0f172a)'
                                }}>
                                  {log.is_last_hit_for_ip && (log.cf_synced || log.ban_scope === 'edge_synced') ? (
                                    <div>
                                      <strong>⚡ Terminal Recorded Hit • Cloudflare Edge Ban Active:</strong> This log entry is the final request received at your origin server from IP <code>{log.ip_address}</code> before edge banishment. All subsequent attempts from this IP are terminated at Cloudflare Anycast edge data centers without consuming origin PHP-FPM workers or MySQL database connections.
                                    </div>
                                  ) : (log.is_last_hit_for_ip && log.is_banned ? (
                                    <div>
                                      <strong>⚡ Terminal Recorded Hit • Origin WAF Block Active:</strong> This request is the final probe received from IP <code>{log.ip_address}</code> before being locked out on the Origin WAF. Sync to Cloudflare Edge to offload perimeter filtering.
                                    </div>
                                  ) : (log.is_last_hit_for_ip ? (
                                    <div>
                                      <strong>Terminal Recorded Hit:</strong> This request is the most recent activity recorded from IP <code>{log.ip_address}</code> in the current log retention window.
                                    </div>
                                  ) : (
                                    <div>
                                      <strong>Reconnaissance Incursion:</strong> This request is part of a multi-stage attack sequence from IP <code>{log.ip_address}</code> ({log.ip_total_hits || 'multiple'} incursions recorded). Click <em>&ldquo;Filter All Hits from {log.ip_address}&rdquo;</em> above to examine the attacker&apos;s full traversal sequence.
                                    </div>
                                  )))}
                                </div>

                                {/* Activity Telemetry 4-Pill Metric Row */}
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '8px', marginBottom: '10px' }}>
                                  <div style={{ background: 'var(--webcare-bg-surface, #ffffff)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
                                    <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700, textTransform: 'uppercase' }}>Total Incursions</div>
                                    <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '2px' }}>
                                      {log.ip_total_hits || 1} <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)' }}>hits</span>
                                    </div>
                                  </div>
                                  <div style={{ background: 'var(--webcare-bg-surface, #ffffff)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
                                    <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700, textTransform: 'uppercase' }}>First Observed</div>
                                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '3px' }}>
                                      {log.ip_first_seen ? formatRelativeTime(new Date(log.ip_first_seen * 1000)) : 'Recorded'}
                                    </div>
                                  </div>
                                  <div style={{ background: 'var(--webcare-bg-surface, #ffffff)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
                                    <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700, textTransform: 'uppercase' }}>Latest Incursion</div>
                                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '3px' }}>
                                      {log.ip_last_seen ? formatRelativeTime(new Date(log.ip_last_seen * 1000)) : 'Recent'}
                                    </div>
                                  </div>
                                  <div style={{ background: 'var(--webcare-bg-surface, #ffffff)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-standard, #e2e8f0)' }}>
                                    <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700, textTransform: 'uppercase' }}>Attacker Scope</div>
                                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '3px' }}>
                                      {log.ip_distinct_targets?.length || 1} URI{(log.ip_distinct_targets?.length || 1) !== 1 ? 's' : ''} &bull; {log.ip_distinct_vectors?.length || 1} Vector{(log.ip_distinct_vectors?.length || 1) !== 1 ? 's' : ''}
                                    </div>
                                  </div>
                                </div>

                                {/* Probed Targets & Triggered Vectors Chips */}
                                {((log.ip_distinct_targets && log.ip_distinct_targets.length > 0) || (log.ip_distinct_vectors && log.ip_distinct_vectors.length > 0)) && (
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                    {log.ip_distinct_targets && log.ip_distinct_targets.length > 0 && (
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', fontSize: '11px' }}>
                                        <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700 }}>Probed Targets:</span>
                                        {log.ip_distinct_targets.slice(0, 5).map((tgt, tIdx) => (
                                          <code key={tIdx} style={{ fontSize: '11px', background: 'var(--webcare-bg-surface, #ffffff)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--webcare-border-standard, #e2e8f0)', color: '#0284c7' }}>
                                            {tgt}
                                          </code>
                                        ))}
                                        {log.ip_distinct_targets.length > 5 && (
                                          <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '10px' }}>+{log.ip_distinct_targets.length - 5} more</span>
                                        )}
                                      </div>
                                    )}
                                    {log.ip_distinct_vectors && log.ip_distinct_vectors.length > 0 && (
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', fontSize: '11px' }}>
                                        <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontWeight: 700 }}>Triggered Vectors:</span>
                                        {log.ip_distinct_vectors.map((vec, vIdx) => (
                                          <span key={vIdx} style={{ fontSize: '11px', background: 'rgba(79, 70, 229, 0.08)', color: '#4f46e5', padding: '1px 6px', borderRadius: '4px', border: '1px solid rgba(79, 70, 229, 0.2)', fontWeight: 600 }}>
                                            {vec}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>

                              {/* 4-Column Metadata Grid */}
                              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px', marginBottom: '14px' }}>
                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                    Rule Trigger &amp; Description
                                  </div>
                                  <div style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 600 }}>
                                    {log.rule_description}
                                  </div>
                                  {log.rule_id && (
                                    <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                                      Rule ID: <code style={{ fontSize: '11px', color: '#4f46e5' }}>{log.rule_id}</code>
                                    </div>
                                  )}
                                  {log.rule_id === 'WAF-GUEST-AJAX-PROBE' && (() => {
                                    const action = log.matching_entry || (log.payload_sample?.match(/Action:\s*([^\s]+)/)?.[1]) || '';
                                    if (!action) return null;
                                    return (
                                      <div style={{ marginTop: '6px' }}>
                                        <button
                                          type="button"
                                          className="webcare-btn-micro"
                                          onClick={() => handleAllowlistRuleTarget(36, action)}
                                          disabled={allowingTarget === action}
                                          style={{
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: '4px',
                                            fontSize: '11px',
                                            fontWeight: 600,
                                            padding: '3px 8px',
                                            borderRadius: '4px',
                                            background: 'rgba(16, 185, 129, 0.1)',
                                            color: '#059669',
                                            border: '1px solid rgba(16, 185, 129, 0.3)',
                                            cursor: allowingTarget === action ? 'not-allowed' : 'pointer'
                                          }}
                                          title={`Permit unauthenticated guest visitors to invoke AJAX action "${action}" in Rule #36`}
                                        >
                                          {allowingTarget === action ? <Loader2 size={10} className="webcare-spin" /> : <Plus size={10} />}
                                          Allow in Rule #36 ({action})
                                        </button>
                                      </div>
                                    );
                                  })()}
                                  {(log.rule_id === 'WAF-GUEST-REST-MUTATION' || log.rule_id === 'WAF-GUEST-REST-BATCH-MUTATION') && (() => {
                                    const rawTarget = log.matching_entry || log.request_uri || '';
                                    const route = rawTarget.replace(/^\/wp-json/, '').split('?')[0] || '';
                                    const method = (log.request_method || 'POST').toUpperCase();
                                    if (!route) return null;
                                    const targetKey = `${method} ${route}`;
                                    return (
                                      <div style={{ marginTop: '6px' }}>
                                        <button
                                          type="button"
                                          className="webcare-btn-micro"
                                          onClick={() => handleAllowlistRuleTarget(37, route, method)}
                                          disabled={allowingTarget === targetKey}
                                          style={{
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: '4px',
                                            fontSize: '11px',
                                            fontWeight: 600,
                                            padding: '3px 8px',
                                            borderRadius: '4px',
                                            background: 'rgba(16, 185, 129, 0.1)',
                                            color: '#059669',
                                            border: '1px solid rgba(16, 185, 129, 0.3)',
                                            cursor: allowingTarget === targetKey ? 'not-allowed' : 'pointer'
                                          }}
                                          title={`Permit unauthenticated guest visitors to invoke "${method} ${route}" in Rule #37`}
                                        >
                                          {allowingTarget === targetKey ? <Loader2 size={10} className="webcare-spin" /> : <Plus size={10} />}
                                          Allow in Rule #37 ({method} {route})
                                        </button>
                                      </div>
                                    );
                                  })()}
                                  {(log.action_taken === 'warned' || log.action_taken === 'detected' || log.rule_category === 'Execution Armor' || log.rule_category === 'Content Armor' || (log.rule_id && log.rule_id.startsWith('MOD-'))) && (
                                     <div style={{ marginTop: '8px' }}>
                                       <button
                                         type="button"
                                         className="webcare-btn-micro"
                                         onClick={() => handleTrustCustomerAction(log)}
                                         disabled={allowingTarget === `${(log.request_uri || '').split('?')[0] || '/'}:${log.matched_param_key || log.rule_id || ''}`}
                                         style={{
                                           display: 'inline-flex',
                                           alignItems: 'center',
                                           gap: '5px',
                                           fontSize: '11px',
                                           fontWeight: 700,
                                           padding: '4px 10px',
                                           borderRadius: '5px',
                                           background: 'rgba(79, 70, 229, 0.1)',
                                           color: '#4f46e5',
                                           border: '1px solid rgba(79, 70, 229, 0.3)',
                                           cursor: 'pointer'
                                         }}
                                         title="Create narrow (route + param + role) exemption so legitimate user action is trusted while full exploit protection remains active"
                                       >
                                         {allowingTarget === `${(log.request_uri || '').split('?')[0] || '/'}:${log.matched_param_key || log.rule_id || ''}` ? (
                                           <Loader2 size={10} className="webcare-spin" />
                                         ) : (
                                           <span>🛡️</span>
                                         )}
                                         Trust This Customer Action (Scope to Param &amp; Route)
                                       </button>
                                     </div>
                                   )}
                                   {(log.ban_reason || log.matching_entry) && (
                                    <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                      {log.ban_reason && (
                                        <div style={{ fontSize: '11px', color: '#b45309', background: '#fef3c7', padding: '3px 8px', borderRadius: '4px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                                          <span><strong>Ban Reason:</strong> {log.ban_reason}</span>
                                        </div>
                                      )}
                                      {log.matching_entry && (
                                        <div style={{ fontSize: '11px', color: '#475569' }}>
                                          Matched Rule Target: <code style={{ fontSize: '11px' }}>{log.matching_entry}</code>
                                          {log.ban_source ? ` (${log.ban_source === 'manual_admin' ? 'Manual Admin Block' : (log.ban_source === 'rule_auto_ban' ? 'Automated Rule Ban' : 'Custom Blocklist')})` : ''}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>

                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                    User &amp; Authentication Context
                                  </div>
                                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                                    {log.username ? (
                                      <div>
                                        User: <strong>{log.username}</strong> {log.user_id ? `(ID: ${log.user_id})` : ''}
                                        <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                                          Role: {log.user_role || 'None'} &bull; {log.is_authenticated ? 'Authenticated Session' : 'Unauthenticated Login Attempt'}
                                        </div>
                                      </div>
                                    ) : (
                                      <div>
                                        Status: <strong>Unauthenticated Guest / Bot</strong>
                                      </div>
                                    )}
                                  </div>
                                </div>

                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                    HTTP Response Code &amp; Origin Referer
                                  </div>
                                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                                    <div>Status: <strong style={{ color: statusCode === 403 ? '#dc2626' : '#2563eb' }}>{statusCode} {statusCode === 403 ? 'Forbidden' : (statusCode === 404 ? 'Not Found' : (statusCode === 405 ? 'Method Not Allowed' : 'OK'))}</strong></div>
                                    <div style={{ marginTop: '2px', wordBreak: 'break-all', fontSize: '11px' }}>Referer: <code>{log.http_referer || 'None (Direct request)'}</code></div>
                                  </div>
                                </div>

                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                    Client User-Agent Fingerprint
                                  </div>
                                  <div style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--webcare-text-secondary, #475569)', wordBreak: 'break-all' }}>
                                    {log.user_agent || 'Header missing (raw automated socket connection)'}
                                  </div>
                                </div>
                              </div>

                              {/* Technical Forensic Breakdown for Developers / SysAdmins */}
                              {forensics.techDetails.length > 0 && (
                                <div style={{
                                  background: 'var(--webcare-bg-surface, #f8fafc)',
                                  border: '1px solid var(--webcare-border-standard, #e2e8f0)',
                                  borderRadius: '6px',
                                  padding: '10px 14px',
                                  marginBottom: '14px',
                                  display: 'flex',
                                  flexWrap: 'wrap',
                                  gap: '12px 24px'
                                }}>
                                  {forensics.techDetails.map((td, idx) => (
                                    <div key={idx} style={{ fontSize: '12px' }}>
                                      <span style={{ color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>{td.label}: </span>
                                      <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{td.value}</strong>
                                    </div>
                                  ))}
                                </div>
                              )}

                              {/* Malicious or Allowed Request Payload Excerpt */}
                              <div style={{ marginBottom: '14px' }}>
                                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', marginBottom: '6px' }}>
                                  {log.action_taken === 'allowed' ? 'Captured Inbound Query & Request Body Telemetry' : 'Captured Malicious Payload Sample'}
                                </div>
                                <pre style={{
                                  margin: 0,
                                  padding: '12px 14px',
                                  background: 'var(--webcare-bg-code, #090d16)',
                                  color: '#38bdf8',
                                  borderRadius: '6px',
                                  fontSize: '12px',
                                  fontFamily: 'monospace',
                                  overflowX: 'auto',
                                  whiteSpace: 'pre-wrap',
                                  wordBreak: 'break-all',
                                  border: '1px solid rgba(56, 189, 248, 0.2)'
                                }}>
                                  {log.payload_sample ? log.payload_sample : `${log.request_method} ${log.request_uri}`}
                                </pre>
                              </div>

                              {/* Actionable Recommended Remediation & Guidance */}
                              <div style={{
                                padding: '10px 14px',
                                borderRadius: '6px',
                                background: 'rgba(16, 185, 129, 0.05)',
                                border: '1px solid rgba(16, 185, 129, 0.2)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                flexWrap: 'wrap',
                                gap: '10px'
                              }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '220px' }}>
                                  <Lightbulb size={16} color="#059669" style={{ flexShrink: 0 }} />
                                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                    <strong style={{ color: '#047857' }}>Recommended Action: </strong>
                                    {forensics.recommendation}
                                  </div>
                                </div>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                  {forensics.suggestedAction === 'delete_component' && onNavigateToFirewallRules && (
                                    <button
                                      type="button"
                                      className="webcare-btn-micro"
                                      style={{ background: '#4f46e5', color: '#fff', border: 'none' }}
                                      onClick={onNavigateToFirewallRules}
                                    >
                                      Tune CAF Policies
                                    </button>
                                  )}
                                  {forensics.suggestedAction === 'block_ip' && (
                                    <button
                                      type="button"
                                      className="webcare-btn-micro"
                                      style={{ background: '#dc2626', color: '#fff', border: 'none' }}
                                      onClick={() => handleBlockIp(log.ip_address)}
                                    >
                                      Ban IP {log.ip_address}
                                    </button>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                        );
                      })()}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* 6. Footer & Pagination Bar */}
        <div className="webcare-waf-pagination-bar">
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
            Showing <strong>{logs.length > 0 ? (page - 1) * pageSize + 1 : 0}</strong> - <strong>{Math.min(totalCount, page * pageSize)}</strong> of <strong>{totalCount.toLocaleString()}</strong> incident logs
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              type="button"
              className="webcare-btn-micro"
              disabled={page <= 1 || loading}
              onClick={() => setPage(prev => Math.max(1, prev - 1))}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
            >
              <ChevronLeft size={14} /> Previous
            </button>

            <span style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', padding: '0 6px' }}>
              Page <strong>{page}</strong> of <strong>{totalPages}</strong>
            </span>

            <button
              type="button"
              className="webcare-btn-micro"
              disabled={page >= totalPages || loading}
              onClick={() => setPage(prev => Math.min(totalPages, prev + 1))}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* 7. SysAdmin Support Footer Note */}
      <div className="webcare-waf-panel-card" style={{
        marginTop: '24px',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        fontSize: '13px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldCheck size={20} color="#10b981" />
          <span style={{ color: 'var(--webcare-text-secondary, #475569)' }}>
            Want tailored edge rules, Nginx fail2ban filters, or Cloudflare Enterprise WAF tuning? Connect directly with <strong>Mir Alamin (WebCare Pro)</strong>.
          </span>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          {onNavigateToFirewallRules && (
            <button
              type="button"
              className="webcare-btn webcare-btn-secondary"
              style={{ fontSize: '12px', padding: '6px 12px' }}
              onClick={onNavigateToFirewallRules}
            >
              <Sliders size={14} /> Configure WAF Rules
            </button>
          )}
          <a
            href="https://webcarepro.dev"
            target="_blank"
            rel="noopener noreferrer"
            className="webcare-btn"
            style={{
              fontSize: '12px',
              padding: '6px 14px',
              background: '#4f46e5',
              color: '#ffffff',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              textDecoration: 'none',
              borderRadius: '6px',
              fontWeight: 600
            }}
          >
            <span>Direct 1-on-1 Assistance</span>
            <ExternalLink size={13} />
          </a>
        </div>
      </div>
        </>
      )}

      {/* 3. TAB CONTENT: CLOUDFLARE EDGE BLOCK EVENTS (VAULT STORED) */}
      {activeLogTab === 'cloudflare' && (
        <div className="webcare-cf-edge-tab-content">
          {/* Cloudflare Edge Telemetry KPI Row */}
          <div className="webcare-waf-kpi-grid">
            <div className="webcare-waf-kpi-card">
              <div className="webcare-waf-kpi-card-inner">
                <div>
                  <div className="webcare-waf-kpi-label">Edge Incursions Neutralized</div>
                  <div className="webcare-waf-kpi-value" style={{ color: '#ea580c' }}>
                    {cfLoading ? '...' : cfEvents.length.toLocaleString()}
                  </div>
                  <div className="webcare-waf-kpi-caption">Saved server RAM &amp; CPU cycles</div>
                </div>
                <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-orange">
                  <Cloud size={22} />
                </div>
              </div>
            </div>

            <div className="webcare-waf-kpi-card">
              <div className="webcare-waf-kpi-card-inner">
                <div>
                  <div className="webcare-waf-kpi-label">Hard Block Actions</div>
                  <div className="webcare-waf-kpi-value" style={{ color: '#dc2626' }}>
                    {cfLoading ? '...' : cfEvents.filter(e => e.action?.toLowerCase() === 'block').length.toLocaleString()}
                  </div>
                  <div className="webcare-waf-kpi-caption">Strict edge drops</div>
                </div>
                <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-danger">
                  <ShieldAlert size={22} />
                </div>
              </div>
            </div>

            <div className="webcare-waf-kpi-card">
              <div className="webcare-waf-kpi-card-inner">
                <div>
                  <div className="webcare-waf-kpi-label">Challenges &amp; Captchas</div>
                  <div className="webcare-waf-kpi-value" style={{ color: '#d97706' }}>
                    {cfLoading ? '...' : cfEvents.filter(e => e.action?.toLowerCase().includes('challenge')).length.toLocaleString()}
                  </div>
                  <div className="webcare-waf-kpi-caption">Managed &amp; JS challenges</div>
                </div>
                <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-warn">
                  <Lock size={22} />
                </div>
              </div>
            </div>

            <div className="webcare-waf-kpi-card">
              <div className="webcare-waf-kpi-card-inner">
                <div>
                  <div className="webcare-waf-kpi-label">Storage Architecture</div>
                  <div className="webcare-waf-kpi-value" style={{ color: '#059669', fontSize: '18px' }}>
                    WebCare Vault JSON
                  </div>
                  <div className="webcare-waf-kpi-caption">Zero MySQL database load</div>
                </div>
                <div className="webcare-waf-kpi-icon-wrap webcare-kpi-icon-emerald">
                  <ShieldCheck size={22} />
                </div>
              </div>
            </div>
          </div>

          {/* Cloudflare Edge Events Main Card */}
          <div className="webcare-card webcare-cf-edge-main-card" style={{ padding: '0', overflow: 'hidden', borderRadius: '12px' }}>
            {/* Header Toolbar */}
            <div className="webcare-cf-edge-header" style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: '8px',
                  background: 'rgba(234, 88, 12, 0.12)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ea580c'
                }}>
                  <Cloud size={22} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      Cloudflare Edge Firewall Block Events
                    </h3>
                    {cfZoneName && (
                      <span style={{
                        fontSize: '11px',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: 'rgba(234, 88, 12, 0.1)',
                        color: '#ea580c',
                        border: '1px solid rgba(234, 88, 12, 0.25)',
                        fontWeight: 600
                      }}>
                        Zone: {cfZoneName}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                    Attacks stopped at Cloudflare Anycast edge before reaching origin • Stored securely in WebCare Vault (Zero DB overhead)
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {cfEvents.length > 0 && (
                  <button
                    type="button"
                    className="webcare-btn webcare-btn-danger-soft"
                    onClick={handleClearCfLogs}
                    disabled={cfClearingLogs}
                    style={{
                      fontSize: '13px',
                      padding: '8px 14px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                    title="Clean all cached Cloudflare edge logs from local JSON file"
                  >
                    <Trash2 size={14} />
                    <span>Clean Local JSON Logs</span>
                  </button>
                )}
                <button
                  type="button"
                  className="webcare-btn"
                  onClick={handleFetchNewCfEvents}
                  disabled={cfFetchingNew}
                  style={{
                    background: '#ea580c',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '13px',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    boxShadow: '0 2px 4px rgba(234, 88, 12, 0.2)'
                  }}
                >
                  {cfFetchingNew ? <Loader2 size={14} className="webcare-spin" /> : <RefreshCw size={14} />}
                  <span>{cfFetchingNew ? 'Fetching from Edge...' : 'Fetch New Cloudflare Events'}</span>
                </button>
              </div>
            </div>

            {/* Error or Missing Permission Banner */}
            {cfError && (
              <div className="webcare-alert-banner webcare-alert-banner-error" style={{
                padding: '14px 20px',
                borderTop: 'none',
                borderLeft: 'none',
                borderRight: 'none',
                borderRadius: '0',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px'
              }}>
                <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ flex: 1 }}>
                  <strong>{cfError}</strong>
                  {cfMissingPerm && (
                    <div style={{ marginTop: '8px', fontSize: '12.5px', lineHeight: 1.5, opacity: 0.9 }}>
                      <strong>How to enable:</strong> In your Cloudflare Dashboard, go to <em>My Profile &gt; API Tokens</em>, edit your WebCare Token, and under <strong>Permissions</strong> add: <code>Zone &gt; Analytics &gt; Read</code>. Then save and click "Fetch New Cloudflare Events" again.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Explanatory Retention & Deep-Link Note */}
            <div style={{
              padding: '12px 20px',
              background: 'rgba(234, 88, 12, 0.04)',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              fontSize: '12.5px',
              color: 'var(--webcare-text-secondary, #475569)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '280px' }}>
                <Info size={16} color="#ea580c" style={{ flexShrink: 0 }} />
                <span>
                  <strong>Note:</strong> Only the <strong>1,000 most recent</strong> Cloudflare edge logs are stored and displayed here in zero-overhead local JSON vault. To inspect all historical events, security analytics, and raw payload telemetry, visit your Cloudflare Security Events Console.
                </span>
              </div>
              <a
                href={cfZoneId ? `https://dash.cloudflare.com/?to=/:account/:zone/security/events&zone=${cfZoneId}` : 'https://dash.cloudflare.com/'}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  color: '#ea580c',
                  fontWeight: 600,
                  textDecoration: 'none',
                  fontSize: '12.5px',
                  whiteSpace: 'nowrap'
                }}
              >
                <span>View All Logs in Cloudflare Security Events</span>
                <ExternalLink size={13} />
              </a>
            </div>

            {/* Whitelist Feedback Banner */}
            {cfWhitelistSuccess && (
              <div className="webcare-alert-banner webcare-alert-banner-success" style={{
                padding: '12px 20px',
                borderTop: 'none',
                borderLeft: 'none',
                borderRight: 'none',
                borderRadius: '0',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <Check size={16} />
                <span>IP <strong>{cfWhitelistSuccess}</strong> successfully whitelisted on Cloudflare Edge with <code>mode: allow</code>!</span>
              </div>
            )}

            {/* Sub-Header Toolbar (Search, Filter, Synced Time) */}
            <div className="webcare-cf-edge-toolbar" style={{
              padding: '12px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              fontSize: '12px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '260px' }}>
                <div style={{ position: 'relative', flex: 1, maxWidth: '360px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--webcare-text-muted, #64748b)' }} />
                  <input
                    type="text"
                    value={cfSearch}
                    onChange={(e) => setCfSearch(e.target.value)}
                    placeholder="Search by IP, URI path, rule name, country..."
                    className="webcare-input"
                    style={{ width: '100%', paddingLeft: '32px', fontSize: '12.5px', padding: '7px 12px 7px 32px' }}
                  />
                </div>

                <select
                  value={cfActionFilter}
                  onChange={(e) => setCfActionFilter(e.target.value)}
                  className="webcare-input"
                  style={{ fontSize: '12.5px', padding: '7px 12px' }}
                >
                  <option value="all">All Edge Actions</option>
                  <option value="block">Block Only</option>
                  <option value="managed_challenge">Managed Challenge</option>
                  <option value="js_challenge">JS Challenge</option>
                  <option value="log">Log Only</option>
                </select>
              </div>

              <div style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '12.5px' }}>
                {cfLastSynced ? (
                  <span>Last synced from Edge: <strong>{formatRelativeTime(cfLastSynced)}</strong> ({cfEvents.length} events in Vault cache)</span>
                ) : (
                  <span>No events cached yet. Click "Fetch New Cloudflare Events".</span>
                )}
              </div>
            </div>

            {/* Table View */}
            <div style={{ overflowX: 'auto' }}>
              {cfLoading ? (
                <div style={{ padding: '80px 20px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <Loader2 size={28} className="webcare-spin" style={{ margin: '0 auto 12px', color: '#ea580c' }} />
                  <p style={{ margin: 0, fontSize: '14px', fontWeight: 500 }}>Reading cached security events from WebCare Vault...</p>
                </div>
              ) : cfEvents.length === 0 ? (
                <div style={{ padding: '80px 20px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                  <Cloud size={44} color="#ea580c" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '16px', color: 'var(--webcare-text-primary, #0f172a)' }}>No Cloudflare Edge Events Cached</h4>
                  <p style={{ margin: '0 0 20px 0', fontSize: '13px', maxWidth: '480px', marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.5 }}>
                    Click below to fetch the latest perimeter attacks blocked by Cloudflare Anycast Edge directly into your WebCare Vault.
                  </p>
                  <button
                    type="button"
                    className="webcare-btn"
                    onClick={handleFetchNewCfEvents}
                    disabled={cfFetchingNew}
                    style={{
                      background: '#ea580c',
                      color: '#ffffff',
                      border: 'none',
                      fontSize: '13.5px',
                      padding: '10px 22px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px',
                      boxShadow: '0 2px 6px rgba(234, 88, 12, 0.25)'
                    }}
                  >
                    {cfFetchingNew ? <Loader2 size={15} className="webcare-spin" /> : <RefreshCw size={15} />}
                    <span>Fetch Cloudflare Security Events</span>
                  </button>
                </div>
              ) : (
                <table className="webcare-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                  <thead>
                    <tr style={{ background: 'var(--webcare-bg-surface-elevated, var(--webcare-bg-elevated))', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                      <th style={{ padding: '12px 14px', width: '34px' }}></th>
                      <th style={{ padding: '12px 14px', width: '170px' }}>Timestamp</th>
                      <th style={{ padding: '12px 14px', width: '100px' }}>Action</th>
                      <th style={{ padding: '12px 14px', width: '180px' }}>Country / IP</th>
                      <th style={{ padding: '12px 14px' }}>Target Path &amp; Method</th>
                      <th style={{ padding: '12px 14px' }}>Matched Rule</th>
                      <th style={{ padding: '12px 14px', textAlign: 'right', width: '120px' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cfEvents
                      .filter(ev => {
                        if (cfActionFilter !== 'all' && ev.action?.toLowerCase() !== cfActionFilter.toLowerCase()) return false;
                        if (!cfSearch) return true;
                        const s = cfSearch.toLowerCase();
                        return (
                          ev.client_ip?.toLowerCase().includes(s) ||
                          ev.path?.toLowerCase().includes(s) ||
                          ev.rule_name?.toLowerCase().includes(s) ||
                          ev.country?.toLowerCase().includes(s) ||
                          ev.ray_id?.toLowerCase().includes(s)
                        );
                      })
                      .map(ev => {
                        const isExpanded = cfExpandedRay === ev.ray_id;
                        const isBlocked = ev.action?.toLowerCase() === 'block';
                        const isChallenge = ev.action?.toLowerCase().includes('challenge');

                        return (
                          <React.Fragment key={ev.ray_id}>
                            <tr
                              onClick={() => setCfExpandedRay(isExpanded ? null : ev.ray_id)}
                              style={{
                                cursor: 'pointer',
                                borderBottom: '1px solid var(--webcare-border, #f1f5f9)',
                                background: isExpanded ? 'var(--webcare-bg-surface-elevated, rgba(79, 70, 229, 0.04))' : 'transparent',
                                transition: 'background 0.15s ease'
                              }}
                            >
                              <td style={{ padding: '12px 14px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
                                {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                              </td>
                              <td style={{ padding: '12px 14px', whiteSpace: 'nowrap', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                <strong>{formatTelemetryDateFull(ev.datetime)}</strong>
                              </td>
                              <td style={{ padding: '12px 14px' }}>
                                <span className={`webcare-badge-pill ${isBlocked ? 'webcare-badge-danger' : (isChallenge ? 'webcare-badge-warn' : 'webcare-badge-info')}`} style={{
                                  display: 'inline-block',
                                  padding: '3px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.02em'
                                }}>
                                  {ev.action}
                                </span>
                              </td>
                              <td style={{ padding: '12px 14px' }}>
                                <div style={{ display: 'flex', flexDirection: 'column' }}>
                                  <span style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                    {ev.country || 'Unknown Country'}
                                  </span>
                                  <code style={{ fontSize: '11.5px', color: '#0284c7' }}>{ev.client_ip}</code>
                                </div>
                              </td>
                              <td style={{ padding: '12px 14px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <span className="webcare-badge-pill webcare-badge-muted" style={{
                                    fontSize: '10px',
                                    fontWeight: 700,
                                    padding: '2px 5px',
                                    borderRadius: '3px'
                                  }}>
                                    {ev.method || 'GET'}
                                  </span>
                                  <code style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                    {ev.path}
                                  </code>
                                </div>
                              </td>
                              <td style={{ padding: '12px 14px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <Shield size={14} color="#ea580c" />
                                  <span style={{ fontWeight: 500, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                    {ev.rule_name}
                                  </span>
                                </div>
                              </td>
                              <td style={{ padding: '12px 14px', textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                                <button
                                  type="button"
                                  className="webcare-btn-micro webcare-action-btn-clean"
                                  onClick={() => handleWhitelistCfIp(ev.client_ip)}
                                  disabled={cfWhitelistingIp === ev.client_ip}
                                  title="Add to Cloudflare & Local Allowlist"
                                  style={{
                                    fontSize: '11.5px',
                                    padding: '4px 9px'
                                  }}
                                >
                                  {cfWhitelistingIp === ev.client_ip ? <Loader2 size={11} className="webcare-spin" /> : '+ Allow IP'}
                                </button>
                              </td>
                            </tr>

                            {/* Expandable Forensic Details Drawer */}
                            {isExpanded && (
                              <tr className="webcare-waf-expanded-row">
                                <td colSpan={7} style={{ padding: '16px 20px', borderBottom: '1px solid var(--webcare-border, #e2e8f0)' }}>
                                  <div className="webcare-waf-panel-card" style={{
                                    padding: '16px 20px',
                                    display: 'grid',
                                    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                                    gap: '16px',
                                    fontSize: '12px'
                                  }}>
                                    <div>
                                      <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Activity size={15} color="#ea580c" /> Cloudflare Edge Forensic Details
                                      </div>
                                      <div style={{ lineHeight: 1.7, color: 'var(--webcare-text-secondary, #475569)' }}>
                                        <div><strong>Ray ID:</strong> <code style={{ color: '#ea580c', fontWeight: 600 }}>{ev.ray_id}</code></div>
                                        <div><strong>Matched Rule:</strong> <span style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>{ev.rule_name}</span></div>
                                        {ev.rule_id && <div><strong>Rule ID:</strong> <code style={{ fontSize: '11px' }}>{ev.rule_id}</code></div>}
                                        {ev.ruleset_id && <div><strong>Ruleset ID:</strong> <code style={{ fontSize: '11px' }}>{ev.ruleset_id}</code></div>}
                                        <div><strong>Trigger Source:</strong> <span style={{ textTransform: 'capitalize' }}>{ev.source || 'Edge Firewall'}</span></div>
                                        <div><strong>HTTP Protocol:</strong> <span>{ev.protocol || 'HTTP/1.1'}</span></div>
                                        <div><strong>Target Host:</strong> <span>{ev.host || 'N/A'}</span></div>
                                        <div><strong>Autonomous System (ASN):</strong> <span>AS{ev.asn} {ev.asn_desc ? `(${ev.asn_desc})` : ''}</span></div>
                                        <div><strong>Referer:</strong> <span>{ev.referer || 'None (direct incursion)'}</span></div>
                                      </div>
                                    </div>

                                    <div>
                                      <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Terminal size={15} color="#4f46e5" /> Request Fingerprint &amp; Query
                                      </div>
                                      <div style={{ lineHeight: 1.7, color: 'var(--webcare-text-secondary, #475569)' }}>
                                        <div><strong>Query String:</strong> <code style={{ wordBreak: 'break-all' }}>{ev.query ? `?${ev.query}` : 'Empty query string'}</code></div>
                                        <div style={{ marginTop: '6px' }}><strong>User-Agent:</strong></div>
                                        <div className="webcare-code-block" style={{
                                          padding: '8px 10px',
                                          borderRadius: '4px',
                                          fontFamily: 'monospace',
                                          fontSize: '11px',
                                          marginTop: '4px',
                                          wordBreak: 'break-all'
                                        }}>
                                          {ev.user_agent || 'Unknown'}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Table Footer */}
            <div className="webcare-cf-edge-footer" style={{
              padding: '12px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '12px'
            }}>
              <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>
                Attackers blocked at Cloudflare Edge never touch your server CPU or RAM.
              </span>
              <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>
                Total cached in Vault: <strong>{cfEvents.length}</strong> events
              </span>
            </div>
          </div>
        </div>
      )}

      {/* 4. TAB CONTENT: BANS, BLOCK & ALLOWLIST RULES */}
      {activeLogTab === 'rules' && (
        <div style={{ marginTop: '16px' }}>
          <BansAndAllowlistsPanel
            apiRequest={apiRequest}
            onNotice={(type, msg) => setActionMessage({ type, text: msg })}
            cfConfigured={Boolean(cfStatus?.configured)}
          />
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={wafConfirmDialog.isOpen}
        title={wafConfirmDialog.title}
        message={wafConfirmDialog.message}
        targetItem={wafConfirmDialog.targetItem}
        confirmLabel={wafConfirmDialog.confirmLabel}
        variant={wafConfirmDialog.variant}
        isLoading={wafConfirmDialog.isLoading}
        onConfirm={wafConfirmDialog.onConfirm || (() => {})}
        onClose={() => setWafConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />

      {/* WAF Export Options Modal */}
      {isExportModalOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={() => !isExporting && setIsExportModalOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px',
          }}
        >
          <div
            className="webcare-modal-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              borderRadius: '12px',
              maxWidth: '520px',
              width: '100%',
              boxShadow: '0 20px 40px rgba(0, 0, 0, 0.35)',
              overflow: 'hidden',
              animation: 'webcareModalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: 'rgba(79, 70, 229, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#4f46e5',
                  }}
                >
                  <Download size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Export WAF Incident Logs
                  </h3>
                  <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Choose scope, specific dates, and download format
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => !isExporting && setIsExportModalOpen(false)}
                disabled={isExporting}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: isExporting ? 'not-allowed' : 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Scope Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Select Incident Scope
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px' }}>
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'all' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'all' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="wafExportScope"
                      checked={exportScope === 'all'}
                      onChange={() => setExportScope('all')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        All Historical WAF Logs
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Export complete multi-day perimeter attack logs across all daily archives
                      </div>
                    </div>
                  </label>

                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'date' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'date' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="wafExportScope"
                      checked={exportScope === 'date'}
                      onChange={() => setExportScope('date')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Specific Date Logs
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Download incidents from a specific daily partition file
                      </div>
                    </div>
                  </label>

                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'filtered' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'filtered' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="wafExportScope"
                      checked={exportScope === 'filtered'}
                      onChange={() => setExportScope('filtered')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Current Filtered Table View ({logs.length} incidents)
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Export only currently active filtered rows from this view
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Date Input / Daily Partition Picker */}
              {exportScope === 'date' && (
                <div style={{ padding: '12px 14px', background: 'var(--webcare-bg-surface-elevated, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                    Choose Daily Log Partition:
                  </label>
                  {availableFiles.length > 0 ? (
                    <select
                      value={exportDate}
                      onChange={(e) => setExportDate(e.target.value)}
                      className="webcare-input"
                      style={{ width: '100%', fontSize: '13px', padding: '7px 12px' }}
                    >
                      {availableFiles.map((f, idx) => (
                        <option key={idx} value={f.filename}>
                          {f.filename} ({f.date} &bull; {f.size_human})
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="date"
                      value={exportDate}
                      onChange={(e) => setExportDate(e.target.value)}
                      className="webcare-input"
                      style={{ width: '100%', fontSize: '13px', padding: '7px 12px' }}
                    />
                  )}
                </div>
              )}

              {/* Format Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Download Format
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={() => setExportFormat('json')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${exportFormat === 'json' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportFormat === 'json' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileCode size={16} color="#3b82f6" />
                      <span>JSON (.json)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Complete payload telemetry &amp; security dossier
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setExportFormat('csv')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${exportFormat === 'csv' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportFormat === 'csv' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileText size={16} color="#10b981" />
                      <span>CSV (.csv)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Spreadsheet &amp; Microsoft Excel compatible table
                    </div>
                  </button>
                </div>
              </div>

              {/* Include System & Environment Diagnostics Checkbox */}
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '8px',
                  background: includeSystemInfo ? 'rgba(79, 70, 229, 0.04)' : 'var(--webcare-bg-surface-elevated, #f8fafc)',
                  border: `1px solid ${includeSystemInfo ? '#c7d2fe' : 'var(--webcare-border, #e2e8f0)'}`,
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
                onClick={() => {
                  const newVal = !includeSystemInfo;
                  setIncludeSystemInfo(newVal);
                  try {
                    localStorage.setItem('webcare_export_include_system_info', String(newVal));
                  } catch (e) {}
                }}
              >
                <input
                  type="checkbox"
                  id="wafIncludeSystemInfo"
                  checked={includeSystemInfo}
                  onChange={(e) => {
                    const newVal = e.target.checked;
                    setIncludeSystemInfo(newVal);
                    try {
                      localStorage.setItem('webcare_export_include_system_info', String(newVal));
                    } catch (e) {}
                  }}
                  style={{
                    marginTop: '2px',
                    cursor: 'pointer',
                    width: '16px',
                    height: '16px',
                    accentColor: '#4f46e5'
                  }}
                />
                <div style={{ flex: 1 }}>
                  <label
                    htmlFor="wafIncludeSystemInfo"
                    style={{
                      display: 'block',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      color: 'var(--webcare-text-primary, #0f172a)',
                      cursor: 'pointer',
                      marginBottom: '2px'
                    }}
                  >
                    Include System &amp; Environment Diagnostics <span style={{ fontSize: '11px', color: '#4f46e5', fontWeight: 500 }}>(Recommended for Log Analysis)</span>
                  </label>
                  <p style={{ margin: 0, fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.45 }}>
                    Embeds domain name, server real IP, Cloudflare protection status, web server / PHP versions, and active &amp; installed themes/plugins with versions. Uncheck to download raw attack events only.
                  </p>
                </div>
              </div>

              {/* Filename Preview Info Box */}
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  fontSize: '11.5px',
                  color: 'var(--webcare-text-muted, #64748b)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <Info size={15} style={{ flexShrink: 0, color: '#4f46e5' }} />
                <span>
                  Log file will be stamped with site domain: <code>waf-logs-{exportScope === 'date' ? exportDate.replace(/-waf-logs\.json$/, '') : new Date().toISOString().slice(0, 10)}-[time]-[domain]-[hash].{exportFormat}</code>
                </span>
              </div>
            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '10px',
              }}
            >
              <button
                type="button"
                onClick={() => setIsExportModalOpen(false)}
                disabled={isExporting}
                className="webcare-btn webcare-btn-secondary"
                style={{ padding: '8px 16px', fontSize: '13px', fontWeight: 600 }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeWafExport}
                disabled={isExporting}
                className="webcare-btn webcare-btn-primary"
                style={{
                  padding: '8px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#4f46e5',
                  color: '#ffffff',
                }}
              >
                {isExporting ? <RefreshCw size={14} className="webcare-spin-icon" /> : <Download size={14} />}
                <span>{isExporting ? 'Generating Export...' : `Download ${exportFormat.toUpperCase()}`}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Granular Rule-Scoped IP Allowlist */}
      {allowlistModal.isOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 100000,
            background: 'rgba(15, 23, 42, 0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
          }}
          onClick={() => { if (!allowlistModal.isSubmitting) setAllowlistModal(prev => ({ ...prev, isOpen: false })); }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '560px',
              borderRadius: '14px',
              background: 'var(--webcare-bg-panel, #ffffff)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              overflow: 'hidden',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: '#ecfdf5', color: '#059669', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ShieldCheck size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Configure Allowlist Rule
                  </h3>
                  <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Exempt IP <code>{allowlistModal.ip}</code> with Least-Privilege Granularity
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setAllowlistModal(prev => ({ ...prev, isOpen: false }))}
                disabled={allowlistModal.isSubmitting}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: '4px' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px', maxHeight: '75vh', overflowY: 'auto' }}>
              
              {/* Trigger Info Card */}
              <div style={{ padding: '12px 14px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', fontSize: '12px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px' }}>
                  <strong style={{ color: 'var(--webcare-text-muted, #64748b)' }}>Client IP:</strong>
                  <code style={{ color: '#0284c7', fontWeight: 600 }}>{allowlistModal.ip}</code>
                  
                  {allowlistModal.ruleId && (
                    <>
                      <strong style={{ color: 'var(--webcare-text-muted, #64748b)' }}>Triggered Rule:</strong>
                      <span><code style={{ color: '#4f46e5', fontWeight: 600 }}>{allowlistModal.ruleId}</code> ({allowlistModal.ruleName})</span>
                    </>
                  )}

                  <strong style={{ color: 'var(--webcare-text-muted, #64748b)' }}>Category:</strong>
                  <span className="webcare-badge-pill webcare-badge-info" style={{ display: 'inline-block', width: 'fit-content' }}>{allowlistModal.ruleCategory}</span>

                  <strong style={{ color: 'var(--webcare-text-muted, #64748b)' }}>Target Path:</strong>
                  <code style={{ color: 'var(--webcare-text-secondary, #475569)' }}>{allowlistModal.endpoint}</code>
                </div>
              </div>

              {/* Scoping Options */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '8px' }}>
                  Select Allowlist Scope:
                </label>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  
                  {/* Option A: Specific Rule */}
                  {allowlistModal.ruleId && (
                    <label
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '10px',
                        padding: '12px 14px',
                        borderRadius: '8px',
                        border: allowlistModal.scope === 'rule' ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                        background: allowlistModal.scope === 'rule' ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-surface, #ffffff)',
                        cursor: 'pointer'
                      }}
                    >
                      <input
                        type="radio"
                        name="allowScope"
                        value="rule"
                        checked={allowlistModal.scope === 'rule'}
                        onChange={() => setAllowlistModal(prev => ({ ...prev, scope: 'rule' }))}
                        style={{ marginTop: '2px' }}
                      />
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                            Exempt Only This Specific Rule (Recommended)
                          </strong>
                          <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px', padding: '1px 6px' }}>Safest</span>
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.4 }}>
                          Allows <code>{allowlistModal.ip}</code> to bypass <strong>{allowlistModal.ruleId}</strong>. All other firewall checks (SQLi, XSS, PHP Armor) remain 100% active.
                        </div>
                      </div>
                    </label>
                  )}

                  {/* Option B: Category Group */}
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '12px 14px',
                      borderRadius: '8px',
                      border: allowlistModal.scope === 'category' ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                      background: allowlistModal.scope === 'category' ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-surface, #ffffff)',
                      cursor: 'pointer'
                    }}
                  >
                    <input
                      type="radio"
                      name="allowScope"
                      value="category"
                      checked={allowlistModal.scope === 'category'}
                      onChange={() => setAllowlistModal(prev => ({ ...prev, scope: 'category' }))}
                      style={{ marginTop: '2px' }}
                    />
                    <div style={{ flex: 1 }}>
                      <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Exempt Entire Rule Category Group
                      </strong>
                      <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.4 }}>
                        Allows <code>{allowlistModal.ip}</code> to bypass all rules classified under <strong>{allowlistModal.ruleCategory}</strong>.
                      </div>
                    </div>
                  </label>

                  {/* Option C: Global Bypass */}
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '12px 14px',
                      borderRadius: '8px',
                      border: allowlistModal.scope === 'global' ? '2px solid #ea580c' : '1px solid var(--webcare-border, #e2e8f0)',
                      background: allowlistModal.scope === 'global' ? '#fff7ed' : 'var(--webcare-bg-surface, #ffffff)',
                      cursor: 'pointer'
                    }}
                  >
                    <input
                      type="radio"
                      name="allowScope"
                      value="global"
                      checked={allowlistModal.scope === 'global'}
                      onChange={() => setAllowlistModal(prev => ({ ...prev, scope: 'global' }))}
                      style={{ marginTop: '2px' }}
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <strong style={{ fontSize: '13px', color: allowlistModal.scope === 'global' ? '#c2410c' : 'var(--webcare-text-primary, #0f172a)' }}>
                          Global Firewall Bypass (Legacy All-Rules Pass)
                        </strong>
                        <span className="webcare-badge-pill webcare-badge-warn" style={{ fontSize: '10px', padding: '1px 6px' }}>High Trust</span>
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.4 }}>
                        Bypasses all firewall rules for this IP. Use only for trusted developer environments or verified corporate headquarters.
                      </div>
                    </div>
                  </label>

                </div>
              </div>

              {/* Endpoint Scope Restrictor */}
              <div style={{ padding: '12px 14px', borderRadius: '8px', background: 'var(--webcare-bg-surface, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '12.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  <input
                    type="checkbox"
                    checked={allowlistModal.endpointScoped}
                    onChange={(e) => setAllowlistModal(prev => ({ ...prev, endpointScoped: e.target.checked }))}
                  />
                  <span>Restrict exemption strictly to path: <code>{allowlistModal.endpoint}</code></span>
                </label>
                <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', marginLeft: '22px' }}>
                  If checked, requests by this IP to other endpoints will still be inspected normally.
                </div>
              </div>

              {/* Expiration Duration */}
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>
                  Exemption Expiration Schedule:
                </label>
                <select
                  value={allowlistModal.expiresIn}
                  onChange={(e) => setAllowlistModal(prev => ({ ...prev, expiresIn: Number(e.target.value) }))}
                  className="webcare-input"
                  style={{ width: '100%', padding: '7px 10px', fontSize: '12.5px', borderRadius: '6px' }}
                >
                  <option value={0}>Permanent (Active until manually removed)</option>
                  <option value={86400}>24 Hours (Temporary Client Testing)</option>
                  <option value={604800}>7 Days (Transient Integration Setup)</option>
                  <option value={2592000}>30 Days (Extended Integration Evaluation)</option>
                </select>
              </div>

              {/* Reason / Note */}
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '4px' }}>
                  Audit Justification / Note:
                </label>
                <input
                  type="text"
                  value={allowlistModal.reason}
                  onChange={(e) => setAllowlistModal(prev => ({ ...prev, reason: e.target.value }))}
                  placeholder="e.g. Authorized client XML-RPC endpoint access"
                  className="webcare-input"
                  style={{ width: '100%', padding: '7px 10px', fontSize: '12px', borderRadius: '6px' }}
                />
              </div>

            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '10px',
              }}
            >
              <button
                type="button"
                onClick={() => setAllowlistModal(prev => ({ ...prev, isOpen: false }))}
                disabled={allowlistModal.isSubmitting}
                className="webcare-btn webcare-btn-secondary"
                style={{ padding: '8px 16px', fontSize: '13px', fontWeight: 600 }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitAllowlist}
                disabled={allowlistModal.isSubmitting}
                className="webcare-btn webcare-btn-primary"
                style={{
                  padding: '8px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                }}
              >
                {allowlistModal.isSubmitting ? <Loader2 size={14} className="webcare-spin-icon" /> : <ShieldCheck size={14} />}
                <span>{allowlistModal.isSubmitting ? 'Saving Allowlist...' : 'Confirm & Apply Exemption'}</span>
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};

export default WafLogsPage;
