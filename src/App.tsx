import { Fragment, useState, useEffect, useRef, useMemo, Component, ReactNode } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __ } from '@wordpress/i18n';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Shield,
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode, 
  Database, 
  Layers, 
  Search, 
  ChevronDown, 
  ChevronRight,
  ChevronLeft,
  ExternalLink, 
  Info, 
  Activity, 
  Archive, 
  RotateCcw,
  Server,
  HardDrive,
  Download,
  Trash2,
  History,
  UserCheck,
  Key,
  RefreshCw,
  FileQuestion,
  FileText,
  Lock,
  Unlock,
  CheckCircle,
  XCircle,
  Zap,
  Filter,
  FileWarning,
  Clock,
  Loader2,
  Terminal,
  Cpu,
  Sparkles,
  Eye,
  Edit3,
  Globe,
  Cloud,
  Copy,
  Check,
  X,
  ArrowUpRight,
  Settings as SettingsIcon,
  Bell,
  Bot,
  LifeBuoy,
  Phone,
  MessageSquare,
  Calendar,
  PlayCircle,
  User,
  Users,
  Folder,
  BookOpen,
  Package,
  SlidersHorizontal,
  Sliders,
  Radar,
  Scan,
  Target,
  Sun,
  Moon,
  LayoutDashboard,
  Image as ImageIcon,
  ZoomIn,
  ZoomOut,
  Grid,
  WrapText,
  Wrench
} from 'lucide-react';
import MegaMenuModal from './components/MegaMenuModal';
import { RescueAssistantModal } from './components/RescueAssistantModal';
import { ConfirmDialog } from './components/ConfirmDialog';
import { InlineConfirmPopover } from './components/InlineConfirmPopover';
import AboutServicesPage from './AboutServicesPage';
import VulnerabilitiesPage from './VulnerabilitiesPage';
import SettingsPage from './SettingsPage';
import NotificationsPage from './NotificationsPage';
import FirewallPage from './FirewallPage';
import ServerTelemetryPage from './ServerTelemetryPage';
import WafLogsPage from './WafLogsPage';
import VirtualPatchPage from './VirtualPatchPage';
import FileIntegrityPage from './FileIntegrityPage';
import AuthSecurityPage from './AuthSecurityPage';
import QuarantinePage from './QuarantinePage';
import VisualDiffModal from './VisualDiffModal';
import ExportResultsDropdown from './ExportResultsDropdown';
import { FilesystemForensicsCard } from './FilesystemForensicsCard';
import { PersistenceSentinelCard } from './components/PersistenceSentinelCard';
import { AttackChainCard } from './components/AttackChainCard';
import DatabaseBackupVault from './components/DatabaseBackupVault';
import WebCareBrandLogo from './components/WebCareBrandLogo';
import { WhitelistModal } from './components/WhitelistModal';
import { DisableWpDebugModal } from './components/DisableWpDebugModal';
import { WhitelistManagerTab } from './components/WhitelistManagerTab';
import { BehavioralBaselineCard } from './components/BehavioralBaselineCard';
import { RemediationTransactionsCard } from './components/RemediationTransactionsCard';
import { WebCareVaultPage } from './WebCareVaultPage';
import AiForensicReportView from './components/AiForensicReportView';
import WelcomeModal from './components/WelcomeModal';
import { CustomScanModal, CUSTOM_SCAN_OPTIONS_CATALOG } from './components/CustomScanModal';
import { ScanLogsPage } from './ScanLogsPage';
import { ForensicsPage } from './ForensicsPage';
import { ActivityLogsPage } from './ActivityLogs/ActivityLogsPage';
import { SecurityScannerPage } from './SecurityScannerPage';
import { DashboardOverview } from './components/DashboardOverview';
import { useWorkspaceMode } from './hooks/useWorkspaceMode';
import { parseWpDate, formatRelativeTime, formatTelemetryTime, formatTelemetryDateFull } from './timeUtils';
import { ContextualSubNav } from './components/ContextualSubNav';
import { WebCareAnimatedLogo } from './components/WebCareAnimatedLogo';
import { applyWebCareTheme, getWebCareTheme } from './utils/theme';
import { toast } from './utils/dialog';
// Global CSS is now provided by build/global.css
// import './index.css';

interface ScanDiagnostics {
  duration_seconds: number;
  duration_ms?: number;
  duration_formatted: string;
  peak_memory_mb: number;
  peak_memory_fmt: string;
  memory_limit_raw: string;
  memory_percent: number;
  scanned_files: number;
  total_files: number;
  files_per_second: number;
  cpu_load?: {
    '1m': number;
    '5m': number;
    '15m': number;
  } | null;
  php_version: string;
  php_sapi: string;
  server_os: string;
  engines_active: number;
}

interface LiveScanTelemetry {
  memory_mb?: number;
  memory_peak_mb?: number;
  memory_limit_raw?: string;
  memory_percent?: number;
  memory_peak_percent?: number;
  memory_free_mb?: number;
  cpu_percent?: number | null;
  cpu_load?: {
    '1m': number;
    '5m': number;
    '15m': number;
  } | null;
  cpu_cores?: number | null;
  scanned_files?: number;
  total_files?: number;
  files_per_sec?: number;
  eta_seconds?: number | null;
  issues_found?: number;
  php_version?: string;
  server_os?: string;
  max_execution_time?: number;
}

const formatElapsedTimer = (seconds: number): string => {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

const formatEtaRemaining = (seconds?: number | null): string => {
  if (seconds === undefined || seconds === null || seconds <= 0 || !isFinite(seconds)) {
    return 'Estimating...';
  }
  if (seconds < 60) return `~${Math.round(seconds)}s remaining`;
  const mins = Math.floor(seconds / 60);
  const rem = Math.round(seconds % 60);
  return `~${mins}m ${rem}s remaining`;
};

interface ScanData {
  id: number;
  status: string;
  scan_target?: string;
  trigger_type?: 'manual' | 'scheduled' | string;
  scanned_files: number;
  total_files: number;
  issues_found: number;
  risk_score: number;
  duration?: number;
  duration_ms?: number;
  duration_formatted?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  diagnostics?: ScanDiagnostics;
}


export interface IssueData {
  id: number;
  scan_id: number;
  engine: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  file_path: string;
  line_number?: number;
  code_snippet?: string;
  evidence?: string;
  description: string;
  status: string;
  is_post?: boolean;
  post_id?: number | null;
  post_title?: string | null;
  post_type?: string | null;
  view_url?: string | null;
  edit_url?: string | null;
  is_comment?: boolean;
  comment_id?: number | null;
  author_id?: number | null;
  author_name?: string | null;
  author_email?: string | null;
  author_url?: string | null;
  author_ip?: string | null;
  comment_date?: string | null;
  comment_content?: string | null;
  is_user?: boolean;
  user_id?: number | null;
  user_login?: string | null;
  user_display_name?: string | null;
  user_nicename?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  user_roles?: string | null;
  user_roles_list?: string[] | null;
  user_email?: string | null;
  user_registered?: string | null;
  injected_caps?: string[] | null;
  all_capabilities?: string[] | null;
  capabilities_count?: number | null;
  user_level?: number | null;
  authored_posts_count?: number | null;
  hash_type?: string | null;
  two_factor_enabled?: boolean | null;
  has_application_passwords?: boolean | null;
  application_passwords_count?: number | null;
  is_current_user?: boolean;
  is_admin?: boolean;
  password_url?: string | null;
  profile_url?: string | null;
  reassign_target_id?: number | null;
  reassign_target_name?: string | null;
  admin_options?: Array<{
    id: number;
    user_login: string;
    display_name: string;
    user_email?: string;
    is_current?: boolean;
  }> | null;
  is_orphaned_author?: boolean;
  sample_post_id?: number | null;
  sample_post_title?: string | null;
  sample_post_slug?: string | null;
  sample_post_type?: string | null;
  sample_post_status?: string | null;
  sample_post_date?: string | null;
  sample_view_url?: string | null;
  sample_edit_url?: string | null;
  is_db_table?: boolean;
  table_name?: string | null;
  column_name?: string | null;
  row_id?: number | null;
  is_log_table?: boolean;
  db_row?: Record<string, any> | null;
  db_primary_key?: string | null;
  is_file?: boolean;
  is_dir?: boolean;
  is_server_config?: boolean;
  is_network?: boolean;
  can_view?: boolean;
  file_exists?: boolean;
  is_software_update?: boolean;
  is_outdated?: boolean;
  has_cve?: boolean;
  installed_version?: string;
  latest_version?: string;
  component_name?: string;
  component_type?: string;
  update_url?: string;
  cves?: Array<{
    cve_id: string;
    title: string;
    severity: string;
    cvss: number;
    fixed_in: string;
    reference: string;
    cve_details: string;
  }>;
  display_title?: string;
  has_update?: boolean;
  author_name?: string;
  author_url?: string;
  component_status?: string;
  last_updated?: string;
  has_changelog?: boolean;
  component_meta?: {
    type?: string;
    slug?: string;
    plugin_file?: string;
    name?: string;
    version?: string;
    latest_version?: string | null;
    has_update?: boolean;
    update_package?: boolean;
    author?: string;
    author_uri?: string;
    theme_uri?: string;
    plugin_uri?: string;
    description?: string;
    is_active?: boolean;
    network_active?: boolean;
    is_child?: boolean;
    parent_name?: string | null;
    parent_version?: string | null;
    status_label?: string;
    requires_wp?: string;
    requires_php?: string;
    text_domain?: string;
    path?: string;
    last_modified?: string;
    last_modified_human?: string;
    folder_perms?: string;
    main_file_perms?: string;
    main_file?: string;
    has_changelog?: boolean;
    changelog_file?: string;
    admin_url?: string;
    classification?: string;
  };
  fs_forensics?: Record<string, any>;
  sha256?: string;
  file_sha256?: string;
}

interface FileViewerData {
  filename: string;
  file_path: string;
  full_path: string;
  sha256?: string;
  md5?: string;
  size_bytes: number;
  size_formatted: string;
  permissions: string;
  is_writable: boolean;
  ctime?: string;
  mtime?: string;
  atime?: string;
  ctime_raw?: number | null;
  mtime_raw?: number | null;
  atime_raw?: number | null;
  owner?: string;
  group?: string;
  ownership?: string;
  mime_type?: string;
  modified_at?: string;
  line_count: number;
  content: string;
  is_truncated: boolean;
  is_masked?: boolean;
  is_image?: boolean;
  is_valid_image?: boolean;
  image_mime?: string | null;
  image_base64?: string | null;
  image_dimensions?: { width: number | null; height: number | null } | null;
  image_security?: {
    is_valid_binary: boolean;
    detected_type: string | null;
    magic_bytes_match: boolean;
    threat_warning: string | null;
    has_embedded_php: boolean;
    disguised_exec: string | null;
  };
}

interface PostViewerData {
  post_id: number;
  title: string;
  post_type: string;
  post_status: string;
  author: string;
  content: string;
  view_url: string;
  edit_url: string;
  date?: string;
  modified?: string;
}

interface ScannedFileInfo {
  id: number;
  scan_id: number;
  file_path: string;
  file_size: number;
  status: 'clean' | 'threat';
  scanned_at: string;
}

interface QuarantineRecord {
  id: number;
  scan_id?: number;
  issue_id?: number;
  original_path: string;
  quarantine_filename: string;
  sha256: string;
  file_size: number;
  status: 'quarantined' | 'restored';
  quarantined_at: string;
  restored_at?: string;
}

interface RiskSummary {
  score: number;
  level: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total: number;
}

interface BackupItem {
  filename: string;
  size_mb: number;
  size_bytes: number;
  created: string;
  timestamp: number;
}

interface ServerInfoData {
  php: {
    version: string;
    sapi: string;
    memory_limit: string;
    memory_usage_mb: number;
    max_execution_time: number;
    upload_max_filesize: string;
    post_max_size: string;
    display_errors: string;
    disabled_functions: string[];
    extensions: Record<string, boolean>;
  };
  database: {
    version: string;
    name: string;
    host: string;
    charset: string;
    collate: string;
    size_mb: number;
    table_prefix: string;
  };
  server: {
    software: string;
    os: string;
    arch: string;
    ip: string;
    server_ip?: string;
    webroot: string;
  };
  wordpress: {
    version: string;
    debug: boolean;
    debug_log: boolean;
    debug_display: boolean;
    ssl: boolean;
    ssl_active?: boolean;
    multisite: boolean;
  };
  permissions: {
    'wp-config.php': string;
    '.htaccess': string;
    'wp-content': string;
    'uploads': string;
  };
  filesystem?: {
    total_files: number;
    php_files: number;
    js_files: number;
    css_files: number;
    extension_counts: Record<string, number>;
    total_size_mb: number;
    wp_admin_size_mb: number;
    wp_includes_size_mb: number;
    wp_content_size_mb: number;
    plugins_size_mb: number;
    themes_size_mb: number;
    uploads_size_mb: number;
  };
}

type NavTab =
  | 'dashboard'
  | 'scan'
  | 'targeted'
  | 'logs'
  | 'forensics'
  | 'vault'
  | 'quarantine'
  | 'backup'
  | 'server'
  | 'vulnerabilities'
  | 'firewall'
  | 'vpatch'
  | 'waf_logs'
  | 'fim'
  | 'auth'
  | 'notifications'
  | 'activity_logs'
  | 'cron_manager'
  | 'settings'
  | 'about';

const TAB_TO_PAGE: Record<string, string> = {
  dashboard: 'webcare-pro-security',
  scan: 'webcare-pro-scanner',
  targeted: 'webcare-pro-scanner',
  logs: 'webcare-pro-logs',
  forensics: 'webcare-pro-backups',
  vault: 'webcare-pro-backups',
  quarantine: 'webcare-pro-backups',
  backup: 'webcare-pro-backups',
  server: 'webcare-pro-backups',
  vulnerabilities: 'webcare-pro-scanner',
  firewall: 'webcare-pro-firewall',
  vpatch: 'webcare-pro-firewall',
  waf_logs: 'webcare-pro-logs',
  fim: 'webcare-pro-scanner',
  auth: 'webcare-pro-login',
  notifications: 'webcare-pro-settings',
  activity_logs: 'webcare-pro-logs',
  cron_manager: 'webcare-pro-settings',
  settings: 'webcare-pro-settings',
  about: 'webcare-pro-settings',
};

const PAGE_TO_TAB: Record<string, NavTab> = {
  'webcare-pro-security': 'dashboard',
  'webcare-pro-scanner': 'scan',
  'webcare-pro-scan': 'scan',
  'webcare-pro-tools': 'targeted',
  'webcare-pro-logs': 'logs',
  'webcare-pro-forensics': 'forensics',
  'webcare-pro-backups': 'vault',
  'webcare-pro-vault': 'vault',
  'webcare-pro-quarantine': 'vault',
  'webcare-pro-backup': 'backup',
  'webcare-pro-server': 'server',
  'webcare-pro-vulnerabilities': 'vulnerabilities',
  'webcare-pro-firewall': 'firewall',
  'webcare-pro-vpatch': 'firewall',
  'webcare-pro-waf-logs': 'waf_logs',
  'webcare-pro-fim': 'fim',
  'webcare-pro-login': 'auth',
  'webcare-pro-auth': 'auth',
  'webcare-pro-notifications': 'notifications',
  'webcare-pro-activity-logs': 'activity_logs',
  'webcare-pro-cron-manager': 'cron_manager',
  'webcare-pro-settings': 'settings',
  'webcare-pro-about': 'about',
};



// Resilient REST API client resolving against localized rest_url with automatic nonce attachment
const apiRequest = async (options: { path: string; method?: string; data?: any }) => {
  const root = (window as any).webcareScannerSettings?.root;
  const nonce = (window as any).webcareScannerSettings?.nonce;

  if (root) {
    const cleanRoot = root.replace(/\/$/, '');
    const rawSubPath = (options.path || '').replace(/^\/?webcare-pro-security\/v1/, '');
    const normalizedSubPath = rawSubPath.startsWith('/') ? rawSubPath : `/${rawSubPath}`;
    
    // Correctly split path from query string so plain permalinks (with ?rest_route=) use & instead of duplicate ?
    const [pathPart, queryPart] = normalizedSubPath.split('?');
    
    let url: string;
    if (cleanRoot.includes('?')) {
      url = `${cleanRoot}${pathPart}`;
      if (queryPart) {
        url += (url.includes('?') ? '&' : '?') + queryPart;
      }
    } else {
      url = `${cleanRoot}${pathPart}`;
      if (queryPart) {
        url += `?${queryPart}`;
      }
    }

    return apiFetch({
      url,
      method: options.method || 'GET',
      data: options.data,
      headers: nonce ? { 'X-WP-Nonce': nonce } : undefined,
    });
  }

  const rawPath = options.path || '';
  const namespacedPath = rawPath.startsWith('/webcare-pro-security/v1')
    ? rawPath
    : `/webcare-pro-security/v1${rawPath.startsWith('/') ? rawPath : `/${rawPath}`}`;
  return apiFetch({
    ...options,
    path: namespacedPath,
    headers: nonce ? { 'X-WP-Nonce': nonce, ...(options as any).headers } : (options as any).headers,
  });
};

// Metadata for target profiles
const TARGET_META: Record<string, { title: string; steps: string[] }> = {
  suspicious_uploads: {
    title: 'Uploads Executables & Shell Audit',
    steps: [
      'Traversing wp-content/uploads/ directory structure...',
      'Checking extensions for forbidden PHP (.php, .phtml, .phar) & shell scripts (.sh, .bash)...',
      'Scanning for stealth double extensions (e.g. image.png.php, photo.jpg.sh)...',
      'Inspecting uploaded media assets for embedded PHP execution tags (<?php, <?=)...',
      'Verifying directory permissions & rogue .htaccess overrides...',
      'Finalizing uploads threat classification & risk scoring...'
    ]
  },
  unknown_files: {
    title: 'Unknown Files Integrity Audit',
    steps: [
      'Querying WordPress.org Core & Plugin official checksum repositories...',
      'Reconciling wp-admin & wp-includes against official distribution manifests...',
      'Reverse auditing active plugins & themes directories for rogue files...',
      'Isolating unverified scripts, backdoors & orphan artifacts...',
      'Finalizing integrity reconciliation report...'
    ]
  },
  spam_content: {
    title: 'Spam Content & Database Audit',
    steps: [
      'Querying database posts, pages, and revision tables...',
      'Inspecting post content for blackhat SEO keywords, pharma spam & cloaked links...',
      'Auditing user comments database for spam injection vectors...',
      'Scanning wp_options for serialized payload modifications...',
      'Compiling spam threat summary...'
    ]
  },
  filesystem_only: {
    title: 'Filesystem Permissions & Symlinks Audit',
    steps: [
      'Collecting filesystem manifest across WordPress root directory...',
      'Auditing file & folder permissions against WordPress security standards...',
      'Detecting hazardous symlinks pointing outside web document root...',
      'Analyzing hidden executable files & directory structures...',
      'Finalizing filesystem security report...'
    ]
  },
  user_security: {
    title: 'User Accounts, Roles & Capability Auditor',
    steps: [
      'Retrieving registered user accounts & security capability roles...',
      'Auditing user capabilities against role definitions to detect stealth privilege escalation...',
      'Scanning for Trojan Customers & Subscribers with file upload or editing rights...',
      'Checking for ghost user accounts missing standard capability metadata...',
      'Auditing global role definitions in wp_user_roles for tampering...',
      'Testing password hashes against high-frequency dictionary attack databases...',
      'Finalizing user account & credential security breakdown...'
    ]
  },
  outdated_software: {
    title: 'Outdated Software & Vulnerability Audit',
    steps: [
      'Checking WordPress core version against latest security releases...',
      'Querying WordPress.org Plugin API for updates & deprecations...',
      'Inspecting active and installed themes for available patches...',
      'Evaluating vulnerability risk indices for installed software...',
      'Compiling software update advisory...'
    ]
  },
  crontab_audit: {
    title: 'Crontab & Scheduled Tasks Audit',
    steps: [
      'Querying Linux server crontab (crontab -l & /var/spool/cron)...',
      'Inspecting system cron jobs for remote piped shells (curl|bash, wget|sh)...',
      'Analyzing reverse shell vectors, /dev/tcp pipes, and base64 decode executions...',
      'Auditing WordPress virtual wp-cron array for malicious hooks & orphaned events...',
      'Verifying cron task execution targets in uploads or temp folders...',
      'Finalizing crontab persistence forensic report...'
    ]
  },
  core_integrity: {
    title: 'WordPress Core Integrity Audit',
    steps: [
      'Querying official WordPress.org release checksum API for WordPress core...',
      'Verifying cryptographic MD5 hashes of wp-admin, wp-includes & root bootstrap files...',
      'Detecting modified, tampered, or injected core files...',
      'Reverse reconciling core directories for unknown rogue backdoor scripts...',
      'Checking for missing WordPress core dependencies...',
      'Finalizing core integrity verification...'
    ]
  },
  modified_files: {
    title: 'Modified Themes, Plugins & Core Audit',
    steps: [
      'Querying official WordPress.org release checksum APIs for Core, Plugins & Themes...',
      'Verifying cryptographic hashes of all installed WordPress core files...',
      'Reconciling active and installed plugin files against official distribution manifests...',
      'Comparing theme template files against pristine release checksums...',
      'Auditing critical bootstrap files (wp-config.php, .htaccess, index.php)...',
      'Inspecting modified files with AST lexer for injected malware wrappers & shells...',
      'Finalizing modified files integrity & tampering report...'
    ]
  },
  rogue_admin: {
    title: 'Rogue Admins & DB Anomalies Audit',
    steps: [
      'Scanning wp_users and wp_usermeta for hidden administrative accounts...',
      'Auditing user role capabilities and privilege escalation anomalies...',
      'Verifying ghost user accounts missing standard WordPress registration metadata...',
      'Inspecting database options and transients for stealth backdoor payloads...',
      'Finalizing rogue admin and database anomalies breakdown...'
    ]
  },
  hook_sentinel: {
    title: 'Hook Sentinel & LotL Traps Audit',
    steps: [
      'Inspecting all registered WordPress actions and filter hooks in runtime memory...',
      'Auditing closures, anonymous functions, and high-risk hook callbacks...',
      'Detecting Living-off-the-Land (LotL) execution traps and stealth persistence...',
      'Evaluating mu-plugins and theme functions for dynamic code evaluation hooks...',
      'Finalizing hook infiltration sentinel security report...'
    ]
  }
};

export interface ScanTargetInfo {
  name: string;
  shortName: string;
  category: 'custom' | 'targeted' | 'standard';
  categoryLabel: string;
  badgeBg: string;
  badgeColor: string;
  badgeBorder: string;
  iconType: 'custom' | 'targeted' | 'standard';
  description: string;
}

export const getScanTargetInfo = (target?: string): ScanTargetInfo => {
  const t = (target || 'plugins_themes').toLowerCase().trim();

  if (t === 'custom') {
    return {
      name: 'Custom Security Scan',
      shortName: 'Custom Scan',
      category: 'custom',
      categoryLabel: 'Custom Scan',
      badgeBg: '#faf5ff',
      badgeColor: '#7e22ce',
      badgeBorder: '#e9d5ff',
      iconType: 'custom',
      description: 'Administrator-configured modular audit tailored to specific security engines and directories.'
    };
  }

  if (t === 'plugins_themes') {
    return {
      name: 'Quick Scan (Plugins & Themes)',
      shortName: 'Quick Scan',
      category: 'standard',
      categoryLabel: 'Standard Scan',
      badgeBg: '#eff6ff',
      badgeColor: '#1d4ed8',
      badgeBorder: '#bfdbfe',
      iconType: 'standard',
      description: 'Standard audit of active and installed plugins and themes.'
    };
  }

  if (t === 'full' || t === 'full_filesystem') {
    return {
      name: 'Complete Website Scan (Full Filesystem)',
      shortName: 'Complete Scan',
      category: 'standard',
      categoryLabel: 'Standard Scan',
      badgeBg: '#f0fdf4',
      badgeColor: '#15803d',
      badgeBorder: '#bbf7d0',
      iconType: 'standard',
      description: 'Comprehensive audit of entire WordPress root, core, plugins, themes, uploads, and database.'
    };
  }

  const TARGETED_MAP: Record<string, { name: string; shortName: string; desc: string }> = {
    modified_files: {
      name: 'Targeted: Modified Themes, Plugins & Core Audit',
      shortName: 'Targeted: Modified Files',
      desc: 'Cryptographic checksum verification against official WordPress.org manifests.'
    },
    suspicious_uploads: {
      name: 'Targeted: Uploads Executables & Shell Audit',
      shortName: 'Targeted: Uploads',
      desc: 'Forensic scan isolating dangerous scripts, shells, and double extensions in uploads.'
    },
    unknown_files: {
      name: 'Targeted: Unknown Files Integrity Audit',
      shortName: 'Targeted: Unknown Files',
      desc: 'Reconciliation against official repositories to detect orphan files and backdoors.'
    },
    spam_content: {
      name: 'Targeted: Spam Content & Database Audit',
      shortName: 'Targeted: Spam Content',
      desc: 'Database scan hunting for cloaked spam, blackhat SEO injections, and malicious comments.'
    },
    filesystem_only: {
      name: 'Targeted: Filesystem Permissions & Symlinks Audit',
      shortName: 'Targeted: Filesystem',
      desc: 'Audit evaluating Unix permissions, writeability hazards, and symlink breakouts.'
    },
    user_security: {
      name: 'Targeted: User Accounts, Roles & Capability Auditor',
      shortName: 'Targeted: User Accounts',
      desc: 'Inspection of rogue administrator privileges, ghost users, and weak credentials.'
    },
    outdated_software: {
      name: 'Targeted: Outdated Software & Vulnerability Audit',
      shortName: 'Targeted: Outdated Software',
      desc: 'CVE intelligence matching against active WordPress core, plugins, and themes.'
    },
    crontab_audit: {
      name: 'Targeted: Crontab & Scheduled Tasks Audit',
      shortName: 'Targeted: Crontab Audit',
      desc: 'Linux crontab and WP-Cron virtual hook inspection for scheduled stealth persistence.'
    },
    crontab_hooks: {
      name: 'Targeted: Crontab & Scheduled Tasks Audit',
      shortName: 'Targeted: Crontab Audit',
      desc: 'Linux crontab and WP-Cron virtual hook inspection.'
    },
    core_integrity: {
      name: 'Targeted: WordPress Core Integrity Audit',
      shortName: 'Targeted: Core Integrity',
      desc: 'Cryptographic checksum verification strictly auditing core WordPress files.'
    },
    rogue_admin: {
      name: 'Targeted: Rogue Admins & DB Anomalies Audit',
      shortName: 'Targeted: Rogue Admins',
      desc: 'Database scan detecting backdoor accounts, hidden administrators, and tampered capability roles.'
    },
    hook_sentinel: {
      name: 'Targeted: Hook Sentinel & LotL Traps Audit',
      shortName: 'Targeted: Hook Sentinel',
      desc: 'Runtime inspection uncovering malicious filters, actions, and Living-off-the-Land persistence hooks.'
    },
    uploads_database: {
      name: 'Targeted: Uploads & Database Audit',
      shortName: 'Targeted: Uploads & DB',
      desc: 'Inspection of media uploads folder and database tables.'
    }
  };

  if (TARGETED_MAP[t]) {
    return {
      name: TARGETED_MAP[t].name,
      shortName: TARGETED_MAP[t].shortName,
      category: 'targeted',
      categoryLabel: 'Targeted Scan',
      badgeBg: '#f0f9ff',
      badgeColor: '#0369a1',
      badgeBorder: '#bae6fd',
      iconType: 'targeted',
      description: TARGETED_MAP[t].desc
    };
  }

  const isCustom = t.includes('custom');
  const formatted = t.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

  return {
    name: isCustom ? `Custom Scan: ${formatted}` : `Targeted: ${formatted}`,
    shortName: isCustom ? 'Custom Scan' : `Targeted: ${formatted}`,
    category: isCustom ? 'custom' : 'targeted',
    categoryLabel: isCustom ? 'Custom Scan' : 'Targeted Scan',
    badgeBg: isCustom ? '#faf5ff' : '#f0f9ff',
    badgeColor: isCustom ? '#7e22ce' : '#0369a1',
    badgeBorder: isCustom ? '#e9d5ff' : '#bae6fd',
    iconType: isCustom ? 'custom' : 'targeted',
    description: 'Specialized security audit.'
  };
};

const TARGETED_SCAN_TYPES = [
  'modified_files',
  'suspicious_uploads',
  'unknown_files',
  'spam_content',
  'filesystem_only',
  'user_security',
  'outdated_software',
  'crontab_audit',
  'core_integrity',
  'rogue_admin',
  'hook_sentinel'
];

export const getFindingDisplayTitle = (issue: any): string => {
  if (!issue) return '';
  if (issue.display_title) {
    return issue.display_title;
  }
  if (issue.type === 'vulnerable_plugin') {
    return issue.component_name ? `Vulnerable Plugin: ${issue.component_name}` : 'Vulnerable Plugin';
  }
  if (issue.type === 'outdated_plugin') {
    return issue.component_name ? `Outdated Plugin: ${issue.component_name}` : 'Outdated Plugin';
  }
  if (issue.type === 'vulnerable_theme') {
    return issue.component_name ? `Vulnerable Theme: ${issue.component_name}` : 'Vulnerable Theme';
  }
  if (issue.type === 'outdated_theme') {
    return issue.component_name ? `Outdated Theme: ${issue.component_name}` : 'Outdated Theme';
  }
  if (issue.type === 'vulnerable_core') {
    return 'Vulnerable WordPress Core';
  }
  if (issue.type === 'outdated_core') {
    return 'Outdated WordPress Core';
  }
  if (issue.engine === 'wordpress-updates' || issue.is_software_update) {
    return 'Software Update Available';
  }
  if (issue.type === 'theme_checksums_unavailable') {
    const path = (issue.file_path || '').toLowerCase();
    const desc = (issue.description || '').toLowerCase();
    if (path.includes('-child') || desc.includes('child')) {
      return 'Custom Child Theme';
    }
    if (path.match(/\b(premium|pro|themeforest|envato)\b/) || desc.includes('premium')) {
      return 'Premium Theme';
    }
    return 'Custom or Premium Theme';
  }
  if (issue.type === 'plugin_checksums_unavailable') {
    const path = (issue.file_path || '').toLowerCase();
    const desc = (issue.description || '').toLowerCase();
    if (path.match(/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/) || path.match(/\b(yith|woocommerce)\b/) || desc.includes('premium')) {
      return 'Premium Plugin';
    }
    return 'Custom or Premium Plugin';
  }

  if (issue.type === 'weak_admin_password') {
    return 'Weak Administrator Password';
  }
  if (issue.type === 'weak_user_password') {
    return 'Weak User Password';
  }
  if (issue.type === 'weak_password_detected') {
    const isExplicitAdmin = issue.severity === 'critical' || (Array.isArray(issue.roles) && issue.roles.includes('administrator')) || issue.role === 'administrator';
    return isExplicitAdmin ? 'Weak Administrator Password' : 'Weak User Password';
  }

  const typeMap: Record<string, string> = {
    weak_password_detected: 'Weak User Password',
    weak_admin_password: 'Weak Administrator Password',
    weak_user_password: 'Weak User Password',
    username_enumeration_risk: 'Username Enumeration Vulnerability',
    generic_admin_username: 'Generic Admin Username',
    user_missing_capabilities: 'User Account Missing Role Capabilities',
    suspicious_user_capabilities: 'Suspicious User Capabilities',
    injected_user_capabilities: 'Injected User Capabilities',
    tampered_role_definition: 'Tampered Role Definition',
    orphaned_post_author: 'Orphaned Post Author',
    webshell_pattern: 'Webshell Signature Pattern',
    obfuscated_malware_payload: 'Obfuscated Malware Payload',
    suspicious_strings: 'Suspicious Remote Code Strings',
    obfuscation_detected: 'Code Obfuscation Detected',
    executable_in_uploads: 'Executable Script in Uploads Directory',
    unsafe_permissions: 'Unsafe File Permissions',
    symlink_detected: 'Filesystem Symbolic Link',
    unknown_core_file: 'Unrecognized Core Directory File',
    unknown_wp_admin_file: 'Unrecognized WP-Admin File',
    unknown_wp_includes_file: 'Unrecognized WP-Includes File',
    modified_core_file: 'Modified WordPress Core File',
    modified_theme_file: 'Modified Theme File',
    modified_plugin_file: 'Modified Plugin File',
    missing_core_file: 'Missing WordPress Core File',
    eval_in_options: 'PHP Code in WordPress Options',
    base64_in_options: 'Base64 Payload in Options',
    serialized_injection: 'Serialized Object Injection',
    malicious_cron_hook: 'Suspicious Scheduled Cron Hook',
    malicious_cron_hook_name: 'Suspicious Scheduled Cron Hook',
    orphaned_cron_hook: 'Orphaned Scheduled Cron Hook',
    malicious_system_crontab: 'Malicious System Crontab Entry',
    suspicious_crontab_execution: 'Suspicious Crontab Execution',
    hidden_directory_crontab: 'Hidden Directory Crontab Task',
    malicious_mu_plugin: 'Suspicious Must-Use (MU) Plugin',
    mu_plugin_warning: 'Unverified Must-Use Plugin',
    unexpected_wp_content_file: 'Unexpected File in WP-Content',
    malicious_dropin: 'Malicious WordPress Drop-in',
    unauthorized_dropin: 'Unauthorized WordPress Drop-in',
    db_autoload_malware_anchor: 'Autoload Database Malware Anchor',
    self_healing_malware_resurrection: 'Self-Healing Malware Persistence',
    rogue_server_preloader: 'Rogue Server Auto-Preloader',
    ini_auto_prepend: 'PHP INI auto_prepend_file Injection',
    ini_auto_append: 'PHP INI auto_append_file Injection',
    user_ini_preloader: 'User INI Preload Injection',
    htaccess_preloader: 'htaccess Preload Injection',
    core_checksums_unavailable: 'WordPress Core Checksums Unavailable',
  };

  if (issue.type && typeMap[issue.type]) {
    return typeMap[issue.type];
  }

  if (issue.type) {
    return issue.type
      .replace(/[-_]+/g, ' ')
      .replace(/\b\w/g, (char: string) => char.toUpperCase());
  }

  return issue.type || '';
};

export class SafeErrorBoundary extends Component<{ children: ReactNode; fallbackTitle?: string }, { hasError: boolean; error: Error | null }> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('WebCare finding details rendering error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', padding: '16px', marginTop: '12px', color: '#991b1b', fontSize: '13px' }}>
          <div style={{ fontWeight: 700, marginBottom: '4px' }}>{this.props.fallbackTitle || 'Unable to render detailed forensic panel'}</div>
          <div style={{ fontSize: '12px', color: '#b91c1c' }}>{this.state.error?.message || 'An unexpected rendering error occurred.'}</div>
        </div>
      );
    }
    return this.props.children;
  }
}

interface ComponentForensicsCardProps {
  issue: IssueData;
  onOpenChangelog: (issue: IssueData) => void;
  onCopyPath: (path: string) => void;
  copiedPath: string | null;
}

export const ComponentForensicsCard = ({
  issue,
  onOpenChangelog,
  onCopyPath,
  copiedPath,
}: ComponentForensicsCardProps) => {
  const meta = issue.component_meta || {};
  const isTheme = issue.component_type === 'theme' || meta.type === 'theme' || issue.type?.includes('theme') || issue.file_path?.includes('/themes/') || issue.engine === 'integrity-theme';
  const typeLabel = isTheme ? 'Theme' : 'Plugin';
  const name = issue.component_name || meta.name || issue.file_path?.split(/[/|\\]/).filter(Boolean).pop() || 'Component';
  const version = issue.installed_version || meta.version || '';
  const latestVersion = issue.latest_version || meta.latest_version;
  const hasUpdate = issue.has_update || meta.has_update;
  const author = issue.author_name || meta.author;
  const authorUri = issue.author_url || meta.author_uri;
  const homeUri = meta.plugin_uri || meta.theme_uri;
  const statusLabel = issue.component_status || meta.status_label || (meta.is_active ? 'Active' : 'Inactive');
  const isActive = meta.is_active;
  const lastMod = issue.last_updated || meta.last_modified;
  const lastModHuman = meta.last_modified_human;
  const requiresWp = meta.requires_wp;
  const requiresPhp = meta.requires_php;
  const textDomain = meta.text_domain;
  const folderPerms = meta.folder_perms || '0755';
  const mainFile = meta.main_file;
  const mainFilePerms = meta.main_file_perms;
  const adminUrl = meta.admin_url || (isTheme ? 'themes.php' : 'plugins.php');
  const parentName = meta.parent_name;
  const parentVersion = meta.parent_version;
  const isChild = Boolean(meta.is_child || parentName || (issue.file_path && issue.file_path.toLowerCase().includes('-child')));
  const isUnmanaged = issue.type === 'plugin_checksums_unavailable' || issue.type === 'theme_checksums_unavailable';
  const isWpOrg = !isUnmanaged && Boolean((meta.is_wporg ?? issue.is_wporg) || issue.engine === 'wordpress-updates' || issue.type === 'outdated_plugin' || issue.type === 'outdated_theme' || issue.type === 'vulnerable_plugin' || issue.type === 'vulnerable_theme');
  const classification = isUnmanaged
    ? (issue.display_title || (meta.classification && !meta.classification.includes('Official') ? meta.classification : (isTheme ? (isChild ? 'Custom Child Theme' : 'Custom or Premium Theme') : 'Premium Plugin')))
    : (meta.classification || (isWpOrg ? (isTheme ? 'Official WordPress Theme' : 'Official WordPress Plugin') : (issue.display_title || (isTheme ? (isChild ? 'Custom Child Theme' : 'Custom or Premium Theme') : 'Custom or Premium Plugin'))));
  const isPremium = !isWpOrg && (classification.toLowerCase().includes('premium') || classification.toLowerCase().includes('pro'));

  return (
    <SafeErrorBoundary fallbackTitle="Component Forensics Unavailable">
      <div className="webcare-component-forensics-card">
      {/* Header Bar */}
      <div className="webcare-component-forensics-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: isTheme ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.15), rgba(30, 64, 175, 0.25))' : 'linear-gradient(135deg, rgba(22, 163, 74, 0.15), rgba(21, 128, 61, 0.25))', display: 'flex', alignItems: 'center', justifyContent: 'center', border: `1px solid ${isTheme ? 'rgba(56, 189, 248, 0.3)' : 'rgba(52, 211, 153, 0.3)'}`, flexShrink: 0 }}>
            {isTheme ? <Layers size={22} color="#38bdf8" /> : <Package size={22} color="#34d399" />}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h4 className="webcare-component-title">
                {name}
              </h4>
              <span
                className={isWpOrg ? 'webcare-component-badge-wporg' : (isPremium ? 'webcare-component-badge-premium' : 'webcare-component-badge-custom')}
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '5px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                {isWpOrg && <CheckCircle size={11} />}
                {isPremium && <Sparkles size={11} />}
                {classification}
              </span>
              <span
                className={isActive ? 'webcare-component-badge-active' : 'webcare-component-badge-inactive'}
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '5px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px'
                }}
              >
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: isActive ? '#10b981' : '#94a3b8' }} />
                {statusLabel}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', fontSize: '12px', flexWrap: 'wrap' }}>
              <span className="webcare-component-path">{issue.file_path}</span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onCopyPath(issue.file_path);
                }}
                style={{ background: 'none', border: 'none', padding: '2px', cursor: 'pointer', color: copiedPath === issue.file_path ? '#34d399' : '#94a3b8', display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px' }}
                title="Copy folder path"
              >
                {copiedPath === issue.file_path ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
                <span>{copiedPath === issue.file_path ? 'Copied' : 'Copy Path'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Quick Action Toolbar */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-forensics-changelog"
            onClick={() => onOpenChangelog(issue)}
            title="Read release notes and changelog history in modal"
          >
            <BookOpen size={13} />
            <span>View Changelog</span>
          </button>

          {adminUrl && (
            <a
              href={adminUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-btn webcare-btn-forensics-admin"
              title={`Open WordPress ${typeLabel} manager in wp-admin`}
            >
              <span>Manage in WP-Admin</span>
              <ArrowUpRight size={12} />
            </a>
          )}

          {homeUri && (
            <a
              href={homeUri}
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-btn webcare-btn-forensics-website"
              title="Visit official plugin/theme documentation or homepage"
            >
              <Globe size={12} />
              <span>Official Website</span>
              <ExternalLink size={11} />
            </a>
          )}
        </div>
      </div>

      {/* Forensic Metrics 4-Column Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px' }}>
        {/* Installed Version */}
        <div className="webcare-component-metric-card">
          <div className="webcare-component-metric-label">
            Installed Version
          </div>
          <div className="webcare-component-metric-val" style={{ fontFamily: 'monospace' }}>
            {version ? `v${version}` : 'Not Specified'}
          </div>
          <div className="webcare-component-metric-sub">
            Local disk deployment
          </div>
        </div>

        {/* Latest Version / Update Status */}
        <div className={`webcare-component-metric-card ${hasUpdate ? 'webcare-update-status-alert' : latestVersion ? 'webcare-update-status-clean' : 'webcare-update-status-unmanaged'}`}>
          <div className="webcare-component-metric-label webcare-status-title">
            Update Status
          </div>
          <div className="webcare-component-metric-val webcare-status-val">
            {hasUpdate ? `v${latestVersion} Available` : latestVersion ? `v${latestVersion} (Up to Date)` : 'Unmanaged / Vendor'}
          </div>
          <div className="webcare-component-metric-sub">
            {hasUpdate ? 'New release waiting in WP updates' : latestVersion ? 'Matches current upstream release' : 'Vendor-licensed / private repository'}
          </div>
        </div>

        {/* Author / Maintainer */}
        <div className="webcare-component-metric-card">
          <div className="webcare-component-metric-label">
            Author / Developer
          </div>
          <div className="webcare-component-metric-val" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={author || 'Unknown'}>
            {author || 'Unknown Author'}
          </div>
          <div style={{ fontSize: '11px', marginTop: '2px' }}>
            {authorUri ? (
              <a href={authorUri} target="_blank" rel="noopener noreferrer" style={{ color: '#38bdf8', display: 'inline-flex', alignItems: 'center', gap: '3px', textDecoration: 'none' }}>
                <span>Author Website</span>
                <ExternalLink size={10} />
              </a>
            ) : (
              <span className="webcare-component-metric-sub">No author URL declared</span>
            )}
          </div>
        </div>

        {/* Last Modified Date */}
        <div className="webcare-component-metric-card">
          <div className="webcare-component-metric-label">
            Last Modified Date
          </div>
          <div className="webcare-component-metric-val" style={{ fontSize: '13px' }}>
            {lastMod || 'Unknown'}
          </div>
          <div className="webcare-component-metric-sub">
            {lastModHuman ? `${lastModHuman} on server` : 'Server timestamp'}
          </div>
        </div>
      </div>

      {/* Secondary Forensic Attributes */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '10px', fontSize: '12px' }}>
        {isTheme && isChild && (
          <div className="webcare-component-sub-strip" style={{ color: '#38bdf8' }}>
            <strong>Parent Theme:</strong> {parentName || 'Template'} {parentVersion && `(v${parentVersion})`}
          </div>
        )}
        <div className="webcare-component-sub-strip">
          <strong>WordPress Requirements:</strong> {requiresWp ? `Requires WP ${requiresWp}+` : 'Standard WP'} &bull; {requiresPhp ? `PHP ${requiresPhp}+` : 'Standard PHP'}
        </div>
        <div className="webcare-component-sub-strip">
          <strong>Text Domain:</strong> <code style={{ fontFamily: 'monospace', fontWeight: 600, color: '#38bdf8' }}>{textDomain || 'None'}</code>
        </div>
        <div className="webcare-component-sub-strip">
          <strong>Filesystem Perms:</strong> Folder <code className="webcare-parent-perms-pill">{folderPerms}</code> {mainFile && `• File ${mainFilePerms || '0644'} (${mainFile})`}
        </div>
      </div>

      {/* Author Description if Provided */}
      {meta.description && (
        <div className="webcare-component-desc-box">
          <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Description:</strong> {meta.description}
        </div>
      )}

      {/* Forensic Security & Integrity Advisory (Only for custom/unmanaged components) */}
      {!isWpOrg && (issue.type === 'theme_checksums_unavailable' || issue.type === 'plugin_checksums_unavailable' || issue.engine?.includes('integrity')) && (
        <div className="webcare-component-desc-box" style={{ borderLeftColor: '#94a3b8' }}>
          <strong>Directory Integrity Advisory:</strong> This {typeLabel.toLowerCase()} is not hosted on public WordPress.org repositories and relies on proprietary vendor or custom source trees. File integrity verification cannot automatically download official WordPress.org checksums. Ensure all future updates and patches are procured exclusively through your authorized vendor account.
        </div>
      )}

      {/* Official Repository Update Recommendation */}
      {isWpOrg && hasUpdate && (
        <div style={{ fontSize: '12px', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.25)', padding: '12px 14px', borderRadius: '8px', borderLeft: '3px solid #38bdf8', lineHeight: 1.5, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <strong style={{ color: '#f0f9ff' }}>Official Repository Release:</strong> An update to <strong>v{latestVersion}</strong> is available in the official WordPress.org directory. You can inspect the release notes via <strong>View Changelog</strong> above or update this component directly in WP-Admin.
          </div>
          {adminUrl && (
            <a href={adminUrl} target="_blank" rel="noopener noreferrer" className="webcare-btn" style={{ background: '#2563eb', color: '#ffffff', border: 'none', padding: '5px 12px', fontSize: '11px', fontWeight: 600, borderRadius: '5px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <span>Update in WP-Admin</span> <ArrowUpRight size={10} />
            </a>
          )}
        </div>
      )}
    </div>
  </SafeErrorBoundary>
  );
};

interface ChangelogModalProps {
  modal: {
    isOpen: boolean;
    name: string;
    slug: string;
    version: string;
    type: 'theme' | 'plugin';
    path: string;
    loading: boolean;
    error: string | null;
    filename: string;
    content: string;
    lastModified?: string;
    fileSize?: number;
    source?: string;
    sourceLabel?: string;
    isLatest?: boolean;
    latestNotFound?: boolean;
    versionShown?: string;
    latestVersion?: string;
    installedVersion?: string;
    notice?: string;
  };
  onClose: () => void;
  onCopy: (text: string) => void;
  copied: boolean;
}

const ChangelogModal = ({
  modal,
  onClose,
  onCopy,
  copied,
}: ChangelogModalProps) => {
  if (!modal.isOpen) return null;

  const fileSizeKb = modal.fileSize ? (modal.fileSize / 1024).toFixed(1) : null;
  const lineCount = modal.content ? modal.content.split('\n').length : 0;

  return (
    <div
      className="webcare-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="webcare-modal-window webcare-changelog-modal" style={{ maxWidth: '900px', width: '95%' }}>
        {/* Header */}
        <div className="webcare-changelog-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
            <div className="webcare-modal-icon-badge" style={{ background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)' }}>
              <BookOpen size={22} color="#ffffff" />
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <h3 className="webcare-changelog-title">
                  {modal.name}
                </h3>
                <span className="webcare-badge webcare-badge-changelog">
                  CHANGELOG
                </span>
                {modal.isLatest ? (
                  <span className="webcare-badge webcare-badge-latest" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    <Sparkles size={11} color="#10b981" /> LATEST v{modal.versionShown || modal.latestVersion || modal.version}
                  </span>
                ) : (
                  (modal.versionShown || modal.installedVersion || modal.version) && (
                    <span className={`webcare-badge ${modal.latestNotFound ? 'webcare-badge-warning' : 'webcare-badge-installed'}`}>
                      INSTALLED v{modal.versionShown || modal.installedVersion || modal.version}
                    </span>
                  )
                )}
                {modal.sourceLabel && (
                  <span className={`webcare-badge ${modal.isLatest ? 'webcare-badge-source-latest' : 'webcare-badge-source-default'}`}>
                    {modal.sourceLabel}
                  </span>
                )}
              </div>
              <div className="webcare-changelog-meta">
                Release History &bull; {modal.path}
                {modal.lastModified && <span> &bull; Modified: {modal.lastModified}</span>}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            {modal.content && (
              <button
                type="button"
                className="webcare-btn webcare-changelog-copy-btn"
                onClick={() => onCopy(modal.content)}
              >
                {copied ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                <span>{copied ? 'Copied' : 'Copy Changelog'}</span>
              </button>
            )}
            <button
              type="button"
              className="webcare-btn-close-modal webcare-changelog-close-btn"
              onClick={onClose}
              title="Close changelog modal (Esc)"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="webcare-changelog-body">
          {modal.loading && (
            <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
              <Loader2 size={24} className="webcare-spin" style={{ margin: '0 auto 12px' }} color="#3b82f6" />
              <div className="webcare-changelog-loading-title">
                Fetching latest upstream changelog from WordPress.org repository...
              </div>
              <div style={{ fontSize: '12px', marginTop: '4px' }}>
                Checking WordPress.org release notes with local fallback
              </div>
            </div>
          )}

          {modal.error && !modal.loading && (
            <div className="webcare-changelog-error-box">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '14px', marginBottom: '6px' }}>
                <AlertTriangle size={16} color="#dc2626" />
                <span>Changelog Unavailable</span>
              </div>
              <div style={{ fontSize: '13px' }}>
                {modal.error}
              </div>
              <div className="webcare-changelog-error-note">
                <strong>Developer Note:</strong> Premium or proprietary themes and plugins often publish release logs on their private vendor portals (e.g. CodeCanyon, ThemeForest, WooCommerce.com, or developer documentation).
              </div>
            </div>
          )}

          {!modal.loading && !modal.error && modal.content && (
            <div>
              {/* Notice when latest version was not found, falling back to installed */}
              {modal.latestNotFound && (
                <div className="webcare-changelog-notice-box">
                  <AlertTriangle size={18} color="#b45309" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <div style={{ fontWeight: 700, marginBottom: '2px' }}>
                      Latest Version ({modal.latestVersion ? `v${modal.latestVersion}` : 'Upstream'}) Changelog Not Found
                    </div>
                    <div>
                      {modal.notice || 'The latest remote release notes could not be retrieved from remote repositories or the plugin update manager. Displaying the currently installed version changelog from local disk below.'}
                    </div>
                  </div>
                </div>
              )}

              {/* Verified badge when showing latest upstream release */}
              {modal.isLatest && (
                <div className="webcare-changelog-latest-banner">
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                    <Sparkles size={14} color="#16a34a" />
                    <span>{modal.sourceLabel || `Upstream Changelog for Latest Release (v${modal.versionShown || modal.latestVersion})`}</span>
                  </div>
                  {modal.installedVersion && (
                    <span className="webcare-changelog-installed-subtext">
                      (Installed on your server: <strong>v{modal.installedVersion}</strong>)
                    </span>
                  )}
                </div>
              )}

              <div className="webcare-changelog-doc-bar">
                <span>Document: <strong className="webcare-changelog-doc-name">{modal.filename}</strong> {fileSizeKb && `(${fileSizeKb} KB)`}</span>
                <span>{lineCount} lines</span>
              </div>
              <pre className="webcare-changelog-pre">
                {modal.content}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="webcare-changelog-footer">
          <div className="webcare-changelog-footer-meta">
            Direct component forensics inspection &bull; WebCare Pro Security Engine
          </div>
          <button
            type="button"
            className="webcare-btn webcare-changelog-footer-close"
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export const App = ({ initialTab }: { initialTab?: NavTab } = {}) => {
  const localizedSettings = (window as any).webcareScannerSettings || {};
  const logoPngUrl = localizedSettings.logoPngUrl || (localizedSettings.assetsUrl ? `${localizedSettings.assetsUrl}logo.png` : '');
  const logo3dUrl = localizedSettings.logo3dUrl || (localizedSettings.assetsUrl ? `${localizedSettings.assetsUrl}webcare-original-logo-3d.jpg` : '');
  const emblem3dUrl = localizedSettings.emblem3dUrl || logoPngUrl || (localizedSettings.assetsUrl ? `${localizedSettings.assetsUrl}logo.png` : '');
  const pluginVersion = localizedSettings.version || '1.20.0';

  const getInitialNavTab = (): NavTab => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const page = urlParams.get('page');
      const tabParam = urlParams.get('tab');
      if (page === 'webcare-pro-vpatch' || page === 'webcare-scanner-vpatch' || ((page === 'webcare-pro-firewall' || page === 'webcare-scanner-firewall') && tabParam === 'vpatch') || ((page === 'webcare-pro-security' || page === 'webcare-security-scanner') && tabParam === 'vpatch')) {
        return 'firewall';
      }
      if (tabParam) {
        if (tabParam === 'file-changes' || tabParam === 'file-integrity') return 'fim';
        if (tabParam === 'risks' || tabParam === 'vulnerabilities') return 'vulnerabilities';
        if (tabParam === 'malware') return 'scan';
        if (tabParam === 'scans') return 'logs';
        if (tabParam === 'database') return 'backup';
        if (tabParam === 'diagnostics') return 'forensics';
        if (tabParam === 'doctor') return 'settings';
        if (tabParam === 'lockdown') return 'settings';
        if (['dashboard', 'scan', 'targeted', 'logs', 'forensics', 'vault', 'quarantine', 'backup', 'server', 'vulnerabilities', 'firewall', 'vpatch', 'waf_logs', 'fim', 'auth', 'notifications', 'settings', 'about'].includes(tabParam)) {
          return (PAGE_TO_TAB[tabParam] || tabParam) as NavTab;
        }
      }
      if (page && PAGE_TO_TAB[page]) {
        return PAGE_TO_TAB[page];
      }
    } catch (e) {}

    if (initialTab) return initialTab;

    const localized = (window as any).webcareScannerSettings?.initialTab;
    if (localized && (PAGE_TO_TAB[localized] || ['dashboard', 'scan', 'targeted', 'logs', 'forensics', 'vault', 'quarantine', 'backup', 'server', 'vulnerabilities', 'firewall', 'vpatch', 'waf_logs', 'fim', 'auth', 'notifications', 'settings', 'about'].includes(localized))) {
      return PAGE_TO_TAB[localized] || (localized as NavTab);
    }
    return 'dashboard';
  };

  const [themeMode, setThemeMode] = useState<'dark' | 'light'>(() => getWebCareTheme());

  // Two-Mode UX Architecture: Simple Mode (Default for Site Owners) vs. Developer Mode
  const { mode: workspaceMode, isSimpleMode, isDeveloperMode, setMode: setWorkspaceMode } = useWorkspaceMode();

  const toggleWorkspaceMode = () => {
    setWorkspaceMode(isDeveloperMode ? 'simple' : 'developer');
  };

  const [rescueModalOpen, setRescueModalOpen] = useState<boolean>(() => {
    try {
      return new URLSearchParams(window.location.search).get('rescue') === '1';
    } catch {
      return false;
    }
  });
  const [rescuePaused, setRescuePaused] = useState<boolean>(false);
  const [dailyStory, setDailyStory] = useState<any>(null);

  useEffect(() => {
    let active = true;
    apiRequest({ path: '/webcare-pro-security/v1/rescue/status', method: 'GET' })
      .then((res) => {
        if (!active || !res?.success) return;
        setDailyStory(res.daily_story || null);
        setRescuePaused(Boolean(res.pause_status?.paused));
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

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

  const toggleThemeMode = () => {
    setThemeMode((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      applyWebCareTheme(next);
      return next;
    });
  };

  const [navTab, setNavTab] = useState<NavTab>(getInitialNavTab);
  const [containmentActive, setContainmentActive] = useState<boolean>(false);
  const [initialFimFile, setInitialFimFile] = useState<string | null>(null);
  const [initialSettingsSubTab, setInitialSettingsSubTab] = useState<'containment' | 'schedule' | 'email' | 'webhooks' | 'cloudflare' | 'headers' | 'ai' | 'mcp' | 'performance' | 'import_export' | 'updates' | 'cleanup' | 'support' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('tab') || urlParams.get('subtab');
      if (sub && ['containment', 'schedule', 'email', 'webhooks', 'cloudflare', 'headers', 'ai', 'mcp', 'performance', 'import_export', 'updates', 'cleanup', 'support'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });
  const [initialForensicsSubTab, setInitialForensicsSubTab] = useState<'persistence' | 'watchdog' | 'baseline' | 'files' | 'attack_chain' | 'correlation' | 'whitelist' | 'transactions' | 'self_defense' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('tab') || urlParams.get('subtab');
      if (sub && ['persistence', 'watchdog', 'baseline', 'files', 'attack_chain', 'correlation', 'whitelist', 'transactions', 'self_defense'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });
  const [initialFirewallSubTab, setInitialFirewallSubTab] = useState<'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const page = urlParams.get('page');
      if (page === 'webcare-pro-vpatch' || page === 'webcare-scanner-vpatch') {
        return 'vpatch';
      }
      if (page === 'webcare-pro-caf' || page === 'webcare-scanner-caf') {
        return 'caf';
      }
      const sub = urlParams.get('tab');
      if (sub && ['stream', 'rules', 'caf', 'drill', 'supply_chain', 'behavioral', 'server_sec', 'intel', 'cloudflare', 'vpatch', 'ai_defense'].includes(sub)) {
        return sub as any;
      }
      // Backwards-compatible check if subtab was passed as tab
      const subtab = urlParams.get('subtab');
      if (subtab && ['sbom', 'gatekeeper', 'advisor', 'lockfiles', 'scripts'].includes(subtab)) {
        return 'supply_chain';
      }
      if (subtab && ['learning', 'honeytoken', 'ratelimit'].includes(subtab)) {
        return 'behavioral';
      }
      if (subtab && ['ghost', 'egress', 'prompt', 'credentials', 'surface'].includes(subtab)) {
        return 'ai_defense';
      }
    } catch (e) {}
    return undefined;
  });

  const [initialSupplyChainSubTab, setInitialSupplyChainSubTab] = useState<'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['sbom', 'gatekeeper', 'advisor', 'lockfiles', 'scripts'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  const [initialBehavioralSubTab, setInitialBehavioralSubTab] = useState<'learning' | 'honeytoken' | 'ratelimit' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['learning', 'honeytoken', 'ratelimit'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  const [initialAiDefenseSubTab, setInitialAiDefenseSubTab] = useState<'ghost' | 'egress' | 'prompt' | 'credentials' | 'surface' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['ghost', 'egress', 'prompt', 'credentials', 'surface'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  const [initialWatchdogSubTab, setInitialWatchdogSubTab] = useState<'watchdog' | 'snapshots' | 'preloaders' | 'reputation' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['watchdog', 'snapshots', 'preloaders', 'reputation'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  const [initialIdentitySubTab, setInitialIdentitySubTab] = useState<'sessions' | 'breach' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('subtab');
      if (sub && ['sessions', 'breach'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  // State to track expanded user capabilities matrix per finding ID and search filter
  const [expandedUserCaps, setExpandedUserCaps] = useState<Record<string, boolean>>({});
  const [userCapSearch, setUserCapSearch] = useState<Record<string, string>>({});
  // Selected target admin user ID for orphaned post reassignment per issue
  const [selectedReassignAdmin, setSelectedReassignAdmin] = useState<Record<string, number>>({});
  const [initialAuthSubTab, setInitialAuthSubTab] = useState<'2fa' | 'passkeys' | 'admins' | 'temporary_access' | 'zero_trust' | 'sessions' | 'lockouts' | 'app_passwords' | 'settings' | undefined>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sub = urlParams.get('tab') || urlParams.get('subtab');
      if (sub && ['2fa', 'passkeys', 'admins', 'temporary_access', 'zero_trust', 'sessions', 'lockouts', 'app_passwords', 'settings'].includes(sub)) {
        return sub as any;
      }
    } catch (e) {}
    return undefined;
  });

  const [megaMenuOpen, setMegaMenuOpen] = useState<boolean>(false);

  // Global In-App Toast Notification State
  const [globalToast, setGlobalToast] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const showGlobalToast = (type: 'success' | 'error' | 'info', message: string) => {
    setGlobalToast({ type, message });
    setTimeout(() => {
      setGlobalToast((prev) => (prev?.message === message ? null : prev));
    }, 4500);
  };

  // Global In-App Confirm Dialog State
  const [confirmModal, setConfirmModal] = useState<{
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

  const requestConfirmation = ({
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
    setConfirmModal({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setConfirmModal((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setConfirmModal((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error('Confirmation action error:', err);
          setConfirmModal((prev) => ({ ...prev, isLoading: false }));
          showGlobalToast('error', err?.message || 'Action encountered an error.');
        }
      },
    });
  };

  useEffect(() => {
    const handleGlobalKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        // Only toggle if not actively typing inside an input/textarea
        const target = e.target as HTMLElement;
        const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
        if (!isInput) {
          e.preventDefault();
          setMegaMenuOpen((prev) => !prev);
        }
      }
    };
    window.addEventListener('keydown', handleGlobalKey);
    return () => window.removeEventListener('keydown', handleGlobalKey);
  }, []);

  // Synchronize browser URL bar and WordPress sidebar active menu on tab switch
  const handleNavTabChange = (
    newTab: NavTab,
    subTab?: string,
    nestedSubTab?: string
  ) => {
    // If staying on the Executive SOC Dashboard
    if (newTab === 'dashboard') {
      const url = new URL(window.location.href);
      if (url.searchParams.get('page') !== 'webcare-pro-security') {
        window.location.href = 'admin.php?page=webcare-pro-security';
      } else {
        setNavTab('dashboard');
      }
      return;
    }

    // Direct decoupled page navigation map strictly targeting canonical pillars
    const pageMap: Record<string, string> = {
      scan: 'webcare-pro-scanner&tab=malware',
      targeted: 'webcare-pro-scanner&tab=targeted',
      logs: 'webcare-pro-logs&tab=scans',
      fim: 'webcare-pro-scanner&tab=file-changes',
      vulnerabilities: 'webcare-pro-scanner&tab=risks',
      firewall: 'webcare-pro-firewall&tab=rules',
      custom_rules: 'webcare-pro-firewall&tab=custom-rules',
      modular_waf: 'webcare-pro-firewall&tab=custom-rules',
      waf_logs: 'webcare-pro-logs&tab=firewall',
      vpatch: 'webcare-pro-firewall&tab=virtual-patches',
      auth: 'webcare-pro-login&tab=2fa',
      vault: 'webcare-pro-backups&tab=database',
      quarantine: 'webcare-pro-backups&tab=quarantine',
      backup: 'webcare-pro-backups&tab=database',
      forensics: 'webcare-pro-backups&tab=diagnostics',
      server: 'webcare-pro-backups&tab=server',
      settings: 'webcare-pro-settings&tab=doctor',
      notifications: 'webcare-pro-settings&tab=alerts',
      activity_logs: 'webcare-pro-logs&tab=activity',
      cron_manager: 'webcare-pro-settings&tab=cron',
      about: 'webcare-pro-settings&tab=support',
      wizard: 'webcare-pro-setup',
    };

    let target = pageMap[newTab] || TAB_TO_PAGE[newTab] || ('webcare-pro-security&tab=' + newTab);
    if (subTab) {
      const canonicalSub = (subTab === 'rules' || subTab === 'waf-rules') ? 'rules' : (subTab === 'custom_rules' || subTab === 'rule-builder' || subTab === 'custom-rules' || subTab === 'custom-waf-rules') ? 'custom-rules' : (subTab === 'caf' || subTab === 'adaptive') ? 'adaptive' : (subTab === 'behavioral' || subTab === 'bots') ? 'bots' : (subTab === 'ai_defense' || subTab === 'ai-defense') ? 'ai-defense' : (subTab === 'supply_chain' || subTab === 'supply-chain') ? 'supply-chain' : (subTab === 'server_sec' || subTab === 'server') ? 'server' : (subTab === 'stream' || subTab === 'traffic') ? 'traffic' : subTab;
      if (target.includes('&tab=')) {
        target = target.replace(/&tab=[^&]*/, '&tab=' + canonicalSub);
      } else {
        target += '&tab=' + canonicalSub;
      }
    }
    if (nestedSubTab) {
      if (target.includes('&section=')) {
        target = target.replace(/&section=[^&]*/, '&section=' + nestedSubTab);
      } else {
        target += '&section=' + nestedSubTab;
      }
    }
    window.location.href = 'admin.php?page=' + target;
  };

  // Listen to browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      const urlParams = new URLSearchParams(window.location.search);
      const page = urlParams.get('page') || 'webcare-pro-security';
      const matched = PAGE_TO_TAB[page] || 'dashboard';
      setNavTab(matched);

      const tabParam = urlParams.get('tab');
      const subtabParam = urlParams.get('subtab');

      if (matched === 'scan') {
        if (tabParam === 'file-changes' || tabParam === 'file-integrity') {
          setNavTab('fim');
        } else if (tabParam === 'risks' || tabParam === 'vulnerabilities') {
          setNavTab('vulnerabilities');
        } else if (tabParam === 'targeted') {
          setNavTab('targeted');
        } else if (tabParam === 'malware' || tabParam === 'scan') {
          setNavTab('scan');
        }
      } else if (matched === 'firewall') {
        if (tabParam) setInitialFirewallSubTab(tabParam as any);
        if (subtabParam) {
          if (['sbom', 'gatekeeper', 'advisor', 'lockfiles', 'scripts'].includes(subtabParam)) {
            setInitialSupplyChainSubTab(subtabParam as any);
          }
          if (['learning', 'honeytoken', 'ratelimit'].includes(subtabParam)) {
            setInitialBehavioralSubTab(subtabParam as any);
          }
          if (['ghost', 'egress', 'prompt', 'credentials', 'surface'].includes(subtabParam)) {
            setInitialAiDefenseSubTab(subtabParam as any);
          }
        }
      } else if (matched === 'auth') {
        if (tabParam) setInitialAuthSubTab(tabParam as any);
        if (subtabParam && ['sessions', 'breach'].includes(subtabParam)) {
          setInitialIdentitySubTab(subtabParam as any);
        }
      } else if (matched === 'forensics') {
        if (tabParam) setInitialForensicsSubTab(tabParam as any);
        if (subtabParam && ['watchdog', 'snapshots', 'preloaders', 'reputation'].includes(subtabParam)) {
          setInitialWatchdogSubTab(subtabParam as any);
        }
      } else if (matched === 'settings' && tabParam) {
        setInitialSettingsSubTab(tabParam as any);
      }

      if (matched === 'logs') {
        const scanResultId = urlParams.get('scanresults');
        if (scanResultId) {
          loadScanLogDetail(parseInt(scanResultId, 10), false);
        } else {
          setSelectedScanDetail(null);
        }
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Monitor containment mode status for active warning pill in top header
  useEffect(() => {
    let isMounted = true;
    const checkContainment = async () => {
      try {
        const res = await apiRequest({ path: '/webcare-pro-security/v1/containment/status', method: 'GET' });
        if (isMounted && res?.success && res.status) {
          setContainmentActive(!!res.status.active);
        }
      } catch (e) {}
    };
    checkContainment();
    return () => { isMounted = false; };
  }, [navTab]);

  // Dashboard states
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [scanStage, setScanStage] = useState<string>('');
  const [scanTarget, setScanTarget] = useState<'plugins_themes' | 'full' | 'custom'>('plugins_themes');
  const [isCustomScanModalOpen, setIsCustomScanModalOpen] = useState<boolean>(false);
  const [customScanOptions, setCustomScanOptions] = useState<Record<string, boolean>>(() => {
    const defaults: Record<string, boolean> = {};
    CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
      defaults[item.key] = item.defaultChecked;
    });
    return defaults;
  });
  const [activeScanTrigger, setActiveScanTrigger] = useState<'manual' | 'scheduled'>('manual');
  const [currentScan, setCurrentScan] = useState<ScanData | null>(null);
  const [availableScans, setAvailableScans] = useState<any[]>([]);
  const [selectedDashboardScanId, setSelectedDashboardScanId] = useState<number | null>(null);
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [issues, setIssues] = useState<IssueData[]>([]);
  const [scannedFiles, setScannedFiles] = useState<ScannedFileInfo[]>([]);
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantineRecord[]>([]);
  const [dashboardSubTab, setDashboardSubTab] = useState<'issues' | 'attack_chain' | 'persistence' | 'baseline' | 'transactions' | 'whitelist' | 'quarantine' | 'files'>('issues');
  const [whitelistModal, setWhitelistModal] = useState<{ isOpen: boolean; issue: any | null }>({ isOpen: false, issue: null });
  const [issueStatusFilter, setIssueStatusFilter] = useState<'open' | 'ignored' | 'all'>('open');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [issueSearch, setIssueSearch] = useState<string>('');
  const [fileFilter, setFileFilter] = useState<string>('');
  const [progress, setProgress] = useState<number>(0);
  const [currentFile, setCurrentFile] = useState<string>('');
  const [expandedIssue, setExpandedIssue] = useState<number | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [copiedIssuePath, setCopiedIssuePath] = useState<string | null>(null);
  const [isWelcomeModalOpen, setIsWelcomeModalOpen] = useState<boolean>(false);
  const [findingsPage, setFindingsPage] = useState<number>(1);
  const [findingsPageSize, setFindingsPageSize] = useState<number>(100);
  const [findingsViewMode, setFindingsViewMode] = useState<'simple' | 'technical'>(() => {
    return (localStorage.getItem('webcare_findings_view_mode') as 'simple' | 'technical') || 'simple';
  });

  // Auto-check system readiness and display first-time welcome modal if not dismissed
  useEffect(() => {
    apiFetch<{ success: boolean; report: { welcome_dismissed: boolean } }>({
      path: '/webcare-pro-security/v1/readiness',
    })
      .then((res) => {
        if (res && res.report && !res.report.welcome_dismissed) {
          setIsWelcomeModalOpen(true);
        }
      })
      .catch((err) => {
        console.warn('WebCare Readiness check failed:', err);
      });
  }, []);

  // Live Audit Telemetry & Resource states
  const [scanElapsed, setScanElapsed] = useState<number>(0);
  const [scanTelemetry, setScanTelemetry] = useState<LiveScanTelemetry | null>(null);
  const [dbProgress, setDbProgress] = useState<{
    current_table: string;
    table_index: number;
    total_tables: number;
    table_rows_scanned: number;
    table_approx_rows: number;
    overall_rows_scanned?: number;
    overall_total_rows?: number;
    overall_rows_left?: number;
    completed?: boolean;
  } | null>(null);
  const scanStartTimeRef = useRef<number | null>(null);

  // Active scan elapsed ticking timer
  useEffect(() => {
    let timer: any = null;
    if (scanning) {
      if (!scanStartTimeRef.current) {
        scanStartTimeRef.current = Date.now();
      }
      timer = setInterval(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        if (scanStartTimeRef.current) {
          const secs = Math.max(0, Math.floor((Date.now() - scanStartTimeRef.current) / 1000));
          setScanElapsed(secs);
        }
      }, 1000);
    } else {
      scanStartTimeRef.current = null;
      setScanElapsed(0);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [scanning]);

  // Targeted scans state
  const [adminOnlyUsers, setAdminOnlyUsers] = useState<boolean>(true);
  const [expandedTargetedIssue, setExpandedTargetedIssue] = useState<number | null>(null);
  const [targetedScanning, setTargetedScanning] = useState<string | null>(null);
  const [targetedResult, setTargetedResult] = useState<{ target: string; summary: RiskSummary; issues: IssueData[] } | null>(null);
  const targetedResultRef = useRef<HTMLDivElement | null>(null);
  const [targetedProgress, setTargetedProgress] = useState<number>(0);
  const [targetedStage, setTargetedStage] = useState<string>('');
  const [targetedDetail, setTargetedDetail] = useState<string>('');
  const [targetedElapsed, setTargetedElapsed] = useState<number>(0);

  // Auto scroll down to targeted scan results when a targeted scan completes
  useEffect(() => {
    if (targetedResult && targetedResultRef.current) {
      setTimeout(() => {
        targetedResultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    }
  }, [targetedResult]);

  // Scan Logs state
  const [scanHistory, setScanHistory] = useState<ScanData[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [selectedScanDetail, setSelectedScanDetail] = useState<{ scan: ScanData; summary: RiskSummary; issues: IssueData[]; files_count: number; diagnostics?: ScanDiagnostics } | null>(null);
  const [expandedLogIssue, setExpandedLogIssue] = useState<number | null>(null);
  const [logIssueSearch, setLogIssueSearch] = useState<string>('');
  const [logSeverityFilter, setLogSeverityFilter] = useState<string>('all');
  const [logCategoryFilter, setLogCategoryFilter] = useState<string>('all');
  const [logStatusFilter, setLogStatusFilter] = useState<string>('all');

  // Database Backup state
  const [backups, setBackups] = useState<BackupItem[]>([]);
  const [backupLoading, setBackupLoading] = useState<boolean>(false);
  const [creatingBackup, setCreatingBackup] = useState<boolean>(false);

  // Server Info & Live Dashboard states
  const [serverInfo, setServerInfo] = useState<ServerInfoData | null>(() => (window as any).webcareScannerSettings?.serverInfo || null);
  const [serverInfoLoading, setServerInfoLoading] = useState<boolean>(false);
  const [firewallStatus, setFirewallStatus] = useState<any>(null);
  const [firewallLogs, setFirewallLogs] = useState<any[]>([]);
  const [vulnReport, setVulnReport] = useState<any>(null);
  const [lastLiveCheck, setLastLiveCheck] = useState<Date>(() => new Date());
  const [isLiveRefreshing, setIsLiveRefreshing] = useState<boolean>(false);

  // Global Refresh state
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null);

  // File Code & Image Inspection Modal State
  const [fileViewer, setFileViewer] = useState<{
    isOpen: boolean;
    loading: boolean;
    error: string | null;
    filePath: string;
    issue: IssueData | null;
    data: FileViewerData | null;
    searchQuery: string;
    activeTab: 'image' | 'code';
    imageZoom: number;
    wordWrap: boolean;
  }>({
    isOpen: false,
    loading: false,
    error: null,
    filePath: '',
    issue: null,
    data: null,
    searchQuery: '',
    activeTab: 'code',
    imageZoom: 100,
    wordWrap: true,
  });
  const [copiedFileContent, setCopiedFileContent] = useState<boolean>(false);
  const [copiedFilePathModal, setCopiedFilePathModal] = useState<boolean>(false);
  const [copiedFileShaModal, setCopiedFileShaModal] = useState<boolean>(false);
  const [fileCopyDropdownOpen, setFileCopyDropdownOpen] = useState<boolean>(false);
  const [fileCopyFeedback, setFileCopyFeedback] = useState<string | null>(null);
  const fileCopyDropdownRef = useRef<HTMLDivElement | null>(null);
  const threatLineRef = useRef<HTMLDivElement | null>(null);

  // Post / Page Threat Inspector Modal State
  const [postViewer, setPostViewer] = useState<{
    isOpen: boolean;
    loading: boolean;
    error: string | null;
    issue: IssueData | null;
    data: PostViewerData | null;
  }>({
    isOpen: false,
    loading: false,
    error: null,
    issue: null,
    data: null,
  });
  const [copiedPostContent, setCopiedPostContent] = useState<boolean>(false);

  // CVE Vulnerability Inspector Modal State
  const [cveModal, setCveModal] = useState<{
    isOpen: boolean;
    issue: IssueData | null;
  }>({
    isOpen: false,
    issue: null,
  });

  // AI Code Analysis Modal State
  const [aiModal, setAiModal] = useState<{
    isOpen: boolean;
    loading: boolean;
    error: string | null;
    analysis: string | null;
    provider: string | null;
    model: string | null;
    filePath: string;
    threatType: string;
  }>({
    isOpen: false,
    loading: false,
    error: null,
    analysis: null,
    provider: null,
    model: null,
    filePath: '',
    threatType: '',
  });

  // Visual Code Diff (FIM) Modal State
  const [visualDiffModal, setVisualDiffModal] = useState<{
    isOpen: boolean;
    filePath: string | null;
    issueId?: number | null;
  }>({
    isOpen: false,
    filePath: null,
    issueId: null,
  });

  const [dbInspectorModal, setDbInspectorModal] = useState<{
    isOpen: boolean;
    issue: IssueData | null;
    loading: boolean;
    data: Record<string, any> | null;
    error: string | null;
  }>({
    isOpen: false,
    issue: null,
    loading: false,
    data: null,
    error: null,
  });

  const [dbRowCache, setDbRowCache] = useState<Record<number, { loading: boolean; row: Record<string, any> | null; error: string | null }>>({});

  const [changelogModal, setChangelogModal] = useState<{
    isOpen: boolean;
    name: string;
    slug: string;
    version: string;
    type: 'theme' | 'plugin';
    path: string;
    loading: boolean;
    error: string | null;
    filename: string;
    content: string;
    lastModified?: string;
    fileSize?: number;
    source?: string;
    sourceLabel?: string;
    isLatest?: boolean;
    latestNotFound?: boolean;
    versionShown?: string;
    latestVersion?: string;
    installedVersion?: string;
    notice?: string;
  }>({
    isOpen: false,
    name: '',
    slug: '',
    version: '',
    type: 'plugin',
    path: '',
    loading: false,
    error: null,
    filename: '',
    content: '',
  });
  const [copiedChangelog, setCopiedChangelog] = useState<boolean>(false);

  // Auto-scroll to flagged threat line in file viewer
  useEffect(() => {
    if (fileViewer.isOpen && fileViewer.data && fileViewer.issue?.line_number) {
      const timer = setTimeout(() => {
        if (threatLineRef.current) {
          threatLineRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 350);
      return () => clearTimeout(timer);
    }
  }, [fileViewer.isOpen, fileViewer.data]);

  // Global escape key handler to close modals & click outside copy dropdown
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (fileCopyDropdownRef.current && !fileCopyDropdownRef.current.contains(e.target as Node)) {
        setFileCopyDropdownOpen(false);
      }
    };
    if (fileCopyDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [fileCopyDropdownOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (fileCopyDropdownOpen) {
          setFileCopyDropdownOpen(false);
          return;
        }
        if (fileViewer.isOpen) setFileViewer((prev) => ({ ...prev, isOpen: false }));
        if (postViewer.isOpen) setPostViewer((prev) => ({ ...prev, isOpen: false }));
        if (dbInspectorModal.isOpen) setDbInspectorModal((prev) => ({ ...prev, isOpen: false }));
        if (changelogModal.isOpen) setChangelogModal((prev) => ({ ...prev, isOpen: false }));
        if (cveModal.isOpen) setCveModal({ isOpen: false, issue: null });
        if (aiModal.isOpen) setAiModal((prev) => ({ ...prev, isOpen: false }));
        if (visualDiffModal.isOpen) setVisualDiffModal({ isOpen: false, filePath: null, issueId: null });
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [fileViewer.isOpen, postViewer.isOpen, dbInspectorModal.isOpen, changelogModal.isOpen, cveModal.isOpen, aiModal.isOpen, visualDiffModal.isOpen]);

  const handleOpenChangelog = async (issue?: IssueData, explicitPath?: string) => {
    const meta = issue?.component_meta || {};
    const compType = (issue?.component_type || meta.type || (issue?.file_path?.includes('/themes/') ? 'theme' : 'plugin')) as 'theme' | 'plugin';
    const compName = issue?.component_name || meta.name || issue?.file_path?.split(/[/|\\]/).filter(Boolean).pop() || 'Component';
    const targetPath = explicitPath || issue?.file_path || meta.path || '';

    // Accurately resolve folder slug
    let compSlug = meta.slug || '';
    if (!compSlug && targetPath) {
      const norm = targetPath.replace(/\\/g, '/');
      const themeMatch = norm.match(/\/wp-content\/themes\/([^/]+)/i);
      const pluginMatch = norm.match(/\/wp-content\/plugins\/([^/]+)/i);
      if (themeMatch) compSlug = themeMatch[1];
      else if (pluginMatch) compSlug = pluginMatch[1];
      else compSlug = norm.split('/').filter(Boolean).pop()?.replace(/\.php$/i, '') || '';
    }

    const compVersion = issue?.installed_version || meta.version || '';
    const latestVersion = issue?.latest_version || meta.latest_version || '';

    setChangelogModal({
      isOpen: true,
      name: compName,
      slug: compSlug,
      version: compVersion,
      type: compType,
      path: targetPath,
      loading: true,
      error: null,
      filename: '',
      content: '',
      source: '',
      sourceLabel: '',
      isLatest: false,
      latestNotFound: false,
      versionShown: '',
      latestVersion,
      installedVersion: compVersion,
      notice: '',
    });

    try {
      const res: any = await apiFetch({
        path: `webcare-pro-security/v1/component/changelog?path=${encodeURIComponent(targetPath)}&slug=${encodeURIComponent(compSlug)}&type=${encodeURIComponent(compType)}&installed_version=${encodeURIComponent(compVersion)}&latest_version=${encodeURIComponent(latestVersion)}`,
        method: 'GET',
      });

      if (res && res.has_changelog && res.content) {
        setChangelogModal((prev) => ({
          ...prev,
          loading: false,
          filename: res.filename || 'Changelog',
          content: res.content,
          lastModified: res.last_modified,
          fileSize: res.file_size,
          source: res.source,
          sourceLabel: res.source_label,
          isLatest: Boolean(res.is_latest),
          latestNotFound: Boolean(res.latest_not_found),
          versionShown: res.version_shown,
          notice: res.notice,
          latestVersion: res.latest_version || prev.latestVersion,
          installedVersion: res.installed_version || prev.installedVersion,
        }));
      } else {
        setChangelogModal((prev) => ({
          ...prev,
          loading: false,
          error: res?.message || 'No upstream or local changelog file was found for this component.',
          latestNotFound: Boolean(res?.latest_not_found),
        }));
      }
    } catch (err: any) {
      setChangelogModal((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Failed to fetch changelog.',
      }));
    }
  };

  const handleOpenFileViewer = async (issue?: IssueData, explicitPath?: string) => {
    const targetPath = explicitPath || issue?.file_path || '';
    const isImgFile = Boolean(/\.(png|jpe?g|gif|webp|svg|ico|bmp)$/i.test(targetPath));

    setFileViewer({
      isOpen: true,
      loading: true,
      error: null,
      filePath: targetPath,
      issue: issue || null,
      data: null,
      searchQuery: '',
      activeTab: isImgFile ? 'image' : 'code',
      imageZoom: 100,
      wordWrap: true,
    });

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/file/view',
        method: 'POST',
        data: {
          file_path: targetPath,
          issue_id: issue?.id,
        },
      });

      if (res && res.content !== undefined) {
        setFileViewer((prev) => ({
          ...prev,
          loading: false,
          data: res,
          activeTab: res.is_image ? 'image' : 'code',
        }));
      } else {
        setFileViewer((prev) => ({
          ...prev,
          loading: false,
          error: res?.message || 'Unable to read file content from server.',
        }));
      }
    } catch (err: any) {
      setFileViewer((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Failed to inspect file.',
      }));
    }
  };

  const handleOpenPostViewer = async (issue: IssueData) => {
    setPostViewer({
      isOpen: true,
      loading: true,
      error: null,
      issue,
      data: null,
    });

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/post/view',
        method: 'POST',
        data: {
          post_id: issue.post_id,
          path: issue.file_path,
        },
      });

      if (res && res.title !== undefined) {
        setPostViewer((prev) => ({
          ...prev,
          loading: false,
          data: res,
        }));
      } else {
        setPostViewer((prev) => ({
          ...prev,
          loading: false,
          error: res?.message || 'Unable to retrieve post data from database.',
        }));
      }
    } catch (err: any) {
      setPostViewer((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Failed to inspect post.',
      }));
    }
  };

  const handleCopyFileContent = () => {
    if (fileViewer.data?.content) {
      navigator.clipboard.writeText(fileViewer.data.content);
      setCopiedFileContent(true);
      setTimeout(() => setCopiedFileContent(false), 2000);
    }
  };

  /**
   * Multi-format forensic file & code copy helper
   * Formats: 'text' (raw code only), 'forensic_text', 'markdown', 'html', 'csv'
   */
  const handleCopyFileBundle = (format: 'text' | 'forensic_text' | 'markdown' | 'html' | 'csv') => {
    if (!fileViewer.data) return;
    const d = fileViewer.data;
    const iss = fileViewer.issue;

    const filePath = d.file_path || fileViewer.filePath || 'Unknown File';
    const fullPath = d.full_path || d.file_path || fileViewer.filePath;
    const filename = d.filename || filePath.split('/').pop() || 'file';
    const sha256 = d.sha256 || iss?.sha256 || iss?.file_sha256 || 'N/A';
    const md5 = d.md5 || 'N/A';
    const ctime = d.ctime || 'N/A';
    const mtime = d.mtime || 'N/A';
    const atime = d.atime || 'N/A';
    const ownership = d.ownership || (d.owner && d.group ? `${d.owner}:${d.group}` : 'unknown');
    const permissions = d.permissions || 'N/A';
    const mimeType = d.mime_type || (d.is_image ? (d.image_mime || 'image') : 'text/plain');
    const size = d.size_formatted || `${d.size_bytes} bytes`;
    const lineCount = d.line_count || 0;
    const malwareThreat = iss ? `${iss.severity?.toUpperCase() || 'THREAT'}: ${iss.type}${iss.description ? ` (${iss.description})` : ''}` : 'None Detected / Clean Audit';
    const threatLine = iss?.line_number ? `Line #${iss.line_number}` : 'N/A';
    const code = d.content || '';

    let payload = '';

    if (format === 'text') {
      // Normal copy of code
      payload = code;
    } else if (format === 'forensic_text') {
      // Comprehensive plain text forensic report with code
      payload = `=== WebCare Pro Security & Firewall: FORENSIC FILE AUDIT ===
File Name:        ${filename}
Relative Path:    ${filePath}
Full System Path: ${fullPath}
SHA-256 Hash:     ${sha256}
MD5 Hash:         ${md5}
File Size:        ${size} (${d.size_bytes} bytes)
Permissions:      ${permissions} (${d.is_writable ? 'Writable' : 'Read-Only'})
Ownership (U:G):  ${ownership}
Created (ctime):  ${ctime}
Modified (mtime): ${mtime}
Accessed (atime): ${atime}
MIME Type:        ${mimeType}
Line Count:       ${lineCount}
Threat Analysis:  ${malwareThreat}
Flagged Line:     ${threatLine}
${d.is_masked ? 'Note: Sensitive database credentials & keys automatically masked for privacy.\n' : ''}
--- SOURCE CODE / CONTENT BEGIN ---
${code}
--- SOURCE CODE / CONTENT END ---
`;
    } else if (format === 'markdown') {
      const codeLang = filename.endsWith('.php') ? 'php' : filename.endsWith('.js') ? 'javascript' : filename.endsWith('.json') ? 'json' : filename.endsWith('.css') ? 'css' : filename.endsWith('.html') ? 'html' : filename.endsWith('.sql') ? 'sql' : '';
      payload = `# 🛡️ WebCare Pro Security & Firewall — Forensic File Audit

| Forensic Property | Inspection Value |
| :--- | :--- |
| **File Name** | \`${filename}\` |
| **File Path** | \`${filePath}\` |
| **Full System Path** | \`${fullPath}\` |
| **SHA-256 Hash** | \`${sha256}\` |
| **MD5 Hash** | \`${md5}\` |
| **File Size** | ${size} (${d.size_bytes} bytes) |
| **Permissions** | \`${permissions}\` (${d.is_writable ? 'Writable' : 'Read-Only'}) |
| **Ownership & Group** | \`${ownership}\` |
| **Created Time (ctime)** | ${ctime} |
| **Last Edited (mtime)** | ${mtime} |
| **Last Accessed (atime)** | ${atime} |
| **MIME Type** | \`${mimeType}\` |
| **Line Count** | ${lineCount} |
| **Malware / Threat Detected** | **${malwareThreat}** |
| **Flagged Line Number** | ${threatLine} |

${d.is_masked ? '> [!NOTE]\n> Sensitive database passwords and salt keys in this view have been automatically masked.\n\n' : ''}### Source Code

\`\`\`${codeLang}
${code}
\`\`\`
`;
    } else if (format === 'html') {
      const escapeHtml = (str: string) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      payload = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WebCare Pro Security & Firewall - Forensic Audit - ${escapeHtml(filename)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; line-height: 1.5; }
    h1 { color: #38bdf8; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; background: #1e293b; border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 14px; border: 1px solid #334155; text-align: left; }
    th { background: #090d16; color: #94a3b8; width: 220px; }
    code { font-family: monospace; color: #38bdf8; background: #090d16; padding: 2px 6px; border-radius: 4px; }
    .threat { color: #f87171; font-weight: bold; }
    pre { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 12px; color: #f1f5f9; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>🛡️ Forensic File Audit Report: ${escapeHtml(filename)}</h1>
  <table>
    <tr><th>File Name</th><td><code>${escapeHtml(filename)}</code></td></tr>
    <tr><th>Relative Path</th><td><code>${escapeHtml(filePath)}</code></td></tr>
    <tr><th>Full System Path</th><td><code>${escapeHtml(fullPath)}</code></td></tr>
    <tr><th>SHA-256 Hash</th><td><code>${escapeHtml(sha256)}</code></td></tr>
    <tr><th>MD5 Hash</th><td><code>${escapeHtml(md5)}</code></td></tr>
    <tr><th>File Size</th><td>${escapeHtml(size)} (${d.size_bytes} bytes)</td></tr>
    <tr><th>File Permissions</th><td><code>${escapeHtml(permissions)}</code> (${d.is_writable ? 'Writable' : 'Read-Only'})</td></tr>
    <tr><th>File Ownership & Group</th><td><code>${escapeHtml(ownership)}</code></td></tr>
    <tr><th>Created Time (ctime)</th><td>${escapeHtml(ctime)}</td></tr>
    <tr><th>Last Edited (mtime)</th><td>${escapeHtml(mtime)}</td></tr>
    <tr><th>Last Accessed (atime)</th><td>${escapeHtml(atime)}</td></tr>
    <tr><th>MIME Type</th><td><code>${escapeHtml(mimeType)}</code></td></tr>
    <tr><th>Line Count</th><td>${lineCount}</td></tr>
    <tr><th>Malware / Threat Detected</th><td class="threat">${escapeHtml(malwareThreat)}</td></tr>
    <tr><th>Flagged Threat Line</th><td>${escapeHtml(threatLine)}</td></tr>
  </table>
  <h3>Source Code</h3>
  <pre><code>${escapeHtml(code)}</code></pre>
</body>
</html>`;
    } else if (format === 'csv') {
      const escapeCsv = (str: string) => `"${str.replace(/"/g, '""')}"`;
      payload = `Property,Value
Filename,${escapeCsv(filename)}
Relative Path,${escapeCsv(filePath)}
Full System Path,${escapeCsv(fullPath)}
SHA-256 Hash,${escapeCsv(sha256)}
MD5 Hash,${escapeCsv(md5)}
File Size Bytes,${escapeCsv(String(d.size_bytes))}
File Size Formatted,${escapeCsv(size)}
File Permissions,${escapeCsv(permissions)}
Is Writable,${escapeCsv(d.is_writable ? 'Yes' : 'No')}
Ownership,${escapeCsv(ownership)}
Created Time (ctime),${escapeCsv(ctime)}
Last Edited (mtime),${escapeCsv(mtime)}
Last Accessed (atime),${escapeCsv(atime)}
MIME Type,${escapeCsv(mimeType)}
Line Count,${escapeCsv(String(lineCount))}
Malware Threat Type,${escapeCsv(malwareThreat)}
Flagged Line Number,${escapeCsv(threatLine)}
Source Code,${escapeCsv(code)}
`;
    }

    if (navigator.clipboard) {
      navigator.clipboard.writeText(payload);
      const labelMap = {
        text: 'Code Copied!',
        forensic_text: 'Forensic Text Copied!',
        markdown: 'Markdown Copied!',
        html: 'HTML Copied!',
        csv: 'CSV Copied!',
      };
      setFileCopyFeedback(labelMap[format]);
      setFileCopyDropdownOpen(false);
      setTimeout(() => setFileCopyFeedback(null), 2500);
    }
  };

  const handleCopyPostContent = () => {
    if (postViewer.data?.content) {
      navigator.clipboard.writeText(postViewer.data.content);
      setCopiedPostContent(true);
      setTimeout(() => setCopiedPostContent(false), 2000);
    }
  };

  const handleScrollToThreatLine = () => {
    if (threatLineRef.current) {
      threatLineRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const handleAiAnalyzeCode = async (codeSnippet?: string, filePath?: string, threatType?: string, lineNumber?: number) => {
    const code = codeSnippet || fileViewer.data?.content || '';
    const path = filePath || fileViewer.filePath || 'Unknown File';
    const threat = threatType || fileViewer.issue?.type || 'Suspicious Code / Malicious Vector';
    const line = lineNumber || fileViewer.issue?.line_number;

    if (!code) {
      toast.warning('No code snippet available for AI analysis.');
      return;
    }

    setAiModal({
      isOpen: true,
      loading: true,
      error: null,
      analysis: null,
      provider: null,
      model: null,
      filePath: path,
      threatType: threat,
    });

    try {
      const res: any = await apiRequest({
        path: '/ai/analyze',
        method: 'POST',
        data: {
          code,
          file_path: path,
          threat_type: threat,
          line_number: line,
        },
      });

      if (res && res.success) {
        setAiModal({
          isOpen: true,
          loading: false,
          error: null,
          analysis: res.analysis,
          provider: res.provider,
          model: res.model,
          filePath: path,
          threatType: threat,
        });
      } else {
        setAiModal((prev) => ({
          ...prev,
          loading: false,
          error: res?.error || res?.message || 'AI analysis request failed.',
        }));
      }
    } catch (err: any) {
      setAiModal((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Failed to communicate with AI provider. Please verify your API key in Settings.',
      }));
    }
  };

  // 1. Load latest scan & quarantine (supports plugins_themes, full, or custom scans, and specific scanId)
  const loadLatestScan = async (scanId?: number) => {
    try {
      setLoading(true);
      const queryParam = scanId ? `?scan_id=${scanId}` : '';
      const res: any = await apiRequest({ path: `/webcare-pro-security/v1/scan/latest${queryParam}` });
      if (res?.available_scans) {
        setAvailableScans(res.available_scans);
      }
      if (res?.has_scan && res?.scan) {
        setCurrentScan({
          ...res.scan,
          diagnostics: res.diagnostics || res.scan?.diagnostics
        });
        setSelectedDashboardScanId(res.scan.id);
        setSummary(res.summary || null);
        setIssues(res.issues || []);
        setScannedFiles(res.files || []);
      } else {
        setCurrentScan(null);
        setSelectedDashboardScanId(null);
        setSummary(null);
        setIssues([]);
        setScannedFiles([]);
      }

      const qRes: any = await apiRequest({ path: '/webcare-pro-security/v1/quarantine' });
      if (qRes?.records) {
        setQuarantinedFiles(qRes.records);
      }
    } catch (e) {
      console.error('Failed to load scan info', e);
    } finally {
      setLoading(false);
    }
  };

  // 2. Load scan logs history
  const loadScanHistory = async () => {
    try {
      setHistoryLoading(true);
      const res: any = await apiRequest({ path: '/webcare-pro-security/v1/scan/history' });
      if (res?.scans) {
        setScanHistory(res.scans);
      }
    } catch (e) {
      console.error('Failed to load scan history', e);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Load single historical scan log
  const loadScanLogDetail = async (id: number, updateUrl: boolean = true) => {
    try {
      const res: any = await apiRequest({ path: `/webcare-pro-security/v1/scan/history/${id}` });
      if (res?.success) {
        setSelectedScanDetail({
          scan: res.scan,
          summary: res.summary,
          issues: res.issues || [],
          files_count: res.files_count || 0,
          diagnostics: res.diagnostics || res.scan?.diagnostics
        });

        setExpandedLogIssue(null);
        setLogIssueSearch('');
        setLogSeverityFilter('all');
        setLogCategoryFilter('all');
        setLogStatusFilter('all');

        if (updateUrl) {
          try {
            const url = new URL(window.location.href);
            url.searchParams.set('page', 'webcare-pro-logs');
            url.searchParams.set('scanresults', id.toString());
            window.history.pushState({ tab: 'logs', scanresults: id }, '', url.toString());
          } catch (e) {}
        }

        // Smooth scroll to the expanded findings section after rendering
        setTimeout(() => {
          const detailElement = document.getElementById('webcare-scan-log-inspector');
          if (detailElement) {
            detailElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }, 120);
      }
    } catch (e) {
      console.error('Failed to load scan log detail', e);
    }
  };

  // Clear all old scan history & logs
  const handleClearAllScanHistory = async () => {
    const isScanActive = scanning || Boolean(targetedScanning);
    requestConfirmation({
      title: 'Clear Scan History & Logs',
      message: isScanActive
        ? 'A security scan is currently running! Clearing logs will preserve your active running scan and findings while removing all past historical logs. Do you want to proceed?'
        : 'Are you sure you want to permanently clear all old scan logs and history records? This cannot be undone.',
      confirmLabel: 'Clear Scan Logs',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setHistoryLoading(true);
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/scan/history/clear',
            method: 'POST'
          });
          if (res?.success) {
            showGlobalToast('success', res.message || (isScanActive ? 'Past scan logs cleared. Active scan continues running.' : 'All old scan logs cleared successfully.'));
            if (isScanActive) {
              await loadScanHistory();
            } else {
              setScanHistory([]);
              setSelectedScanDetail(null);
              await loadLatestScan();
            }
          } else {
            showGlobalToast('error', 'Could not clear scan logs.');
          }
        } catch (e) {
          console.error('Failed to clear scan history', e);
          showGlobalToast('error', 'Error clearing scan logs.');
        } finally {
          setHistoryLoading(false);
        }
      },
    });
  };

  // 3. Load backups
  const loadBackups = async () => {
    try {
      setBackupLoading(true);
      const res: any = await apiRequest({ path: '/webcare-pro-security/v1/backup/list' });
      if (res?.backups) {
        setBackups(res.backups);
      }
    } catch (e) {
      console.error('Failed to load backups', e);
    } finally {
      setBackupLoading(false);
    }
  };

  const handleCreateBackup = async () => {
    try {
      setCreatingBackup(true);
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/backup/create',
        method: 'POST'
      });
      if (res?.success) {
        toast.success(res.message || 'Database backup created successfully!');
        await loadBackups();
      } else {
        toast.error(res?.message || 'Failed to create backup.');
      }
    } catch (e) {
      console.error('Backup creation failed', e);
      toast.error('Error creating database backup.');
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleDeleteBackup = async (filename: string) => {
    requestConfirmation({
      title: 'Delete Database Backup',
      message: 'Are you sure you want to permanently delete this database backup snapshot? It will be removed from your server storage.',
      targetItem: filename,
      confirmLabel: 'Delete Backup',
      variant: 'danger',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/backup/delete',
            method: 'POST',
            data: { filename }
          });
          if (res?.success) {
            setBackups((prev) => prev.filter((b) => b.filename !== filename));
            showGlobalToast('success', 'Backup file deleted successfully.');
          } else {
            showGlobalToast('error', 'Could not delete backup file.');
          }
        } catch (e) {
          console.error('Failed to delete backup', e);
          showGlobalToast('error', 'Error deleting backup.');
        }
      },
    });
  };

  const handleDownloadBackup = (filename: string) => {
    const root = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
    const nonce = (window as any).webcareScannerSettings?.nonce || '';
    const url = `${root}/backup/download?filename=${encodeURIComponent(filename)}&_wpnonce=${nonce}`;
    window.open(url, '_blank');
  };

  // 4. Load Server Info
  const loadServerInfo = async (forceRefresh = false) => {
    try {
      setServerInfoLoading(true);
      const res: any = await apiRequest({ path: `/webcare-pro-security/v1/server-info${forceRefresh ? '?refresh=1' : ''}` });
      if (res?.info) {
        setServerInfo(res.info);
      }
    } catch (e) {
      console.error('Failed to load server info', e);
    } finally {
      setServerInfoLoading(false);
    }
  };

  // 5. Load Real-Time Dashboard Metrics & Live Defense Telemetry
  const loadDashboardData = async (isSilent = false) => {
    try {
      if (!isSilent) setIsLiveRefreshing(true);
      const [fwStatus, fwLogs, vReport, sInfo] = await Promise.all([
        apiRequest({ path: '/webcare-pro-security/v1/firewall/status' }).catch(() => null),
        apiRequest({ path: '/webcare-pro-security/v1/firewall/logs?limit=10' }).catch(() => null),
        apiRequest({ path: '/webcare-pro-security/v1/vulnerabilities/report' }).catch(() => null),
        (!serverInfo ? apiRequest({ path: '/webcare-pro-security/v1/server-info' }).catch(() => null) : Promise.resolve(null)),
      ]);
      if (fwStatus) setFirewallStatus(fwStatus);
      if (fwLogs?.logs) setFirewallLogs(fwLogs.logs);
      if (vReport?.report) setVulnReport(vReport.report);
      if (sInfo?.info) setServerInfo(sInfo.info);
      setLastLiveCheck(new Date());
    } catch (e) {
      console.warn('Dashboard data fetch failed', e);
    } finally {
      setIsLiveRefreshing(false);
    }
  };

  // Fetch data on tab change or mount
  useEffect(() => {
    loadLatestScan();
    checkAndResumeActiveScan();

    // Pre-load custom scan engine preferences from settings
    apiRequest({ path: '/webcare-pro-security/v1/settings' })
      .then((res: any) => {
        if (res?.settings?.custom_scan_options) {
          setCustomScanOptions(res.settings.custom_scan_options);
        }
      })
      .catch((err) => console.warn('Could not load custom scan settings:', err));

    // Check periodically for background scheduled scans every 8 seconds if idle
    const activeScanChecker = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      if (!isResumingRef.current) {
        checkAndResumeActiveScan();
      }
    }, 8000);

    return () => clearInterval(activeScanChecker);
  }, []);

  useEffect(() => {
    if (navTab === 'dashboard') {
      loadDashboardData();
      const pollInterval = setInterval(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        loadDashboardData(true);
      }, 15000);
      return () => clearInterval(pollInterval);
    } else if (navTab === 'logs') {
      loadScanHistory();
      const urlParams = new URLSearchParams(window.location.search);
      const scanResultId = urlParams.get('scanresults');
      if (scanResultId) {
        loadScanLogDetail(parseInt(scanResultId, 10), false);
      }
    } else if (navTab === 'backup') {
      loadBackups();
    } else if (navTab === 'server') {
      loadServerInfo();
    }
  }, [navTab]);

  const handleGlobalRefresh = async () => {
    if (isRefreshing) return;
    try {
      setIsRefreshing(true);
      setRefreshNotice(null);
      if (navTab === 'dashboard') {
        await Promise.all([loadLatestScan(), checkAndResumeActiveScan(), loadDashboardData(true)]);
      } else if (navTab === 'scan' || navTab === 'targeted') {
        await Promise.all([loadLatestScan(), checkAndResumeActiveScan()]);
      } else if (navTab === 'logs') {
        await loadScanHistory();
      } else if (navTab === 'backup' || navTab === 'vault') {
        await Promise.all([loadBackups(), loadLatestScan()]);
      } else if (navTab === 'server') {
        await loadServerInfo();
      } else {
        await loadLatestScan();
      }
      setRefreshNotice('Refreshed!');
      setTimeout(() => setRefreshNotice(null), 2200);
    } catch (err) {
      console.error('Refresh error', err);
      setRefreshNotice('Error');
      setTimeout(() => setRefreshNotice(null), 2200);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleSaveCustomScanPreferences = async (optsToSave: Record<string, boolean>) => {
    try {
      await apiRequest({
        path: '/webcare-pro-security/v1/settings',
        method: 'POST',
        data: {
          custom_scan_options: optsToSave,
        },
      });
    } catch (e) {
      console.error('Failed to save custom scan preferences', e);
    }
  };

  const isResumingRef = useRef<boolean>(false);

  // Resume or run dashboard scan sequence
  const resumeDashboardScan = async (
    scanId: number,
    totalFiles: number,
    targetType: string,
    initialScanned: number = 0,
    initialElapsed: number = 0,
    customOptionsToUse?: Record<string, boolean>,
    leaseToken?: string
  ) => {
    const scanStartTime = initialElapsed > 0 ? (Date.now() - (initialElapsed * 1000)) : Date.now();
    scanStartTimeRef.current = scanStartTime;
    setScanElapsed(initialElapsed > 0 ? initialElapsed : 0);
    try {
      setScanning(true);
      setScanTarget(targetType === 'full' ? 'full' : targetType === 'custom' ? 'custom' : 'plugins_themes');
      const total = Math.max(1, totalFiles);
      const startPct = Math.min(85, Math.round((initialScanned / total) * 85));
      setProgress(startPct);
      setScanStage(
        initialScanned > 0
          ? `Resuming scan: ${initialScanned} of ${total} files scanned...`
          : targetType === 'custom'
          ? 'Stage 1/2: Scanning Files & Malware Heuristics...'
          : 'Stage 1/2: Scanning Files & Malware Heuristics...'
      );
      setCurrentFile(initialScanned > 0 ? 'Reconnecting to scan batch pipeline...' : 'Initializing file scanner...');

      // Phase 1: Filesystem batch loop (only if totalFiles > 0)
      let finished = totalFiles === 0;
      while (!finished) {
        // Request higher batch size (e.g. 60) so the backend Adaptive Governor can scale up to 120-150 files
        // when ample memory headroom (>500MB free) is available on the server
        const batchRes: any = await apiRequest({
          path: '/webcare-pro-security/v1/scan/batch',
          method: 'POST',
          data: { scan_id: scanId, batch_size: 60, lease_token: leaseToken, from_browser: 1 },
        });

        if (batchRes?.telemetry) {
          setScanTelemetry(batchRes.telemetry);
        }

        if (batchRes?.last_file) {
          setCurrentFile(batchRes.last_file);
        }

        const remaining = batchRes?.remaining || 0;
        const processed = total - remaining;
        const currentPercent = Math.min(85, Math.round((processed / total) * 85));
        setProgress(currentPercent);

        if (batchRes?.is_finished) {
          finished = true;
        }
      }

      // Phase 2: Deep audits
      setScanStage(
        targetType === 'custom'
          ? 'Stage 2/2: Executing Selected Scan Engines & Integrity Verification...'
          : 'Stage 2/2: Deep Audit (Core Integrity, Database Injections, SEO Spam, Updates)...'
      );
      setCurrentFile('Initiating deep engine correlation & database integrity inspection...');
      setProgress(90);

      const clientElapsedMs = Math.max(50, Date.now() - scanStartTime);
      const clientElapsedSecs = Math.max(1, Math.round(clientElapsedMs / 1000));

      // Active polling ticker during Deep Audit to surface live MySQL table names and row telemetry
      let stopDeepAuditPolling = false;
      const deepAuditPollingInterval = setInterval(async () => {
        if (stopDeepAuditPolling) return;
        if (typeof document !== 'undefined' && document.hidden) return;
        try {
          const activeRes: any = await apiRequest({ path: '/webcare-pro-security/v1/scan/active' });
          if (activeRes?.last_file) {
            setCurrentFile(activeRes.last_file);
          }
          if (activeRes?.telemetry) {
            setScanTelemetry(activeRes.telemetry);
          }
          if (activeRes?.db_progress) {
            const dbp = activeRes.db_progress;
            setDbProgress(dbp);
            const tableStr = dbp.current_table ? `Table: ${dbp.current_table}` : 'Database Audit';
            const tableProgressStr = dbp.table_approx_rows > 0
              ? ` (${dbp.table_rows_scanned.toLocaleString()} / ${dbp.table_approx_rows.toLocaleString()} rows)`
              : ` (${dbp.table_rows_scanned.toLocaleString()} rows scanned)`;
            
            const rowsLeftStr = typeof dbp.overall_rows_left === 'number' && dbp.overall_rows_left > 0
              ? ` • ${dbp.overall_rows_left.toLocaleString()} rows left`
              : (dbp.overall_total_rows ? ` • ${dbp.overall_total_rows.toLocaleString()} total rows` : '');

            setScanStage(`Stage 2/2: Deep Audit — ${tableStr}${tableProgressStr} [${dbp.table_index}/${dbp.total_tables}]${rowsLeftStr}`);
          }
        } catch (_) {
          // Silent catch for transient polling hiccup during deep audit
        }
      }, 600);

      // Execute Deep Audit with resilient auto-retry to prevent transient server gateway timeouts (504/timeout) from aborting completed scans
      let deepAuditSuccess = false;
      let deepAuditAttempts = 0;
      let lastDeepError = null;

      try {
        while (!deepAuditSuccess && deepAuditAttempts < 3) {
          deepAuditAttempts++;
          try {
            await apiRequest({
              path: '/webcare-pro-security/v1/scan/deep-audit',
              method: 'POST',
              data: { 
                scan_id: scanId, 
                target: targetType,
                custom_options: customOptionsToUse || customScanOptions,
                client_duration: clientElapsedSecs,
                client_duration_ms: clientElapsedMs,
                lease_token: leaseToken
              },
            });
            deepAuditSuccess = true;
          } catch (auditErr: any) {
            lastDeepError = auditErr;
            console.warn(`[WebCare Pro] Deep audit attempt ${deepAuditAttempts} encountered timeout/network hiccup, checking scan state...`, auditErr);
            // Wait 2.5 seconds before retrying or checking completion
            await new Promise((res) => setTimeout(res, 2500));
          }
        }
      } finally {
        stopDeepAuditPolling = true;
        clearInterval(deepAuditPollingInterval);
      }

      if (!deepAuditSuccess && lastDeepError) {
        throw lastDeepError;
      }

      setProgress(100);
      setScanStage('Scan completed successfully!');
      setCurrentFile('Audit finalized.');
      await loadLatestScan();
    } catch (err: any) {
      console.error('Error during scan batching', err);
      const errMsg = err?.message || err?.data?.message || (typeof err === 'string' ? err : 'Communication failure or server timeout during scanning.');
      toast.error(`Error occurred during scanning: ${errMsg}`);
    } finally {
      setScanning(false);
      setDbProgress(null);
      scanStartTimeRef.current = null;
      isResumingRef.current = false;
    }
  };

  // Resume or run targeted scan sequence
  const resumeTargetedScan = async (
    scanId: number,
    targetType: string,
    elapsedSeconds: number = 0,
    extraOptions: any = {},
    leaseToken?: string
  ) => {
    let progressTimer: any = null;
    try {
      setTargetedScanning(targetType);
      setTargetedResult(null);
      setTargetedElapsed(elapsedSeconds);

      const meta = TARGET_META[targetType] || {
        title: 'Targeted Security Audit',
        steps: [
          'Initializing audit parameters...',
          'Performing deep heuristic evaluation...',
          'Correlating threat signatures...',
          'Finalizing security report...'
        ]
      };

      setTargetedStage(meta.steps[0] || 'Resuming audit...');
      setTargetedDetail(elapsedSeconds > 0 ? 'Reconnecting to active targeted scan...' : 'Acquiring exclusive scan lock & manifest cache...');

      let currentStepIdx = 0;
      let currentPercent = elapsedSeconds > 0 ? Math.min(85, Math.max(20, elapsedSeconds * 8)) : 12;
      setTargetedProgress(currentPercent);

      const targetedStartTime = Date.now() - (elapsedSeconds * 1000);

      // Start elapsed timer and smooth progress animator
      progressTimer = setInterval(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        const currentElapsed = Math.max(1, Math.round((Date.now() - targetedStartTime) / 1000));
        setTargetedElapsed(currentElapsed);
        currentPercent = Math.min(92, currentPercent + (currentPercent < 50 ? 9 : 4));
        setTargetedProgress(currentPercent);

        if (meta.steps.length > 0) {
          const stepIndex = Math.min(
            meta.steps.length - 1,
            Math.floor((currentPercent / 90) * meta.steps.length)
          );
          if (stepIndex !== currentStepIdx) {
            currentStepIdx = stepIndex;
            setTargetedStage(meta.steps[stepIndex]);
          }
        }
      }, 500);

      // If filesystem-only scan, process file batches first
      if (targetType === 'filesystem_only') {
        let finished = false;
        while (!finished) {
          const batchRes: any = await apiRequest({
            path: '/webcare-pro-security/v1/scan/batch',
            method: 'POST',
            data: { scan_id: scanId, batch_size: 60, lease_token: leaseToken, from_browser: 1 },
          });
          if (batchRes.last_file) {
            setTargetedDetail(`Auditing: ${batchRes.last_file}`);
          }
          if (batchRes.is_finished) {
            finished = true;
          }
        }
      }

      setTargetedDetail('Executing deep forensic evaluation...');

      const finalElapsedMs = Math.max(50, Date.now() - targetedStartTime);
      const finalElapsedSecs = Math.max(1, Math.round(finalElapsedMs / 1000));

      // Run deep audit for the target
      await apiRequest({
        path: '/webcare-pro-security/v1/scan/deep-audit',
        method: 'POST',
        data: { 
          scan_id: scanId, 
          target: targetType,
          admins_only: extraOptions.admins_only ?? false,
          client_duration: finalElapsedSecs,
          client_duration_ms: finalElapsedMs,
          lease_token: leaseToken
        },
      });

      setTargetedDetail('Compiling audit results & correlation score...');

      // Fetch the findings of this scan
      const detailRes: any = await apiRequest({
        path: `/webcare-pro-security/v1/scan/history/${scanId}`
      });

      if (detailRes?.success) {
        setTargetedResult({
          target: targetType,
          summary: detailRes.summary,
          issues: detailRes.issues || []
        });
      }

      if (progressTimer) clearInterval(progressTimer);
      setTargetedProgress(100);
      setTargetedStage('Targeted audit complete! Compiling findings...');
      setTargetedDetail('Audit finalized cleanly.');

      await new Promise((resolve) => setTimeout(resolve, 450));
      await loadLatestScan();
    } catch (err: any) {
      console.error('Targeted scan error', err);
      const errMsg = err?.message || err?.data?.message || (typeof err === 'string' ? err : 'Targeted scan execution error.');
      toast.error(`Error occurred during targeted scan: ${errMsg}`);
    } finally {
      if (progressTimer) clearInterval(progressTimer);
      setTargetedScanning(null);
      isResumingRef.current = false;
    }
  };

  // Monitor a background scheduled scan without interfering with its execution
  const monitorBackgroundScan = async (
    scanId: number,
    initialTotal: number,
    targetType: string,
    initialScanned: number = 0,
    initialElapsed: number = 0
  ) => {
    try {
      setScanning(true);
      setActiveScanTrigger('scheduled');
      setScanTarget(targetType === 'full' ? 'full' : 'plugins_themes');
      const total = Math.max(1, initialTotal);
      const startPct = Math.min(92, Math.round((initialScanned / total) * 92));
      setProgress(startPct);
      setScanStage(`Scheduled background audit in progress (${initialScanned} of ${total} files audited)...`);
      setCurrentFile('Auditing server filesystem in background worker...');

      let finished = false;
      let lastScannedCount = initialScanned;
      let pollStreakSame = 0;

      while (!finished) {
        await new Promise((resolve) => setTimeout(resolve, 2500));

        const activeRes: any = await apiRequest({ path: '/webcare-pro-security/v1/scan/active' });

        if (!activeRes?.is_running || activeRes?.scan_id !== scanId) {
          finished = true;
          break;
        }

        const currentScanned = activeRes.scanned_files ?? lastScannedCount;
        const currentTotal = Math.max(1, activeRes.total_files ?? total);
        const currentPhase = activeRes.phase || 'batch';
        const lastFile = activeRes.last_file || '';

        if (currentScanned === lastScannedCount) {
          pollStreakSame++;
        } else {
          pollStreakSame = 0;
          lastScannedCount = currentScanned;
        }

        if (activeRes.elapsed && !scanStartTimeRef.current) {
          scanStartTimeRef.current = Date.now() - (activeRes.elapsed * 1000);
          setScanElapsed(activeRes.elapsed);
        }

        if (activeRes.telemetry) {
          setScanTelemetry(activeRes.telemetry);
        }

        if (lastFile) {
          setCurrentFile(lastFile);
        } else if (currentPhase === 'deep_audit') {
          setCurrentFile('Executing deep heuristic correlation & database integrity inspection...');
        }

        if (currentPhase === 'deep_audit' || currentScanned >= currentTotal) {
          const deepPct = Math.min(97, 90 + Math.min(7, pollStreakSame));
          setProgress(deepPct);
          setScanStage(`Finalizing audit: Core Integrity, Database & Anomaly Correlation...`);
        } else {
          const pct = Math.min(88, Math.max(5, Math.round((currentScanned / currentTotal) * 88)));
          setProgress(pct);
          setScanStage(`Scheduled background audit in progress (${currentScanned} of ${currentTotal} files audited)...`);
        }
      }

      setProgress(100);
      setScanStage('Scheduled audit completed successfully!');
      setCurrentFile('Report generated.');
      await new Promise((resolve) => setTimeout(resolve, 600));
      await loadLatestScan();
    } catch (err: any) {
      console.error('Error monitoring background scan', err);
    } finally {
      setScanning(false);
      scanStartTimeRef.current = null;
      setActiveScanTrigger('manual');
      isResumingRef.current = false;
    }
  };

  // Inspect and auto-resume running scan upon page load or refresh
  const checkAndResumeActiveScan = async () => {
    if (isResumingRef.current || scanning || targetedScanning !== null) return;
    try {
      const activeRes: any = await apiRequest({ path: '/webcare-pro-security/v1/scan/active' });
      if (activeRes?.is_running && activeRes?.scan_id) {
        if (isResumingRef.current || scanning || targetedScanning !== null) return;
        isResumingRef.current = true;
        const scanId = activeRes.scan_id;
        const target = activeRes.scan_target || 'plugins_themes';
        const total = activeRes.total_files || 1;
        const scanned = activeRes.scanned_files || 0;
        const elapsed = activeRes.elapsed || 1;
        const triggerType = activeRes.trigger_type || 'manual';
        const leaseToken = activeRes.lease_token || '';

        if (activeRes.telemetry) {
          setScanTelemetry(activeRes.telemetry);
        }

        if (triggerType === 'scheduled') {
          await monitorBackgroundScan(scanId, total, target, scanned, elapsed);
        } else if (TARGETED_SCAN_TYPES.includes(target)) {
          setActiveScanTrigger('manual');
          await resumeTargetedScan(scanId, target, elapsed, {}, leaseToken);
        } else {
          setActiveScanTrigger('manual');
          await resumeDashboardScan(scanId, total, target, scanned, elapsed, undefined, leaseToken);
        }
      }
    } catch (e) {
      console.error('Failed checking active scan status', e);
    }
  };

  // Abort / Stop active scan
  const handleAbortScan = () => {
    requestConfirmation({
      title: 'Stop Active Security Scan',
      message: 'Are you sure you want to stop and cancel the currently running scan? In-progress checks will be aborted immediately.',
      confirmLabel: 'Stop Scan',
      variant: 'danger',
      onConfirm: async () => {
        await apiRequest({
          path: '/webcare-pro-security/v1/scan/abort',
          method: 'POST',
        });
        setScanning(false);
        scanStartTimeRef.current = null;
        setScanElapsed(0);
        setScanTelemetry(null);
        setTargetedScanning(null);
        setProgress(0);
        setTargetedProgress(0);
        isResumingRef.current = false;
        await loadLatestScan();
        showGlobalToast('info', 'Active security scan was stopped and lock released.');
      },
    });
  };

  // Standard / Custom Dashboard Scan Handler
  const handleStartScan = async (
    explicitTarget?: 'plugins_themes' | 'full' | 'custom',
    explicitOptions?: Record<string, boolean>
  ) => {
    if (isResumingRef.current || scanning) return;
    if (navTab !== 'scan') {
      handleNavTabChange('scan');
    }
    const targetToUse = explicitTarget || scanTarget;
    const optionsToUse = explicitOptions || customScanOptions;

    isResumingRef.current = true;
    try {
      setExpandedIssue(null);
      setScanning(true);
      setProgress(0);
      setScanElapsed(0);
      scanStartTimeRef.current = Date.now();
      setScanStage(
        targetToUse === 'custom'
          ? 'Initializing custom audit engines...'
          : 'Initializing filesystem scanner...'
      );
      setCurrentFile('Collecting audit scope manifest...');

      const startRes: any = await apiRequest({
        path: '/webcare-pro-security/v1/scan/start',
        method: 'POST',
        data: { 
          target: targetToUse,
          custom_options: targetToUse === 'custom' ? optionsToUse : undefined,
        },
      });

      if (!startRes?.success) {
        toast.error('Could not start scan');
        setScanning(false);
        scanStartTimeRef.current = null;
        isResumingRef.current = false;
        return;
      }

      if (startRes?.telemetry) {
        setScanTelemetry(startRes.telemetry);
      }

      const scanId = startRes.scan_id;
      const total = startRes.total_files || 0;
      const scanned = startRes.scanned_files || 0;
      const leaseToken = startRes.lease_token || '';
      await resumeDashboardScan(scanId, total, targetToUse, scanned, 0, optionsToUse, leaseToken);
    } catch (err: any) {
      console.error('Error starting dashboard scan', err);
      const errMsg = err?.message || err?.data?.message || 'Error occurred starting scan';
      toast.error(`Error occurred during scanning: ${errMsg}`);
      setScanning(false);
      scanStartTimeRef.current = null;
      isResumingRef.current = false;
    }
  };

  // Targeted Single-Option Scan Handler
  const handleStartTargetedScan = async (targetType: string, extraOptions: any = {}) => {
    if (isResumingRef.current || targetedScanning !== null) return;
    isResumingRef.current = true;
    try {
      setTargetedScanning(targetType);
      setTargetedResult(null);
      setTargetedProgress(8);
      setTargetedElapsed(0);

      const startRes: any = await apiRequest({
        path: '/webcare-pro-security/v1/scan/start',
        method: 'POST',
        data: { target: targetType },
      });

      if (!startRes?.success) {
        toast.error('Could not start targeted audit.');
        setTargetedScanning(null);
        isResumingRef.current = false;
        return;
      }

      const scanId = startRes.scan_id;
      const leaseToken = startRes.lease_token || '';
      await resumeTargetedScan(scanId, targetType, 0, extraOptions, leaseToken);
    } catch (err: any) {
      console.error('Targeted scan error', err);
      const errMsg = err?.message || err?.data?.message || 'Targeted scan execution error.';
      toast.error(`Error occurred during targeted scan: ${errMsg}`);
      setTargetedScanning(null);
      isResumingRef.current = false;
    }
  };

  const handleUpdateIssue = async (id: number | string, status: string) => {
    try {
      await apiRequest({
        path: `/webcare-pro-security/v1/issues/${id}`,
        method: 'POST',
        data: { status },
      });
      const isTarget = (itemId: any) => String(itemId) === String(id);

      setIssues((prev) =>
        prev.map((item) =>
          isTarget(item.id)
            ? {
                ...item,
                status,
                is_whitelisted: status === 'open' ? false : item.is_whitelisted,
                whitelist_rule: status === 'open' ? null : item.whitelist_rule,
              }
            : item
        )
      );
      if (targetedResult) {
        setTargetedResult({
          ...targetedResult,
          issues: targetedResult.issues.map((item) =>
            isTarget(item.id)
              ? {
                  ...item,
                  status,
                  is_whitelisted: status === 'open' ? false : item.is_whitelisted,
                  whitelist_rule: status === 'open' ? null : item.whitelist_rule,
                }
              : item
          ),
        });
      }
      setSelectedScanDetail((prev) => {
        if (!prev) return null;
        const updatedIssues = prev.issues.map((item) =>
          isTarget(item.id)
            ? {
                ...item,
                status,
                is_whitelisted: status === 'open' ? false : item.is_whitelisted,
                whitelist_rule: status === 'open' ? null : item.whitelist_rule,
              }
            : item
        );
        const openThreatsCount = updatedIssues.filter(
          (i) => (i.status === 'open' || !i.status) && !i.is_whitelisted
        ).length;
        return {
          ...prev,
          issues: updatedIssues,
          scan: prev.scan ? { ...prev.scan, issues_found: openThreatsCount } : prev.scan,
        };
      });

      // Optimistically update matching entry in scanHistory
      setScanHistory((prev) =>
        prev.map((scanItem) => {
          if (selectedScanDetail?.scan && String(scanItem.id) === String(selectedScanDetail.scan.id)) {
            const currIssues = selectedScanDetail.issues || [];
            const newIssues = currIssues.map((item: any) =>
              isTarget(item.id)
                ? {
                    ...item,
                    status,
                    is_whitelisted: status === 'open' ? false : item.is_whitelisted,
                  }
                : item
            );
            const activeThreats = newIssues.filter(
              (i: any) => (i.status === 'open' || !i.status) && !i.is_whitelisted
            ).length;
            return {
              ...scanItem,
              issues_found: activeThreats,
            };
          }
          return scanItem;
        })
      );

      if (status === 'open') {
        setIssueStatusFilter('open');
      }
      loadLatestScan();
      loadScanHistory();
    } catch (e) {
      console.error('Failed to update issue status:', e);
    }
  };

  /**
   * Determine whether an issue/file can be quarantined.
   * Official system files (like wp-config.php, .htaccess) and modified official component files
   * (modified_core_file, modified_plugin_file, modified_theme_file) must NEVER be quarantined
   * because removing them causes fatal site outages. They must be repaired/restored instead.
   * Strictly rogue/unknown/alien files (unknown_core_file, unknown_plugin_file, uploads webshells)
   * can and should be quarantined.
   */
  const canQuarantineIssue = (issue: IssueData | null | undefined): boolean => {
    if (!issue || issue.status !== 'open') return false;

    // Reject non-physical file entities
    if (
      issue.is_hook ||
      issue.is_db ||
      issue.is_db_table ||
      issue.engine === 'database-table' ||
      issue.is_user ||
      issue.is_post ||
      issue.is_comment ||
      issue.engine === 'content-comments' ||
      issue.is_software_update ||
      issue.is_dir ||
      issue.is_server_config ||
      issue.is_network ||
      issue.engine === 'ip-detection' ||
      issue.engine === 'waf-status' ||
      issue.type === 'reverse_proxy_misconfigured' ||
      issue.type === 'plugin_checksums_unavailable' ||
      issue.type === 'theme_checksums_unavailable' ||
      issue.type?.includes('_checksums_unavailable') ||
      !issue.file_path ||
      issue.file_path.startsWith('cron:') ||
      issue.file_path.startsWith('wp_options:') ||
      issue.file_path.startsWith('db:') ||
      issue.file_path.startsWith('table:') ||
      issue.file_path.startsWith('user:') ||
      issue.file_path.startsWith('comment:') ||
      issue.file_path.startsWith('server:') ||
      (!issue.file_path.includes('/') && !issue.file_path.includes('\\') && issue.file_path.includes('.') && issue.file_path.includes('[ID:'))
    ) {
      return false;
    }

    const path = issue.file_path.toLowerCase().replace(/\\/g, '/');

    // Protected bootstrap, configuration and core files (wp-config.php, .htaccess, etc.)
    const protectedBasenames = [
      'wp-config.php',
      '.htaccess',
      'wp-settings.php',
      'wp-load.php',
      'wp-blog-header.php',
      'wp-login.php',
      'xmlrpc.php',
    ];
    if (protectedBasenames.some((b) => path.endsWith('/' + b) || path === b)) {
      return false;
    }
    if (path.endsWith('/index.php') && !path.includes('/wp-content/')) {
      return false;
    }

    // Never quarantine scanner plugin's own files
    if (path.includes('/plugins/webcare-security-scanner/') || path.includes('/plugins/webcare-pro-security/')) {
      return false;
    }

    // Official modified files must be repaired/restored (Auto-Cure / Re-install), NOT quarantined!
    const isModifiedOfficial = Boolean(
      issue.type?.startsWith('modified_') ||
      issue.type === 'injected_wp_config' ||
      issue.type?.startsWith('wp_config_') ||
      issue.engine === 'config'
    );
    if (isModifiedOfficial) {
      return false;
    }

    return true;
  };

  const handleQuarantine = async (issue: IssueData) => {
    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/quarantine',
        method: 'POST',
        data: {
          file_path: issue.file_path,
          scan_id: issue.scan_id,
          issue_id: issue.id,
        },
      });

      if (res?.success) {
        showGlobalToast('success', res.message || 'File quarantined successfully!');
        handleUpdateIssue(issue.id, 'quarantined');
        loadLatestScan();
      } else {
        showGlobalToast('error', res?.message || 'Quarantine failed.');
      }
    } catch (err: any) {
      console.error(err);
      showGlobalToast('error', err?.message || 'Failed to quarantine file');
    }
  };

  const handleDeleteRogueFile = async (issue: IssueData) => {
    requestConfirmation({
      title: 'Delete Unrecognized Rogue File',
      message: 'Are you sure you want to permanently delete this unrecognized rogue file from your server? This action cannot be undone. An automated safety snapshot backup is retained in WebCare Vault for 14 days, allowing 1-click rollback if needed.',
      targetItem: issue.file_path,
      confirmLabel: 'Permanently Delete',
      variant: 'danger',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/delete-file',
            method: 'POST',
            data: {
              file_path: issue.file_path,
              issue_id: issue.id,
            },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'File permanently deleted from server.');
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Failed to delete file.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to delete file.');
        }
      },
    });
  };

  const handleRestoreQuarantine = async (id: number) => {
    requestConfirmation({
      title: 'Restore Quarantined File',
      message: 'Are you sure you want to restore this file back to its original location on your server? The file will become active immediately.',
      confirmLabel: 'Restore File',
      variant: 'primary',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: `/webcare-pro-security/v1/quarantine/${id}/restore`,
            method: 'POST',
          });

          if (res?.success) {
            showGlobalToast('success', res.message || 'File restored successfully!');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Restore failed.');
          }
        } catch (err) {
          console.error(err);
          showGlobalToast('error', 'Failed to restore file');
        }
      },
    });
  };

  const handleDeleteQuarantine = async (record: QuarantineRecord) => {
    const isRestored = record.status === 'restored';
    requestConfirmation({
      title: isRestored ? 'Remove Vault Log Entry' : 'Permanently Delete Quarantined File',
      message: isRestored
        ? 'Remove this entry from the vault history? The restored file on your website will remain active and completely untouched. This only removes the historical log entry.'
        : 'Are you sure you want to PERMANENTLY delete this quarantined file from storage vault? This action CANNOT be undone.',
      targetItem: record.original_path,
      confirmLabel: isRestored ? 'Remove Log' : 'Delete File',
      variant: isRestored ? 'warning' : 'danger',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: `/webcare-pro-security/v1/quarantine/${record.id}`,
            method: 'DELETE',
          });
          if (res?.success) {
            showGlobalToast(
              'success',
              res.message ||
                (isRestored
                  ? 'Vault history entry removed. (Live site file remains untouched).'
                  : 'Quarantined file permanently deleted.')
            );
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Failed to delete file.');
          }
        } catch (err) {
          console.error(err);
          showGlobalToast('error', 'Failed to process quarantine record');
        }
      },
    });
  };

  const handleAutoCurePlugin = async (issue: IssueData) => {
    requestConfirmation({
      title: 'Auto-Cure Plugin File',
      message: 'Are you sure you want to Auto-Cure and restore this plugin file to its official bit-for-bit WordPress.org release? An automated safety snapshot backup is retained in WebCare Vault for 14 days, allowing 1-click rollback at any time.',
      targetItem: issue.file_path,
      confirmLabel: 'Auto-Cure & Restore',
      variant: 'primary',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/restore-plugin',
            method: 'POST',
            data: { file_path: issue.file_path, issue_id: issue.id },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'File restored to official release!');
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to auto-cure plugin file.');
        }
      },
    });
  };

  const handleAutoCureCore = async (issue: IssueData) => {
    requestConfirmation({
      title: 'Auto-Cure WordPress Core File',
      message: 'Are you sure you want to Auto-Cure and restore this WordPress core file to its pristine official bit-for-bit release? An automated safety snapshot backup is retained in WebCare Vault for 14 days, allowing 1-click rollback at any time.',
      targetItem: issue.file_path,
      confirmLabel: 'Restore Core File',
      variant: 'primary',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/restore-core',
            method: 'POST',
            data: { file_path: issue.file_path, issue_id: issue.id },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'Core file restored to official release!');
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to auto-cure core file.');
        }
      },
    });
  };

  const handleAutoCureTheme = async (issue: IssueData) => {
    requestConfirmation({
      title: 'Auto-Cure Theme File',
      message: 'Are you sure you want to Auto-Cure and restore this theme file to its pristine official release? An automated safety snapshot backup is retained in WebCare Vault for 14 days, allowing 1-click rollback at any time.',
      targetItem: issue.file_path,
      confirmLabel: 'Restore Theme File',
      variant: 'primary',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/restore-theme',
            method: 'POST',
            data: { file_path: issue.file_path, issue_id: issue.id },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'Theme file restored to official release!');
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to auto-cure theme file.');
        }
      },
    });
  };

  const handleAutoCureStrip = async (issue: IssueData) => {
    requestConfirmation({
      title: 'Strip Injected Malware Wrapper',
      message: 'Are you sure you want to Auto-Cure and strip the injected malware wrapper from this file? Malicious code will be removed while preserving legitimate logic. An automated safety snapshot backup is retained in WebCare Vault for 14 days.',
      targetItem: issue.file_path,
      confirmLabel: 'Strip Malware',
      variant: 'danger',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/strip',
            method: 'POST',
            data: { file_path: issue.file_path, issue_id: issue.id },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'Malware stripped successfully!');
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Malware stripping failed.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to strip malware wrapper.');
        }
      },
    });
  };

  const handleAutoCureIssue = async (issue: IssueData) => {
    const isUnknown = Boolean(
      issue.type?.includes('unknown') ||
      issue.type?.includes('unrecognized') ||
      issue.type?.includes('extra') ||
      issue.type?.includes('disguised') ||
      issue.type?.includes('webshell') ||
      issue.type?.includes('backdoor') ||
      issue.type?.includes('malware') ||
      issue.type?.includes('rogue') ||
      issue.type?.includes('orphan') ||
      issue.type?.includes('unexpected') ||
      issue.type?.includes('unauthorized_dropin') ||
      issue.engine?.includes('uploads')
    );
    if (isUnknown) {
      showGlobalToast('error', 'Cannot restore unknown file: this file is not part of official WordPress.org releases.');
      return;
    }

    const isChecksumsUnavailable = Boolean(
      issue.is_custom ||
      issue.is_premium ||
      issue.is_wporg === false ||
      issue.type === 'plugin_checksums_unavailable' ||
      issue.type === 'theme_checksums_unavailable' ||
      issue.type === 'core_checksums_unavailable' ||
      issue.type?.includes('_checksums_unavailable') ||
      (issue.severity === 'info' && Boolean(issue.description?.toLowerCase().includes('checksums unavailable')))
    );
    if (isChecksumsUnavailable) {
      showGlobalToast('warning', 'Official WordPress.org clean copy is not available for this custom or unmanaged component.');
      return;
    }

    const filePath = issue.file_path || '';
    const isPlugin = Boolean(filePath.includes('/plugins/'));
    const isCore = Boolean((filePath.includes('/wp-admin/') || filePath.includes('/wp-includes/') || issue.type?.includes('core')) && !filePath.endsWith('wp-config.php') && !filePath.endsWith('.htaccess'));
    const isTheme = Boolean(filePath.includes('/themes/') || issue.type?.includes('theme'));

    if (isCore) {
      await handleAutoCureCore(issue);
    } else if (isPlugin) {
      await handleAutoCurePlugin(issue);
    } else if (isTheme) {
      await handleAutoCureTheme(issue);
    }
  };

  const [disablingWpDebug, setDisablingWpDebug] = useState<boolean>(false);
  const [wpDebugModal, setWpDebugModal] = useState<{ isOpen: boolean; issue: IssueData | null }>({ isOpen: false, issue: null });

  const handleDisableWpDebug = async (issue: IssueData) => {
    setWpDebugModal({ isOpen: true, issue });
  };

  const executeDisableWpDebug = async (issue: IssueData) => {
    setDisablingWpDebug(true);
    try {
      const res: any = await apiRequest({
        path: '/remediation/disable-wp-debug',
        method: 'POST',
        data: { file_path: issue.file_path, issue_id: issue.id },
      });
      if (res?.success) {
        setWpDebugModal({ isOpen: false, issue: null });
        handleUpdateIssue(issue.id, 'repaired');
        loadLatestScan();
      } else {
        toast.error(res?.message || 'Failed to disable WordPress debugging.');
      }
    } catch (err: any) {
      console.error(err);
      toast.error(err?.message || 'Failed to disable WordPress debugging.');
    } finally {
      setDisablingWpDebug(false);
    }
  };

  const handleFixPermissions = async (issue: IssueData, targetPerm = '0644') => {
    if (!issue.file_path) return;
    const isDir = Boolean(issue.is_dir || issue.file_path.endsWith('/'));
    const recommended = targetPerm || (isDir ? '0755' : '0644');
    requestConfirmation({
      title: 'Harden File Permissions',
      message: `Are you sure you want to harden file permissions to ${recommended}? This will restrict unauthorized write and execution privileges while ensuring WordPress functions normally.`,
      targetItem: issue.file_path,
      confirmLabel: `Enforce ${recommended}`,
      variant: 'primary',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/remediation/fix-permissions',
            method: 'POST',
            data: { file_path: issue.file_path, issue_id: issue.id, target_perm: recommended },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || `File permissions successfully hardened to ${recommended}!`);
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Failed to update file permissions.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to update file permissions.');
        }
      },
    });
  };

  const [isFixingAllPerms, setIsFixingAllPerms] = useState<boolean>(false);

  const handleFixAllDetectedPermissions = async () => {
    requestConfirmation({
      title: 'Bulk Harden All Permissions',
      message: 'Are you sure you want to 1-Click Fix all file and folder permissions across your WordPress installation? This will enforce standard 0755 for directories and 0644 for files, securing world-writable items immediately.',
      confirmLabel: 'Harden All Permissions',
      variant: 'warning',
      onConfirm: async () => {
        setIsFixingAllPerms(true);
        try {
          const res: any = await apiRequest({
            path: '/permissions/fix-all',
            method: 'POST',
          });
          if (res?.success) {
            showGlobalToast('success', res.message || 'Permissions successfully hardened!');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Failed to complete bulk permission hardening.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to complete bulk permission hardening.');
        } finally {
          setIsFixingAllPerms(false);
        }
      },
    });
  };

  const handleDeleteCronHook = async (issue: IssueData) => {
    const hookName = issue.file_path?.replace(/^cron:hook:/, '') || issue.file_path;
    try {
      const res: any = await apiRequest({
        path: '/remediation/delete-cron-hook',
        method: 'POST',
        data: {
          file_path: issue.file_path,
          hook_name: hookName,
          issue_id: issue.id,
        },
      });
      if (res?.success) {
        showGlobalToast('success', res.message || `Cron hook "${hookName}" removed successfully!`);
        handleUpdateIssue(issue.id, 'repaired');
        loadLatestScan();
      } else {
        showGlobalToast('error', res?.message || 'Failed to remove cron hook.');
      }
    } catch (err: any) {
      console.error(err);
      showGlobalToast('error', err?.message || 'Failed to remove cron hook.');
    }
  };

  const handleModerateComment = async (issue: IssueData, action: 'trash' | 'spam' | 'delete') => {
    const commentId = issue.comment_id || parseInt(issue.file_path?.replace(/^comment:(\d+).*/, '$1') || '0', 10);
    if (!commentId) {
      showGlobalToast('error', 'Could not determine comment ID for this security finding.');
      return;
    }

    const actionDescriptions: Record<string, { title: string; message: string; label: string; variant: 'danger' | 'warning' }> = {
      trash: {
        title: 'Trash Malicious Comment',
        message: `Move comment #${commentId} to WordPress Trash? This safely quarantines and delists the comment from the public website while allowing recovery in WordPress Admin.`,
        label: 'Move to Trash',
        variant: 'warning'
      },
      spam: {
        title: 'Mark Comment as Spam',
        message: `Mark comment #${commentId} as Spam in WordPress? This flags the comment in WordPress spam filters and immediately delists it from site visitors.`,
        label: 'Mark as Spam',
        variant: 'warning'
      },
      delete: {
        title: 'Permanently Delete Comment',
        message: `PERMANENTLY DELETE comment #${commentId} from the database? This will completely purge the comment and metadata rows. This action cannot be undone.`,
        label: 'Delete Permanently',
        variant: 'danger'
      },
    };

    const config = actionDescriptions[action] || {
      title: 'Moderate Comment',
      message: `Execute ${action} on comment #${commentId}?`,
      label: 'Execute',
      variant: 'danger'
    };

    requestConfirmation({
      title: config.title,
      message: config.message,
      targetItem: `Comment #${commentId}`,
      confirmLabel: config.label,
      variant: config.variant,
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/comment/moderate',
            method: 'POST',
            data: {
              comment_id: commentId,
              action,
              issue_id: issue.id,
            },
          });
          if (res?.success) {
            showGlobalToast('success', res.message || `Comment #${commentId} processed successfully.`);
            handleUpdateIssue(issue.id, 'repaired');
            loadLatestScan();
          } else {
            showGlobalToast('error', res?.message || 'Failed to moderate comment.');
          }
        } catch (err: any) {
          console.error(err);
          showGlobalToast('error', err?.message || 'Failed to moderate comment.');
        }
      },
    });
  };

  const handleRemediateUser = async (
    issue: IssueData,
    action: 'assign_default_role' | 'strip_capabilities' | 'delete_user' | 'reassign_orphaned_posts',
    targetRole: string = 'subscriber',
    targetUserId?: number | null
  ) => {
    let userId = issue.user_id;
    if (!userId && issue.file_path) {
      const match = issue.file_path.match(/(?:author:|user:|_users:user_id_|users\.ID\s*=\s*|User ID:\s*)(\d+)/i);
      if (match) userId = Number(match[1]);
    }
    if (!userId && issue.evidence) {
      const match = issue.evidence.match(/(?:User|Author)\s*ID:\s*(\d+)/i);
      if (match) userId = Number(match[1]);
    }

    if (!userId) {
      toast.warning('Could not determine WordPress User ID for this finding.');
      return;
    }

    let confirmMsg = '';
    const userLabel = issue.user_login || issue.user_display_name || `User #${userId}`;

    if (action === 'assign_default_role') {
      confirmMsg = `REPAIR & ASSIGN DEFAULT ROLE (${targetRole}) to ${userLabel} (ID #${userId})?\n\nThis will synchronize standard capabilities metadata and repair missing capabilities. An automated pre-action snapshot backup of wp_users and wp_usermeta will be saved into the Quarantine Vault before applying changes.`;
    } else if (action === 'strip_capabilities') {
      confirmMsg = `STRIP INJECTED PRIVILEGES from ${userLabel} (ID #${userId})?\n\nThis will purge unauthorized custom capabilities (such as upload_files, edit_plugins, etc.) while strictly preserving their declared primary role (${issue.user_roles || 'customer'}). An automated pre-action snapshot backup will be saved into the Quarantine Vault before applying changes.`;
    } else if (action === 'delete_user') {
      confirmMsg = `SAFELY DELETE account ${userLabel} (ID #${userId})?\n\nAn automated pre-action snapshot backup of both wp_users and wp_usermeta records will be saved into the Quarantine Vault before deletion. Self-deletion and deleting the only admin are strictly protected.`;
    } else if (action === 'reassign_orphaned_posts') {
      const requestedTargetId = targetUserId ?? null;
      const targetAdmin = Number.isSafeInteger(requestedTargetId) && Number(requestedTargetId) > 0
        ? Number(requestedTargetId)
        : null;
      const targetOption = targetAdmin === null
        ? undefined
        : issue.admin_options?.find(a => Number(a.id) === targetAdmin);

      if (targetAdmin === null || !targetOption) {
        showGlobalToast('error', __('Select a valid administrator before reassigning orphaned posts.', 'webcare-pro-security'));
        return;
      }

      const targetAdminName = targetOption?.display_name || issue.reassign_target_name || ('Administrator #' + targetAdmin);
      confirmMsg = `REASSIGN ALL ORPHANED POSTS to ${targetAdminName}?\n\nAll posts and content authored by deleted User ID #${userId} will be reassigned to ${targetAdminName} (ID #${targetAdmin}), fixing missing author references without altering post content or permalinks.`;
    }

    const executeUserRemediation = async () => {
      try {
        const res: any = await apiRequest({
          path: '/user/remediate',
          method: 'POST',
          data: {
            user_id: userId,
            action,
            role: targetRole,
            reassign_to: action === 'reassign_orphaned_posts'
              ? targetUserId
              : undefined,
            issue_id: issue.id,
          },
        });

        if (res?.success) {
          showGlobalToast('success', res.message || 'User remediation completed successfully!');
          handleUpdateIssue(issue.id, 'repaired');
          loadLatestScan();
        } else {
          showGlobalToast('error', res?.error || res?.message || 'Failed to remediate user.');
        }
      } catch (err: any) {
        console.error(err);
        showGlobalToast('error', err?.message || 'Failed to remediate user.');
      }
    };

    requestConfirmation({
      title: 'Confirm User Account Action',
      message: confirmMsg,
      targetItem: `${userLabel} (User ID #${userId})`,
      confirmLabel: action === 'delete_user' ? 'Delete User' : 'Apply Remediation',
      variant: action === 'delete_user' ? 'danger' : 'warning',
      onConfirm: executeUserRemediation,
    });
  };

  const parseDbFinding = (issue: IssueData) => {
    let tableName = issue.table_name || '';
    let columnName = issue.column_name || '';
    let rowId: string | number | null = issue.row_id || null;

    if (!tableName || !columnName || !rowId) {
      const match = issue.file_path?.match(/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i);
      if (match) {
        if (!tableName) tableName = match[1];
        if (!columnName) columnName = match[2];
        if (!rowId && match[3]) rowId = match[3];
      }
    }
    if (!rowId && issue.file_path) {
      const idMatch = issue.file_path.match(/\[ID:\s*(\d+)\]/i);
      if (idMatch) rowId = idMatch[1];
    }
    if (!tableName && issue.file_path) {
      tableName = issue.file_path.split('.')[0] || '';
    }
    if (!columnName && issue.file_path && issue.file_path.includes('.')) {
      columnName = issue.file_path.split('.')[1]?.split(' ')[0] || '';
    }
    return { tableName, columnName, rowId };
  };

  const loadDbRow = async (issue: IssueData) => {
    if (dbRowCache[issue.id]?.loading) return;
    const { tableName, rowId } = parseDbFinding(issue);
    if (!tableName || !rowId) return;

    setDbRowCache(prev => ({ ...prev, [issue.id]: { loading: true, row: prev[issue.id]?.row || null, error: null } }));
    try {
      const res: any = await apiRequest({
        path: `/database/row?table=${encodeURIComponent(tableName)}&row_id=${encodeURIComponent(rowId)}`,
        method: 'GET',
      });
      const rowData = res?.row || res?.data?.row || (res?.data && !res.data.row && typeof res.data === 'object' && Object.keys(res.data).length > 0 ? res.data : null);
      if (res?.success && rowData) {
        setDbRowCache(prev => ({ ...prev, [issue.id]: { loading: false, row: rowData, error: null } }));
      } else {
        setDbRowCache(prev => ({ ...prev, [issue.id]: { loading: false, row: null, error: res?.message || 'Database row not found in MySQL.' } }));
      }
    } catch (err: any) {
      setDbRowCache(prev => ({ ...prev, [issue.id]: { loading: false, row: null, error: err?.message || 'Network error querying row.' } }));
    }
  };

  const handleOpenDbInspector = async (issue: IssueData) => {
    const { tableName, columnName, rowId } = parseDbFinding(issue);
    const existingRow = issue.db_row || dbRowCache[issue.id]?.row;

    const initialData = existingRow ? {
      table: tableName || issue.table_name,
      row_id: rowId || issue.row_id || '',
      primary_key: issue.db_primary_key || 'id',
      is_log_table: Boolean(issue.is_log_table),
      row: existingRow,
    } : null;

    setDbInspectorModal({
      isOpen: true,
      issue: {
        ...issue,
        table_name: tableName || issue.table_name,
        column_name: columnName || issue.column_name,
        row_id: rowId ? Number(rowId) : issue.row_id,
      },
      loading: !initialData,
      data: initialData,
      error: null,
    });

    if (!tableName || !rowId) {
      if (!initialData) {
        setDbInspectorModal(prev => ({
          ...prev,
          loading: false,
          error: 'Unable to parse table name or record ID from finding identifier.',
        }));
      }
      return;
    }

    try {
      const res: any = await apiRequest({
        path: `/database/row?table=${encodeURIComponent(tableName)}&row_id=${encodeURIComponent(rowId)}`,
        method: 'GET',
      });
      const rowData = res?.row || res?.data?.row || (res?.data && !res.data.row && typeof res.data === 'object' && Object.keys(res.data).length > 0 ? res.data : null);
      if (res?.success && rowData) {
        const fullData = {
          table: res.table || res.data?.table || tableName,
          row_id: res.row_id || res.data?.row_id || rowId,
          primary_key: res.primary_key || res.data?.primary_key || issue.db_primary_key || 'id',
          is_log_table: res.is_log_table ?? res.data?.is_log_table ?? Boolean(issue.is_log_table),
          row: rowData,
        };
        setDbInspectorModal(prev => ({
          ...prev,
          loading: false,
          data: fullData,
          error: null,
        }));
        setDbRowCache(prev => ({ ...prev, [issue.id]: { loading: false, row: rowData, error: null } }));
      } else if (!initialData) {
        setDbInspectorModal(prev => ({
          ...prev,
          loading: false,
          error: res?.message || 'Failed to retrieve database row from MySQL.',
        }));
      }
    } catch (err: any) {
      if (!initialData) {
        setDbInspectorModal(prev => ({
          ...prev,
          loading: false,
          error: err?.message || 'Network error retrieving database row.',
        }));
      }
    }
  };

  const handleRemediateDbRow = async (issue: IssueData, action: 'delete_row' | 'cleanse_field') => {
    const { tableName, columnName, rowId } = parseDbFinding(issue);

    if (!tableName || !rowId) {
      showGlobalToast('error', 'Could not determine table name or row ID for this database finding.');
      return;
    }

    try {
      const res: any = await apiRequest({
        path: '/database/remediate',
        method: 'POST',
        data: {
          table: tableName,
          column: columnName,
          row_id: rowId,
          action,
          issue_id: issue.id,
        },
      });

      if (res?.success) {
        showGlobalToast('success', res.message || (action === 'delete_row' ? 'Database record deleted safely.' : 'Database field sanitized successfully.'));
        handleUpdateIssue(issue.id, 'repaired');
        if (dbInspectorModal.isOpen) {
          setDbInspectorModal(prev => ({ ...prev, isOpen: false }));
        }
        loadLatestScan();
      } else {
        showGlobalToast('error', res?.message || 'Database remediation failed.');
      }
    } catch (err: any) {
      console.error(err);
      showGlobalToast('error', err?.message || 'Failed to remediate database row.');
    }
  };

  const uniqueIssues = useMemo(() => {
    const seen = new Set<string>();
    return issues.filter((item) => {
      const key = `${item.engine || ''}|${item.type || ''}|${item.file_path || ''}|${item.line_number || ''}|${item.description || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [issues]);

  const isCveOrWarningIssue = (item: IssueData) =>
    Boolean(
      (item.cves && item.cves.length > 0) ||
      item.is_software_update ||
      item.engine === 'wordpress-updates' ||
      ((item.severity === 'medium' || item.severity === 'low' || item.type?.includes('warning')) &&
        !item.type?.includes('modified') &&
        !item.type?.includes('integrity') &&
        !item.engine?.includes('fim'))
    );

  const openIssuesCount = useMemo(
    () => uniqueIssues.filter((i) => i.status !== 'ignored' && !i.is_whitelisted && i.status !== 'repaired' && i.status !== 'quarantined').length,
    [uniqueIssues]
  );

  const ignoredIssuesCount = useMemo(
    () => uniqueIssues.filter((i) => i.status === 'ignored' || Boolean(i.is_whitelisted)).length,
    [uniqueIssues]
  );

  const filteredIssues = uniqueIssues.filter((item) => {
    const isIgnored = item.status === 'ignored' || Boolean(item.is_whitelisted);
    const matchesStatus =
      issueStatusFilter === 'all' ||
      (issueStatusFilter === 'open' && !isIgnored && item.status !== 'repaired' && item.status !== 'quarantined') ||
      (issueStatusFilter === 'ignored' && isIgnored);
    const matchesSeverity = severityFilter === 'all' || item.severity === severityFilter;
    const matchesCategory =
      categoryFilter === 'all' ||
      (categoryFilter === 'critical' && (item.severity === 'critical' || item.severity === 'high')) ||
      (categoryFilter === 'fim' && (item.type.includes('modified') || item.type.includes('integrity') || item.engine?.includes('fim'))) ||
      (categoryFilter === 'cve' && isCveOrWarningIssue(item)) ||
      (categoryFilter === 'spam' && (item.is_comment || item.is_post || item.engine?.includes('comment') || item.engine?.includes('database') || item.engine?.includes('spam') || item.type.includes('spam') || (item.file_path && item.file_path.startsWith('comment:')))) ||
      (categoryFilter === 'users' && (item.is_user || item.engine?.includes('user') || (item.file_path && item.file_path.startsWith('user:'))));
    const matchesSearch =
      issueSearch === '' ||
      item.file_path.toLowerCase().includes(issueSearch.toLowerCase()) ||
      item.description.toLowerCase().includes(issueSearch.toLowerCase()) ||
      item.type.toLowerCase().includes(issueSearch.toLowerCase()) ||
      (item.author_name && item.author_name.toLowerCase().includes(issueSearch.toLowerCase())) ||
      (item.post_title && item.post_title.toLowerCase().includes(issueSearch.toLowerCase())) ||
      (item.code_snippet && item.code_snippet.toLowerCase().includes(issueSearch.toLowerCase())) ||
      (item.engine && item.engine.toLowerCase().includes(issueSearch.toLowerCase()));
    return matchesStatus && matchesSeverity && matchesCategory && matchesSearch;
  });

  const totalFindingsCount = filteredIssues.length;
  const totalFindingsPages = Math.max(1, Math.ceil(totalFindingsCount / findingsPageSize));

  // Auto reset page to 1 when search or filters change
  useEffect(() => {
    setFindingsPage(1);
  }, [issueStatusFilter, severityFilter, categoryFilter, issueSearch, findingsPageSize]);

  const paginatedIssues = useMemo(() => {
    const startIndex = (findingsPage - 1) * findingsPageSize;
    return filteredIssues.slice(startIndex, startIndex + findingsPageSize);
  }, [filteredIssues, findingsPage, findingsPageSize]);

  const filteredFiles = scannedFiles.filter((item) => {
    if (!fileFilter) return true;
    return item.file_path.toLowerCase().includes(fileFilter.toLowerCase());
  });

  const renderContextualSubNav = () => {
    // 1. Scanner & Audits Cluster
    if (['scan', 'targeted', 'logs', 'fim', 'vulnerabilities'].includes(navTab)) {
      const isEssential = isSimpleMode;
      const scannerTabs = [
        {
          id: 'scan',
          label: 'Security Scan',
          icon: Radar,
          isActive: navTab === 'scan',
          onClick: () => handleNavTabChange('scan'),
        },
        ...(!isEssential ? [{
          id: 'targeted',
          label: 'Targeted Audits',
          icon: Target,
          isActive: navTab === 'targeted',
          onClick: () => handleNavTabChange('targeted'),
        }] : []),
        {
          id: 'logs',
          label: 'Scan Logs & History',
          icon: History,
          isActive: navTab === 'logs',
          onClick: () => handleNavTabChange('logs'),
        },
        {
          id: 'fim',
          label: 'File Integrity (FIM)',
          icon: FileCode,
          isActive: navTab === 'fim',
          onClick: () => handleNavTabChange('fim'),
        },
        {
          id: 'vulnerabilities',
          label: 'Vulnerabilities',
          icon: AlertTriangle,
          isActive: navTab === 'vulnerabilities',
          onClick: () => handleNavTabChange('vulnerabilities'),
        },
      ];

      return (
        <ContextualSubNav
          sectionTitle={isEssential ? 'Essential Scanner' : 'Scanner & Audits'}
          sectionIcon={Radar}
          tabs={scannerTabs}
          relatedLinks={isEssential ? [
            {
              id: 'vault',
              label: 'Quarantine Vault',
              icon: Archive,
              onClick: () => handleNavTabChange('vault'),
            },
          ] : [
            {
              id: 'vault',
              label: 'Quarantine Vault',
              icon: Archive,
              onClick: () => handleNavTabChange('vault'),
            },
            {
              id: 'forensics',
              label: 'Deep Forensics',
              icon: Search,
              onClick: () => handleNavTabChange('forensics'),
            },
          ]}
        />
      );
    }

    // 2. Firewall & WAF Cluster
    if (['firewall', 'waf_logs', 'vpatch'].includes(navTab)) {
      const isEssential = isSimpleMode;
      const firewallTabs = isEssential
        ? [
            {
              id: 'stream',
              label: 'Live Traffic Stream',
              icon: Activity,
              isActive: navTab === 'firewall' && (initialFirewallSubTab === 'stream' || !initialFirewallSubTab),
              onClick: () => handleNavTabChange('firewall', 'stream'),
            },
            {
              id: 'rules',
              label: 'Firewall Rules & WAF',
              icon: Shield,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'rules',
              onClick: () => handleNavTabChange('firewall', 'rules'),
            },
            {
              id: 'caf',
              label: 'Adaptive Firewall (CAF)',
              icon: Sparkles,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'caf',
              onClick: () => handleNavTabChange('firewall', 'caf'),
            },
            {
              id: 'waf_logs',
              label: 'Incident Logs',
              icon: History,
              isActive: navTab === 'waf_logs',
              onClick: () => handleNavTabChange('waf_logs'),
            },
          ]
        : [
            {
              id: 'stream',
              label: 'Live Traffic Stream',
              icon: Activity,
              isActive: navTab === 'firewall' && (initialFirewallSubTab === 'stream' || !initialFirewallSubTab),
              onClick: () => handleNavTabChange('firewall', 'stream'),
            },
            {
              id: 'rules',
              label: 'Firewall Rules & WAF',
              icon: Shield,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'rules',
              onClick: () => handleNavTabChange('firewall', 'rules'),
            },
            {
              id: 'caf',
              label: 'Adaptive Firewall (CAF)',
              icon: Sparkles,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'caf',
              onClick: () => handleNavTabChange('firewall', 'caf'),
            },
            {
              id: 'vpatch',
              label: 'Virtual Patch Studio',
              icon: Zap,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'vpatch',
              onClick: () => handleNavTabChange('firewall', 'vpatch'),
            },
            {
              id: 'intel',
              label: 'Threat Intel Cockpit',
              icon: Globe,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'intel',
              onClick: () => handleNavTabChange('firewall', 'intel'),
            },
            {
              id: 'cloudflare',
              label: 'Cloudflare Edge Sync',
              icon: Cloud,
              isActive: navTab === 'firewall' && initialFirewallSubTab === 'cloudflare',
              onClick: () => handleNavTabChange('firewall', 'cloudflare'),
            },
            {
              id: 'waf_logs',
              label: 'WAF Incident Logs',
              icon: History,
              isActive: navTab === 'waf_logs',
              onClick: () => handleNavTabChange('waf_logs'),
            },
          ];

      return (
        <ContextualSubNav
          sectionTitle={isEssential ? 'Essential Firewall' : 'Firewall & Active Defenses'}
          sectionIcon={Shield}
          tabs={firewallTabs}
          relatedLinks={isEssential ? [
            {
              id: 'auth',
              label: 'Identity Armor',
              icon: Users,
              onClick: () => handleNavTabChange('auth'),
            },
            {
              id: 'headers',
              label: 'Security Headers',
              icon: ShieldCheck,
              onClick: () => handleNavTabChange('settings', 'headers'),
            },
          ] : [
            {
              id: 'server',
              label: 'Host Telemetry',
              icon: Server,
              onClick: () => handleNavTabChange('server'),
            },
            {
              id: 'auth',
              label: 'Identity Armor',
              icon: Users,
              onClick: () => handleNavTabChange('auth'),
            },
            {
              id: 'headers',
              label: 'Security Headers',
              icon: ShieldCheck,
              onClick: () => handleNavTabChange('settings', 'headers'),
            },
          ]}
        />
      );
    }

    // 3. Zero-Trust Identity Cluster
    if (navTab === 'auth') {
      return (
        <ContextualSubNav
          sectionTitle="Login & 2FA"
          sectionIcon={Users}
          tabs={[
            {
              id: '2fa',
              label: 'Two-Factor Auth (2FA)',
              icon: Key,
              isActive: initialAuthSubTab === '2fa' || !initialAuthSubTab,
              onClick: () => handleNavTabChange('auth', '2fa'),
            },
            {
              id: 'admins',
              label: 'Administrator 2FA Policy',
              icon: ShieldCheck,
              isActive: initialAuthSubTab === 'admins',
              onClick: () => handleNavTabChange('auth', 'admins'),
            },
            {
              id: 'zero_trust',
              label: 'Session Forensics & Travel',
              icon: Activity,
              isActive: initialAuthSubTab === 'zero_trust',
              onClick: () => handleNavTabChange('auth', 'zero_trust'),
            },
            {
              id: 'sessions',
              label: 'HIBP Password Shield',
              icon: Lock,
              isActive: initialAuthSubTab === 'sessions',
              onClick: () => handleNavTabChange('auth', 'sessions'),
            },
            {
              id: 'lockouts',
              label: 'Brute-Force Lockouts',
              icon: XCircle,
              isActive: initialAuthSubTab === 'lockouts',
              onClick: () => handleNavTabChange('auth', 'lockouts'),
            },
            {
              id: 'app_passwords',
              label: 'REST App Passwords & Shield',
              icon: Key,
              isActive: initialAuthSubTab === 'app_passwords',
              onClick: () => handleNavTabChange('auth', 'app_passwords'),
            },
            {
              id: 'settings',
              label: 'Auth Hardening',
              icon: SettingsIcon,
              isActive: initialAuthSubTab === 'settings',
              onClick: () => handleNavTabChange('auth', 'settings'),
            },
          ]}
          relatedLinks={[
            {
              id: 'firewall',
              label: 'Firewall Rules',
              icon: Shield,
              onClick: () => handleNavTabChange('firewall', 'rules'),
            },
            {
              id: 'logs',
              label: 'Audit History',
              icon: History,
              onClick: () => handleNavTabChange('logs'),
            },
          ]}
        />
      );
    }

    // 4. Vault & Diagnostics Cluster
    if (['vault', 'quarantine', 'backup', 'forensics', 'server'].includes(navTab)) {
      const isEssential = isSimpleMode;
      const vaultTabs = isEssential
        ? [
            {
              id: 'vault',
              label: 'Quarantine Vault',
              icon: Archive,
              isActive: navTab === 'vault' || navTab === 'quarantine',
              onClick: () => handleNavTabChange('vault'),
            },
            {
              id: 'backup',
              label: 'Database Backup Vault',
              icon: Database,
              isActive: navTab === 'backup',
              onClick: () => handleNavTabChange('backup'),
            },
            {
              id: 'server',
              label: 'Server & PHP Environment',
              icon: HardDrive,
              isActive: navTab === 'server',
              onClick: () => handleNavTabChange('server'),
            },
          ]
        : [
            {
              id: 'vault',
              label: 'Quarantine Vault',
              icon: Archive,
              isActive: navTab === 'vault' || navTab === 'quarantine',
              onClick: () => handleNavTabChange('vault'),
            },
            {
              id: 'backup',
              label: 'Database Backup Vault',
              icon: Database,
              isActive: navTab === 'backup',
              onClick: () => handleNavTabChange('backup'),
            },
            {
              id: 'forensics',
              label: 'Deep System Forensics',
              icon: Search,
              isActive: navTab === 'forensics',
              onClick: () => handleNavTabChange('forensics'),
            },
            {
              id: 'server',
              label: 'Server & PHP Environment',
              icon: HardDrive,
              isActive: navTab === 'server',
              onClick: () => handleNavTabChange('server'),
            },
          ];

      return (
        <ContextualSubNav
          sectionTitle={isEssential ? 'Essential Vault & Tools' : 'WebCare Vault & System Diagnostics'}
          sectionIcon={Server}
          tabs={vaultTabs}
          relatedLinks={isEssential ? [
            {
              id: 'fim',
              label: 'File Integrity (FIM)',
              icon: FileCode,
              onClick: () => handleNavTabChange('fim'),
            },
          ] : [
            {
              id: 'fim',
              label: 'File Integrity (FIM)',
              icon: FileCode,
              onClick: () => handleNavTabChange('fim'),
            },
            {
              id: 'vulnerabilities',
              label: 'CVE Advisor',
              icon: AlertTriangle,
              onClick: () => handleNavTabChange('vulnerabilities'),
            },
          ]}
        />
      );
    }

    // 5. Settings & Administration Cluster
    if (['settings', 'notifications', 'activity_logs', 'about'].includes(navTab)) {
      return (
        <ContextualSubNav
          sectionTitle="Settings & Doctor"
          sectionIcon={SettingsIcon}
          tabs={[
            {
              id: 'containment',
              label: 'Emergency Containment',
              icon: ShieldAlert,
              badge: containmentActive ? 'ACTIVE' : undefined,
              badgeType: 'danger',
              isActive: navTab === 'settings' && initialSettingsSubTab === 'containment',
              onClick: () => handleNavTabChange('settings', 'containment'),
            },
            {
              id: 'schedule',
              label: 'Schedule & General',
              icon: Calendar,
              isActive: navTab === 'settings' && (initialSettingsSubTab === 'schedule' || !initialSettingsSubTab),
              onClick: () => handleNavTabChange('settings', 'schedule'),
            },
            {
              id: 'ai',
              label: 'AI Copilot & Assistant',
              icon: Sparkles,
              isActive: navTab === 'settings' && initialSettingsSubTab === 'ai',
              onClick: () => handleNavTabChange('settings', 'ai'),
            },
            {
              id: 'mcp',
              label: 'Autonomous MCP Server',
              icon: Bot,
              isActive: navTab === 'settings' && initialSettingsSubTab === 'mcp',
              onClick: () => handleNavTabChange('settings', 'mcp'),
            },
            {
              id: 'webhooks',
              label: 'DevSecOps Webhooks',
              icon: MessageSquare,
              isActive: navTab === 'settings' && (initialSettingsSubTab === 'webhooks' || initialSettingsSubTab === 'email'),
              onClick: () => handleNavTabChange('settings', 'webhooks'),
            },
            {
              id: 'headers',
              label: 'Security Headers',
              icon: ShieldCheck,
              isActive: navTab === 'settings' && initialSettingsSubTab === 'headers',
              onClick: () => handleNavTabChange('settings', 'headers'),
            },
            {
              id: 'notifications',
              label: 'Notifications Hub',
              icon: Bell,
              isActive: navTab === 'notifications',
              onClick: () => handleNavTabChange('notifications'),
            },
            {
              id: 'activity_logs',
              label: 'Activity & Audit Logs',
              icon: Activity,
              isActive: navTab === 'activity_logs',
              onClick: () => handleNavTabChange('activity_logs'),
            },
            {
              id: 'about',
              label: 'About & Direct Support',
              icon: LifeBuoy,
              isActive: navTab === 'about',
              onClick: () => handleNavTabChange('about'),
            },
          ]}
          relatedLinks={[
            {
              id: 'firewall',
              label: 'WAF Rules',
              icon: Shield,
              onClick: () => handleNavTabChange('firewall', 'rules'),
            },
            {
              id: 'logs',
              label: 'Audit History',
              icon: History,
              onClick: () => handleNavTabChange('logs'),
            },
          ]}
        />
      );
    }

    // 6. Dashboard / Executive View
    if (navTab === 'dashboard') {
      return (
        <ContextualSubNav
          sectionTitle="Dashboard"
          sectionIcon={LayoutDashboard}
          tabs={[
            {
              id: 'overview',
              label: 'Security Posture & Telemetry',
              icon: LayoutDashboard,
              isActive: true,
              onClick: () => handleNavTabChange('dashboard'),
            },
          ]}
          relatedLinks={[
            {
              id: 'scan',
              label: 'Run Security Scan',
              icon: Radar,
              onClick: () => handleNavTabChange('scan'),
            },
            {
              id: 'firewall',
              label: 'Firewall Stream',
              icon: Shield,
              onClick: () => handleNavTabChange('firewall'),
            },
            {
              id: 'auth',
              label: 'Session Forensics',
              icon: Users,
              onClick: () => handleNavTabChange('auth', 'zero_trust'),
            },
          ]}
        />
      );
    }

    return null;
  };

  return (
    <div className={`webcare-container ${themeMode === 'light' ? 'webcare-theme-light' : 'webcare-theme-dark'}`}>
      {/* =========================================================================
          EXECUTIVE TWO-TIER PROFESSIONAL HEADER BAR (DATADOG / CLOUDFLARE STYLE)
          Tier 1: Brand & Subtitle ("Enterprise Protection Active • v1.29.0") + Global Controls
          Tier 2: Dedicated Navigation Row with 6 Core Pillars & Quick-Jump Modules
          ========================================================================= */}
      <header className="header-bar webcare-two-tier-header">
        {/* TIER 1: BRAND IDENTITY & GLOBAL CONTROLS */}
        <div className="webcare-header-tier-top">
          <div className="brand-section">
            <div 
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
              onClick={() => handleNavTabChange('dashboard')}
              title="Return to Executive Security Dashboard"
            >
              <WebCareBrandLogo size={36} />
            </div>
            <div>
              <div className="brand-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontFamily: 'var(--font-display, "Outfit", sans-serif)', fontSize: '18px', fontWeight: 800, color: 'var(--webcare-text-title)', letterSpacing: '-0.02em' }}>
                  WebCare <span className="highlight" style={{ color: '#0ea5e9' }}>Pro</span> Security
                </span>
              </div>
              <div className="brand-subtitle" style={{ marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--webcare-text-secondary)' }}>
                <span className="pulse-dot" style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 0 3px rgba(16, 185, 129, 0.2)' }}></span>
                <span>Enterprise Protection Active</span>
                <span className="webcare-dot-bullet" />
                <span style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 600, color: 'var(--webcare-text-secondary)' }}>v{pluginVersion}</span>
              </div>
            </div>
          </div>

          <div className="webcare-header-actions" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            {/* Mode Switcher: Simple Owner View vs. Pro Engineer View */}
            <button
              type="button"
              className={`webcare-mode-toggle-pill ${isDeveloperMode ? 'is-advanced' : 'is-essential'}`}
              onClick={toggleWorkspaceMode}
              title={isSimpleMode
                ? "Switch to Pro Engineer Mode (Unlocks all 53 deep inspection engines, Hex dumps, AST analyzer & MCP controls)"
                : "Switch to Simple Owner Mode (Plain-English protection outcomes for site owners & non-technical users)"
              }
              aria-label="Toggle Simple Owner or Pro Engineer View"
            >
              <div className="webcare-mode-toggle-thumb">
                {isDeveloperMode ? (
                  <SlidersHorizontal size={13} className="webcare-mode-icon" />
                ) : (
                  <ShieldCheck size={13} className="webcare-mode-icon" />
                )}
              </div>
              <div className="webcare-mode-toggle-label">
                <span className="webcare-mode-toggle-title">
                  {isDeveloperMode ? 'Pro Engineer' : 'Simple Owner'}
                </span>
                <span className={`webcare-mode-toggle-chip ${isDeveloperMode ? 'chip-advanced' : 'chip-essential'}`}>
                  {isDeveloperMode ? '53 Engines' : 'Simple'}
                </span>
              </div>
            </button>

            {/* Rescue Assistant ("Something Not Working?") */}
            <button
              type="button"
              className="webcare-btn"
              onClick={() => setRescueModalOpen(true)}
              title="Something Not Working? Click to Troubleshoot & 1-Click Fix My Site"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                background: rescuePaused ? 'var(--webcare-status-warn-soft)' : 'var(--webcare-status-info-soft)',
                color: rescuePaused ? 'var(--webcare-status-warn)' : 'var(--webcare-status-info)',
                border: `1px solid ${rescuePaused ? 'var(--webcare-status-warn-border)' : 'var(--webcare-status-info-border)'}`,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Wrench size={13} />
              <span>{rescuePaused ? 'Test Mode Active' : 'Something Not Working?'}</span>
            </button>

            {/* Welcome Guide Trigger */}
            <button
              type="button"
              className="webcare-btn"
              onClick={() => setIsWelcomeModalOpen(true)}
              title="Open Welcome Guide & Pre-Flight Readiness"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 700,
                background: 'rgba(6, 182, 212, 0.08)',
                color: '#0284c7',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Sparkles size={13} color="#0284c7" />
              <span className="webcare-wizard-btn-text">Welcome Guide</span>
            </button>

            {/* 1-Click Emergency Incident Containment Trigger / Status Pill in Header */}
            {containmentActive ? (
              <button
                type="button"
                className="webcare-header-containment-badge"
                onClick={() => handleNavTabChange('settings', 'containment')}
                title="Emergency Incident Containment is ACTIVE. Click to manage."
              >
                <ShieldAlert size={14} />
                <span>LOCKDOWN ACTIVE</span>
              </button>
            ) : (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleNavTabChange('settings', 'containment')}
                title="1-Click Emergency Incident Containment Protocol & Panic Lockdown"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 700,
                  background: 'rgba(239, 68, 68, 0.08)',
                  color: '#dc2626',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <ShieldAlert size={13} color="#dc2626" />
                <span className="webcare-panic-btn-text">Panic Button</span>
              </button>
            )}

            {/* Theme Toggle Button (Light / Dark Mode Switcher) */}
            <button
              type="button"
              className="webcare-theme-toggle-btn"
              onClick={toggleThemeMode}
              title={`Switch to ${themeMode === 'dark' ? 'Light / White Mode' : 'Dark Mode'}`}
              aria-label={`Switch to ${themeMode === 'dark' ? 'Light / White Mode' : 'Dark Mode'}`}
            >
              {themeMode === 'dark' ? (
                <>
                  <Sun size={14} className="webcare-theme-toggle-icon" />
                  <span className="webcare-theme-toggle-text">White Mode</span>
                </>
              ) : (
                <>
                  <Moon size={14} className="webcare-theme-toggle-icon" />
                  <span className="webcare-theme-toggle-text">Dark Mode</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* TIER 2: PRIMARY NAVIGATION ROW (6 CORE PILLARS + ALL MODULES) */}
        <div className="webcare-header-tier-bottom">
          <nav className="nav-tabs">
            <button
              type="button"
              className={`nav-tab-btn ${navTab === 'dashboard' ? 'active' : ''}`}
              id="tabBtnDashboard"
              onClick={() => handleNavTabChange('dashboard')}
            >
              <LayoutDashboard size={15} />
              <span>Dashboard</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['firewall', 'vpatch', 'custom_rules', 'modular_waf'].includes(navTab) ? 'active' : ''}`}
              id="tabBtnFirewall"
              onClick={() => handleNavTabChange('firewall')}
            >
              <Shield size={15} />
              <span>Firewall</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['waf_logs', 'activity_logs'].includes(navTab) ? 'active' : ''}`}
              id="tabBtnLogs"
              onClick={() => handleNavTabChange('waf_logs')}
            >
              <FileText size={15} />
              <span>Logs &amp; Bans</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['scan', 'targeted', 'logs', 'fim', 'vulnerabilities'].includes(navTab) ? 'active' : ''}`}
              id="tabBtnScan"
              onClick={() => handleNavTabChange('scan')}
            >
              <Radar size={15} />
              <span>Malware &amp; Scanner</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${navTab === 'auth' ? 'active' : ''}`}
              id="tabBtnIdentity"
              onClick={() => handleNavTabChange('auth')}
            >
              <Users size={15} />
              <span>Login &amp; Access</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['vault', 'quarantine', 'backup', 'forensics', 'server'].includes(navTab) ? 'active' : ''}`}
              id="tabBtnVault"
              onClick={() => handleNavTabChange('vault')}
            >
              <Server size={15} />
              <span>Backups &amp; Vault</span>
            </button>

            <button
              type="button"
              className={`nav-tab-btn ${['settings', 'notifications', 'about', 'cron_manager'].includes(navTab) ? 'active' : ''}`}
              id="tabBtnSettings"
              onClick={() => handleNavTabChange('settings')}
            >
              <SettingsIcon size={15} />
              <span>Settings &amp; Doctor</span>
            </button>

            {/* Quick-Jump Mega Menu Button */}
            <button
              type="button"
              className={`nav-tab-btn webcare-mega-menu-trigger ${megaMenuOpen ? 'active' : ''}`}
              id="tabBtnAllModules"
              onClick={() => setMegaMenuOpen(true)}
              title="Explore all modules, tools & settings (Ctrl + K)"
            >
              <Grid size={15} />
              <span>All Modules</span>
              <span className="webcare-kbd-shortcut">⌘K</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Tier 2 Contextual Secondary Page Navigation Bar */}
      {renderContextualSubNav()}

      {/* Persistent Global Active Scan Top Banner (Only visible outside Scan page to avoid duplicate progress bars) */}
      {(scanning || targetedScanning) && navTab !== 'scan' && (
        <div className="webcare-active-scan-banner">
          <div className="webcare-active-scan-banner-info">
            <div className="webcare-active-scan-spinner-box">
              <Loader2 size={20} className="webcare-spin-icon" />
            </div>
            <div>
              <div className="webcare-active-scan-title">
                <span><strong>Scan in Progress:</strong> </span>
                <span>
                  {targetedScanning
                    ? getScanTargetInfo(targetedScanning).name
                    : (activeScanTrigger === 'scheduled'
                        ? `Scheduled Auto Scan (${scanTarget === 'full' ? 'Full System' : 'Plugins & Themes'})`
                        : (scanTarget === 'custom' ? 'Custom Security Scan' : scanTarget === 'full' ? 'Complete Website Scan' : 'Quick Scan (Plugins & Themes)'))}
                </span>
                <span className="webcare-active-scan-percent">
                  {targetedScanning ? `${targetedProgress}%` : `${progress}%`}
                </span>
                {!targetedScanning && (
                  <span className="webcare-active-scan-telemetry-chip">
                    <span>⏱️ {formatElapsedTimer(scanElapsed)}</span>
                    {scanTelemetry?.memory_mb && <span> • 💾 {scanTelemetry.memory_mb} MB</span>}
                    {scanTelemetry?.cpu_percent !== null && scanTelemetry?.cpu_percent !== undefined && (
                      <span> • ⚡ {scanTelemetry.cpu_percent}% CPU</span>
                    )}
                  </span>
                )}
              </div>
              <div className="webcare-active-scan-subtitle">
                <span>{targetedScanning ? (targetedStage || 'Auditing security vectors...') : (scanStage || 'Examining filesystem...')}</span>
              </div>
            </div>
          </div>
          <div className="webcare-active-scan-actions">
            {targetedScanning && navTab !== 'targeted' && (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleNavTabChange('targeted')}
                style={{ fontSize: '12px', padding: '6px 14px', background: '#3b82f6', color: '#fff' }}
              >
                <span>View Targeted Scan</span>
              </button>
            )}
            {!targetedScanning && navTab !== 'scan' && (
              <button
                type="button"
                className="webcare-btn"
                onClick={() => handleNavTabChange('scan')}
                style={{ fontSize: '12px', padding: '6px 14px', background: '#3b82f6', color: '#fff' }}
              >
                <span>View Active Scan</span>
              </button>
            )}
            <button
              type="button"
              className="webcare-btn"
              onClick={handleAbortScan}
              style={{ fontSize: '12px', padding: '6px 14px', background: '#ef4444', color: '#fff', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <XCircle size={14} />
              <span>Stop Scan</span>
            </button>
          </div>
        </div>
      )}

      {/* =========================================================
           PAGE 1: CALM EXECUTIVE SECURITY DASHBOARD
           ========================================================= */}
      {navTab === 'dashboard' && (
        <main className="dashboard-view active" id="viewDashboard">
          <DashboardOverview
            currentScan={currentScan}
            uniqueIssues={uniqueIssues}
            firewallStatus={firewallStatus}
            firewallLogs={firewallLogs}
            serverInfo={serverInfo}
            vulnReport={vulnReport}
            quarantinedFiles={quarantinedFiles}
            backups={backups}
            isScanning={scanning}
            onStartScan={() => handleStartScan('quick')}
            onOpenRescueModal={() => setRescueModalOpen(true)}
            isRescuePaused={rescuePaused}
            onNavigate={(targetTab, subTab, nestedSubTab) =>
              handleNavTabChange(targetTab, subTab, nestedSubTab)
            }
            formatRelativeTime={formatRelativeTime}
          />

          {/* MANDATORY SOLO FREELANCER SENIOR EXPERT CARD */}
          <section className="expert-support-card webcare-card-elevated" style={{ marginTop: '24px' }}>
            <div className="expert-info">
              <div className="expert-avatar-wrap">
                <User size={28} color="#ffffff" />
                <div className="expert-badge-online" />
              </div>
              <div className="expert-text">
                <h4>Connect directly with Mir Alamin (WebCare Pro)</h4>
                <p>
                  Senior Linux SysAdmin &amp; WordPress Security Engineer &bull; Direct 1-on-1 assistance for custom server hardening &amp; malware recovery.
                </p>
              </div>
            </div>
            <div className="expert-actions">
              <button
                type="button"
                className="btn-expert"
                onClick={() => handleNavTabChange('settings', 'support')}
              >
                <MessageSquare size={15} />
                <span>Connect with me directly</span>
              </button>
            </div>
          </section>
        </main>
      )}

      {/* =========================================================
           PAGE 2: DEDICATED SECURITY SCANNER & AUDIT SUITE (SCAN TAB ONLY)
           ========================================================= */}
      {navTab === 'scan' && (
        <SafeErrorBoundary fallbackTitle="Security Scanner Error">
          <SecurityScannerPage
            apiRequest={apiRequest}
            currentScan={currentScan}
            availableScans={availableScans}
            selectedDashboardScanId={selectedDashboardScanId}
            setSelectedDashboardScanId={setSelectedDashboardScanId}
            scanning={scanning}
            progress={progress}
            scanStage={scanStage}
            currentFile={currentFile}
            scanTelemetry={scanTelemetry}
            scanElapsed={scanElapsed}
            dbProgress={dbProgress}
            activeScanTrigger={activeScanTrigger}
            scanTarget={scanTarget}
            setScanTarget={setScanTarget}
            customScanOptions={customScanOptions}
            onOpenCustomScanModal={() => setIsCustomScanModalOpen(true)}
            onStartScan={handleStartScan}
            onAbortScan={handleAbortScan}
            onReloadLatestScan={loadLatestScan}
            onNavigateTab={handleNavTabChange}
            quarantinedFiles={quarantinedFiles}
            scannedFiles={scannedFiles}
            issues={issues}
            setIssues={setIssues}
            summary={summary}
            loading={loading}
            requestConfirmation={requestConfirmation}
            showGlobalToast={showGlobalToast}
            handleQuarantine={handleQuarantine}
            handleRestoreQuarantine={handleRestoreQuarantine}
            handleDeleteQuarantine={handleDeleteQuarantine}
            handleRemediateUser={handleRemediateUser}
            handleRemediateDbRow={handleRemediateDbRow}
            handleDeleteCronHook={handleDeleteCronHook}
            handleModerateComment={handleModerateComment}
            handleFixPermissions={handleFixPermissions}
            handleAutoCureIssue={handleAutoCureIssue}
            handleAutoCurePlugin={handleAutoCurePlugin}
            handleAutoCureCore={handleAutoCureCore}
            handleAutoCureStrip={handleAutoCureStrip}
            handleDeleteRogueFile={handleDeleteRogueFile}
            canQuarantineIssue={canQuarantineIssue}
            handleDisableWpDebug={handleDisableWpDebug}
            handleUpdateIssue={handleUpdateIssue}
            onOpenVisualDiff={(filePath, issueId) => {
              setVisualDiffModal({
                isOpen: true,
                filePath,
                issueId,
              });
            }}
            onOpenFileViewer={handleOpenFileViewer}
            onOpenChangelog={handleOpenChangelog}
            onOpenWhitelistModal={(issue) => setWhitelistModal({ isOpen: true, issue })}
            onOpenCveModal={(issue) => setCveModal({ isOpen: true, issue })}
            dbRowCache={dbRowCache}
            loadDbRow={loadDbRow}
          />
        </SafeErrorBoundary>
      )}

      {/* VIEW 2: TARGETED SCANS */}
      {navTab === 'targeted' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ background: 'var(--webcare-bg-card, #ffffff)', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
            <h2 style={{ margin: '0 0 6px 0', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Zap size={22} color="#3b82f6" /> Targeted Single-Purpose Audits
            </h2>
            <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
              Run focused, rapid scans for specific vectors without waiting for a full filesystem scan cycle.
            </p>
          </div>

          {/* Animated Cool Progress Bar Card */}
          {targetedScanning && (
            <div className="webcare-targeted-progress-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <div style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '12px',
                    background: 'rgba(59, 130, 246, 0.25)',
                    border: '1px solid rgba(56, 189, 248, 0.45)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#38bdf8',
                    boxShadow: '0 0 15px rgba(56, 189, 248, 0.3)'
                  }}>
                    <Loader2 size={24} className="webcare-spin-icon" />
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        letterSpacing: '0.8px',
                        padding: '3px 9px',
                        borderRadius: '999px',
                        background: 'rgba(6, 182, 212, 0.22)',
                        color: '#38bdf8',
                        border: '1px solid rgba(6, 182, 212, 0.35)'
                      }}>
                        ⚡ Targeted Audit in Progress
                      </span>
                      <span style={{ fontSize: '13px', color: '#94a3b8' }}>
                        Target: <strong style={{ color: '#f8fafc' }}>{targetedScanning.replace('_', ' ').toUpperCase()}</strong>
                      </span>
                    </div>
                    <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#ffffff' }}>
                      {targetedStage}
                    </h3>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'rgba(255, 255, 255, 0.08)',
                    padding: '6px 14px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.12)',
                    fontSize: '13px',
                    color: '#cbd5e1'
                  }}>
                    <Clock size={15} color="#38bdf8" />
                    <span>Elapsed: <strong style={{ color: '#ffffff' }}>{targetedElapsed}s</strong></span>
                  </div>
                  <div style={{
                    fontSize: '30px',
                    fontWeight: 900,
                    color: '#38bdf8',
                    textShadow: '0 0 18px rgba(56, 189, 248, 0.7)',
                    minWidth: '75px',
                    textAlign: 'right',
                    fontFamily: 'monospace'
                  }}>
                    {targetedProgress}%
                  </div>
                </div>
              </div>

              {/* Progress Track & Animated Fill */}
              <div className="webcare-targeted-progress-track">
                <div
                  className="webcare-targeted-progress-bar"
                  style={{ width: `${targetedProgress}%` }}
                />
              </div>

              {/* Bottom Micro Details */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', fontSize: '12px', color: '#94a3b8', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 10px #10b981' }} />
                  <span style={{ fontFamily: 'monospace', color: '#cbd5e1', fontSize: '13px' }}>
                    {targetedDetail}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={handleAbortScan}
                    style={{
                      background: '#ef4444',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '6px',
                      padding: '4px 10px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      boxShadow: '0 2px 6px rgba(239, 68, 68, 0.4)'
                    }}
                  >
                    <XCircle size={13} /> Stop Scan
                  </button>
                  <span style={{ background: 'rgba(255, 255, 255, 0.06)', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    High-Performance Fast Path
                  </span>
                  <span style={{ color: '#38bdf8', fontWeight: 600 }}>Active Stream</span>
                </div>
              </div>
            </div>
          )}

          <div className="webcare-targeted-grid">
            {/* 1. Modified Themes, Plugins & Core Files Audit */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#fef3c7', color: '#d97706' }}>
                  <FileCode size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Modified Themes, Plugins &amp; Core</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Tampered Files &amp; Code Drift Audit</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Compares all installed WordPress Core, plugins, and themes against official WordPress.org release checksums to instantly isolate tampered, modified, or backdoor-injected files.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#d97706' }}
                onClick={() => handleStartTargetedScan('modified_files')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'modified_files' ? 'Auditing Modified Files...' : 'Scan Modified Files (Core/Plugins/Themes)'}
              </button>
            </div>

            {/* 2. Unknown Files Finder */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#eff6ff', color: '#3b82f6' }}>
                  <FileQuestion size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Unknown Files Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Core, Plugins & Themes Reverse Check</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Reconciles files inside <code>wp-admin</code>, <code>wp-includes</code>, and official plugins/themes against official WordPress.org checksums to isolate unrecognized or rogue backdoors.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => handleStartTargetedScan('unknown_files')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'unknown_files' ? 'Scanning Unknown Files...' : 'Find Only Unknown Files'}
              </button>
            </div>

            {/* 2. Spam Posts / Pages Only */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#fef2f2', color: '#ef4444' }}>
                  <Search size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Spam Content & DB Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Posts, Pages & Comments</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Inspects all published posts, pages, comments, and options for blackhat pharmaceutical spam, hidden iframes, base64 script tags, and malicious SEO keyword cloaking.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#ef4444' }}
                onClick={() => handleStartTargetedScan('spam_content')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'spam_content' ? 'Auditing Content Spam...' : 'Scan Spam Content Only'}
              </button>
            </div>

            {/* 3. Filesystem Only */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#f0fdf4', color: '#16a34a' }}>
                  <HardDrive size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Filesystem Security Only</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Permissions, Uploads & Symlinks</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits filesystem permissions, dangerous symlinks leading outside docroot, and flags PHP or executable scripts disguised inside <code>wp-content/uploads/</code>.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#16a34a' }}
                onClick={() => handleStartTargetedScan('filesystem_only')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'filesystem_only' ? 'Auditing Filesystem...' : 'Audit Filesystem Only'}
              </button>
            </div>

            {/* 4. User Accounts, Roles & Capability Auditor */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#fffbeb', color: '#d97706' }}>
                  <UserCheck size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>User Accounts &amp; Roles Auditor</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Stealth Privileges &amp; Capabilities</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 8px 0' }}>
                Detects stealth privilege escalation (e.g. Customers/Subscribers granted upload or admin powers via Role Editor), flags ghost accounts missing capabilities, detects tampered roles, and audits weak passwords.
              </p>
              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
                  <input
                    type="checkbox"
                    checked={adminOnlyUsers}
                    onChange={(e) => setAdminOnlyUsers(e.target.checked)}
                  />
                  <strong>Audit Administrator Users Only</strong>
                </label>
              </div>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#d97706' }}
                onClick={() => handleStartTargetedScan('user_security', { admins_only: adminOnlyUsers })}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'user_security' ? 'Auditing Users & Capabilities...' : 'Audit Accounts & Capabilities'}
              </button>
            </div>

            {/* 5. Outdated Software Audit */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#faf5ff', color: '#9333ea' }}>
                  <Activity size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Outdated Software Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>WP Core, Plugins & Themes</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits all installed plugins, active/inactive themes, and WordPress core against the official repository to flag software requiring security updates.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#9333ea' }}
                onClick={() => handleStartTargetedScan('outdated_software')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'outdated_software' ? 'Checking Updates...' : 'Audit Outdated Software'}
              </button>
            </div>

            {/* 6. Uploads Executables & Suspicious Files */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#fef2f2', color: '#dc2626' }}>
                  <FileWarning size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Uploads Executables Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Detect .php, .sh & Rogue Files in Uploads</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Recursively audits <code>wp-content/uploads/</code> to detect forbidden <code>.php</code>, <code>.sh</code>, shell scripts, disguised double extensions, and rogue server configs.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#dc2626' }}
                onClick={() => handleStartTargetedScan('suspicious_uploads')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'suspicious_uploads' ? 'Scanning Uploads...' : 'Scan Uploads for Executables'}
              </button>
            </div>

            {/* 7. Crontab & Scheduled Tasks Audit */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#f0fdfa', color: '#0d9488' }}>
                  <Terminal size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Crontab & Schedulers Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Linux Crontab & WP-Cron Tasks</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits Linux server crontab (<code>crontab -l</code>, <code>/var/spool/cron</code>) and WordPress virtual cron hooks for malicious piped shells, reverse shells, and persistence vectors.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#0d9488' }}
                onClick={() => handleStartTargetedScan('crontab_audit')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'crontab_audit' ? 'Auditing Crontab & Tasks...' : 'Audit Crontab & Schedulers'}
              </button>
            </div>

            {/* 8. WordPress Core Integrity Scan */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#e0f2fe', color: '#0284c7' }}>
                  <Cpu size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>WordPress Core Integrity</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Official Release Checksum Verification</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Compares all WordPress core files in <code>wp-admin</code>, <code>wp-includes</code>, and root against official WordPress.org cryptographic hashes to flag modified, tampered, or missing files.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#0284c7' }}
                onClick={() => handleStartTargetedScan('core_integrity')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'core_integrity' ? 'Auditing Core Integrity...' : 'Scan Core Integrity Only'}
              </button>
            </div>

            {/* 9. Rogue Administrator & Database Micro-Anomaly Audit */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#fdf2f8', color: '#db2777' }}>
                  <ShieldAlert size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Rogue Admin &amp; DB Anomalies</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Hidden Admins &amp; Privilege Injections</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits <code>wp_users</code>, <code>wp_usermeta</code>, and <code>wp_options</code> for stealth administrator accounts, backdoored capabilities injected into low-level users, and persistent rootkit transients.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#db2777' }}
                onClick={() => handleStartTargetedScan('rogue_admin')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'rogue_admin' ? 'Auditing Rogue Administrators...' : 'Audit Rogue Admins & DB Anomaly'}
              </button>
            </div>

            {/* 10. Living-off-the-Land (LotL) Hook Infiltration Sentinel */}
            <div className="webcare-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="webcare-action-icon" style={{ background: '#f5f3ff', color: '#7c3aed' }}>
                  <ShieldCheck size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Hook Sentinel &amp; LotL Traps</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Runtime Memory Hook Infiltration</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits runtime WordPress filters and actions (<code>$wp_filter</code>) to detect closures on auth hooks, external file callbacks, and stealth in-memory Living-off-the-Land backdoors.
              </p>
              <button
                className="webcare-btn webcare-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#7c3aed' }}
                onClick={() => handleStartTargetedScan('hook_sentinel')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'hook_sentinel' ? 'Auditing Runtime Hooks...' : 'Audit Hook Infiltration (LotL)'}
              </button>
            </div>
          </div>

          {/* Targeted Scan Result Section */}
          {targetedResult && (
            <div ref={targetedResultRef} className="webcare-card" style={{ marginTop: '12px', scrollMarginTop: '24px' }}>
              <div className="webcare-card-header">
                <div>
                  <h3 style={{ margin: 0 }}>Targeted Audit Results: {targetedResult.target}</h3>
                  <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
                    Risk Score: <strong>{targetedResult.summary.score}/100</strong> ({targetedResult.summary.level.toUpperCase()}) | Issues Found: <strong>{targetedResult.issues.length}</strong>
                  </p>
                </div>
                <button
                  className="webcare-btn"
                  style={{ background: '#f1f5f9', color: '#475569', padding: '6px 12px' }}
                  onClick={() => setTargetedResult(null)}
                >
                  Close Findings
                </button>
              </div>

              {targetedResult.issues.length === 0 ? (
                <div style={{ padding: '36px', textAlign: 'center', color: '#10b981' }}>
                  <CheckCircle size={40} style={{ margin: '0 auto 8px auto' }} />
                  <div style={{ fontWeight: 600, fontSize: '16px', color: 'var(--webcare-text-primary, #0f172a)' }}>Audit Passed Cleanly</div>
                  <div style={{ fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>No threats or anomalies detected for this targeted profile.</div>
                </div>
              ) : (
                <Fragment>
                  {/* Expert Assistance Quick Banner for Targeted Audit Findings */}
                  <div style={{
                    margin: '16px 20px',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    border: '1px solid var(--webcare-border, #cbd5e1)',
                    borderLeft: '4px solid #7c3aed',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <LifeBuoy size={18} color="#7c3aed" />
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                          Need Direct Expert Assistance with these {targetedResult.issues.length} {targetedResult.target} anomalies?
                        </div>
                        <div style={{ fontSize: '12px', color: '#64748b' }}>
                          Connect with Mir Alamin for 1-on-1 forensics, remediation guidance, or custom server configuration.
                        </div>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="webcare-btn"
                      style={{
                        background: '#7c3aed',
                        color: '#ffffff',
                        border: 'none',
                        fontSize: '12px',
                        fontWeight: 600,
                        padding: '6px 14px',
                        borderRadius: '6px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        cursor: 'pointer'
                      }}
                      onClick={() => handleNavTabChange('settings', 'support')}
                    >
                      <Phone size={13} />
                      <span>Contact Mir Alamin</span>
                      <ArrowUpRight size={13} />
                    </button>
                  </div>

                  <table className="webcare-table">
                  <thead>
                    <tr>
                      <th style={{ width: '45px', textAlign: 'center' }}>#</th>
                      <th>Severity</th>
                      <th>Type</th>
                      <th>Location / Subject</th>
                      <th>Description</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Mitigation Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targetedResult.issues.map((iss, index) => {
                      const isExpanded = expandedTargetedIssue === iss.id;
                      const isComment = iss.is_comment || iss.engine === 'content-comments' || Boolean(iss.file_path && iss.file_path.startsWith('comment:'));
                      const isPost = !isComment && iss.is_post;
                      const isDbTable = iss.is_db_table || iss.engine === 'database-table' || Boolean(iss.file_path && !iss.file_path.includes('/') && !iss.file_path.includes('\\') && iss.file_path.includes('.') && iss.file_path.includes('[ID:'));
                      const isUpdate = iss.engine === 'wordpress-updates' || iss.is_software_update;
                      const isUser = Boolean(
                        iss.is_user ||
                        iss.engine === 'wordpress-users' ||
                        iss.type?.startsWith('user_') ||
                        iss.type?.includes('admin_user') ||
                        iss.type?.includes('user_capabilities') ||
                        iss.type?.includes('role_definition') ||
                        iss.type?.includes('weak_password') ||
                        iss.type?.includes('application_password') ||
                        iss.file_path?.startsWith('user:') ||
                        iss.file_path?.startsWith('author:')
                      );
                      const isCron = Boolean(
                        iss.is_cron ||
                        iss.engine === 'cron-scanner' ||
                        iss.type?.includes('cron') ||
                        iss.file_path?.startsWith('cron:')
                      );
                      const isHook = Boolean(
                        iss.is_hook ||
                        iss.engine === 'hook-sentinel' ||
                        iss.type?.includes('hook') ||
                        iss.type?.includes('filter')
                      );
                      const isPhysicalFile = !isPost && !isComment && !isDbTable && !isUpdate && !isUser && !isCron && !iss.is_dir && Boolean(iss.file_path) && !iss.file_path.startsWith('cron:') && !iss.file_path.startsWith('wp_options:') && !iss.file_path.startsWith('db:') && !iss.file_path.startsWith('table:') && !iss.file_path.startsWith('user:') && !iss.file_path.startsWith('author:') && !iss.file_path.startsWith('comment:') && !iss.file_path.startsWith('server:') && (iss.file_path.includes('/') || iss.file_path.includes('\\'));

                      const isUnknownFile = Boolean(
                        iss.type?.includes('unknown') ||
                        iss.type?.includes('unrecognized') ||
                        iss.type?.includes('extra') ||
                        iss.type?.includes('disguised') ||
                        iss.type?.includes('webshell') ||
                        iss.type?.includes('backdoor') ||
                        iss.type?.includes('malware') ||
                        iss.type?.includes('rogue') ||
                        iss.type?.includes('orphan') ||
                        iss.type?.includes('unexpected') ||
                        iss.type?.includes('unauthorized_dropin') ||
                        iss.engine?.includes('uploads')
                      );

                      const isChecksumsUnavailable = Boolean(
                        iss.is_custom ||
                        iss.is_premium ||
                        iss.is_wporg === false ||
                        iss.type === 'plugin_checksums_unavailable' ||
                        iss.type === 'theme_checksums_unavailable' ||
                        iss.type === 'core_checksums_unavailable' ||
                        iss.type?.includes('_checksums_unavailable') ||
                        (iss.severity === 'info' && Boolean(iss.description?.toLowerCase().includes('checksums unavailable')))
                      );

                      const isModifiedFile = isPhysicalFile && !isUnknownFile && !isChecksumsUnavailable && Boolean(
                        iss.type?.includes('modified') ||
                        iss.type?.includes('missing') ||
                        iss.type?.includes('tampered') ||
                        iss.type?.includes('mismatch') ||
                        iss.type === 'core_integrity' ||
                        iss.type === 'important_file_modified' ||
                        iss.file_path?.endsWith('wp-config.php')
                      );

                      const isFimEligible = isPhysicalFile && isModifiedFile && !isUnknownFile && !isChecksumsUnavailable;

                      const isCore = isPhysicalFile && isModifiedFile && !isUnknownFile && !isChecksumsUnavailable && (
                        iss.type === 'modified_core_file' ||
                        iss.type === 'missing_core_file' ||
                        iss.type === 'core_file_modified' ||
                        iss.type === 'core_file_missing' ||
                        iss.type === 'core_integrity' ||
                        (Boolean(iss.file_path && (iss.file_path.includes('/wp-admin/') || iss.file_path.includes('/wp-includes/') || /^wp-[^/\\]+\.php$|^index\.php$/i.test(iss.file_path.replace(/\\/g, '/').split('/').pop() || '')) && !iss.file_path.endsWith('wp-config.php') && !iss.file_path.endsWith('.htaccess')) && isModifiedFile)
                      );

                      const isPlugin = isPhysicalFile && isModifiedFile && !isUnknownFile && !isChecksumsUnavailable && (
                        iss.type === 'modified_plugin_file' ||
                        iss.type === 'missing_plugin_file' ||
                        iss.type === 'plugin_file_modified' ||
                        iss.type === 'plugin_file_missing' ||
                        (Boolean(iss.file_path && iss.file_path.includes('/plugins/')) && isModifiedFile)
                      );

                      const isTheme = isPhysicalFile && isModifiedFile && !isUnknownFile && !isChecksumsUnavailable && (
                        iss.type === 'modified_theme_file' ||
                        iss.type === 'missing_theme_file' ||
                        iss.type === 'theme_file_modified' ||
                        iss.type === 'theme_file_missing' ||
                        (Boolean(iss.file_path && iss.file_path.includes('/themes/')) && isModifiedFile)
                      );

                      const isInjectedWrapper = isPhysicalFile && !isUnknownFile && (
                        iss.type?.includes('injected') ||
                        iss.type?.includes('prepended') ||
                        iss.type === 'injected_critical_file' ||
                        iss.type === 'injected_wp_config'
                      );

                      const isWebshell = Boolean(iss.code_snippet || iss.type?.includes('webshell') || iss.type?.includes('eval') || iss.type?.includes('injected') || iss.type?.includes('malware'));

                      return (
                        <Fragment key={`targeted-finding-${iss.id}`}>
                          <tr key={`targeted-row-${iss.id}`}>
                            <td style={{ textAlign: 'center', padding: '12px 6px' }}>
                              <button
                                type="button"
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  cursor: 'pointer',
                                  padding: '4px',
                                  color: '#64748b',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '3px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  fontFamily: 'monospace'
                                }}
                                onClick={() => setExpandedTargetedIssue(isExpanded ? null : iss.id)}
                                title={isExpanded ? 'Collapse finding details' : 'Expand finding details'}
                              >
                                {isExpanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                                <span>{index + 1}</span>
                              </button>
                            </td>
                            <td><span className={`webcare-badge webcare-badge-${iss.severity}`}>{iss.severity}</span></td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                <span style={{ fontWeight: 600 }}>{iss.type}</span>
                                {isComment ? (
                                  <span className="webcare-type-badge-comment" style={{ background: '#f5f3ff', color: '#7c3aed', border: '1px solid #ddd6fe', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <MessageSquare size={11} /> COMMENT {iss.comment_id ? `#${iss.comment_id}` : ''}
                                  </span>
                                ) : isDbTable ? (
                                  <span className="webcare-type-badge-db" style={{ background: '#faf5ff', color: '#7e22ce', border: '1px solid #e9d5ff', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <Database size={11} /> DB ROW {iss.row_id ? `#${iss.row_id}` : iss.file_path?.match(/\[ID:\s*(\d+)\]/)?.[1] ? `#${iss.file_path.match(/\[ID:\s*(\d+)\]/)?.[1]}` : ''}
                                  </span>
                                ) : isPost ? (
                                  <span className="webcare-type-badge-post">{(iss.post_type || 'post').toUpperCase()} {iss.post_id ? `#${iss.post_id}` : ''}</span>
                                ) : isUpdate ? (
                                  <span className={
                                    iss.type.includes('core') ? 'webcare-type-badge-core' :
                                    iss.type.includes('theme') ? 'webcare-type-badge-theme' : 'webcare-type-badge-plugin'
                                  }>
                                    {iss.type.includes('core') ? 'CORE' : iss.type.includes('theme') ? 'THEME' : 'PLUGIN'}
                                  </span>
                                ) : isUser ? (
                                  <span className="webcare-type-badge-user" style={{ background: '#eff6ff', color: '#2563eb', border: '1px solid #bfdbfe', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <User size={11} /> USER {iss.user_id ? `#${iss.user_id}` : ''}
                                  </span>
                                ) : isCron ? (
                                  <span className="webcare-type-badge-cron" style={{ background: '#fffbeb', color: '#b45309', border: '1px solid #fde68a', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <Clock size={11} /> CRON HOOK
                                  </span>
                                ) : isHook ? (
                                  <span className="webcare-type-badge-hook" style={{ background: '#f5f3ff', color: '#7c3aed', border: '1px solid #ddd6fe', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <Terminal size={11} /> RUNTIME HOOK
                                  </span>
                                ) : (iss.is_server_config || iss.is_network || iss.engine === 'ip-detection' || iss.engine === 'waf-status' || iss.file_path?.startsWith('server:') || iss.type === 'reverse_proxy_misconfigured') ? (
                                  <span className="webcare-type-badge-network" style={{ background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <Globe size={11} /> NETWORK CONFIG
                                  </span>
                                ) : (
                                  <span className="webcare-type-badge-file">FILE</span>
                                )}
                                {iss.cves && iss.cves.length > 0 && (
                                  <button
                                    type="button"
                                    className="webcare-cve-pill-btn"
                                    onClick={() => setCveModal({ isOpen: true, issue: iss })}
                                    title={`View ${iss.cves.length} documented CVE security reference(s)`}
                                  >
                                    <ShieldAlert size={11} />
                                    <span>{iss.cves.length} CVE{iss.cves.length > 1 ? 's' : ''}</span>
                                    <span className="webcare-cvss-score-pill">
                                      {iss.cves[0]?.cvss ? `CVSS ${iss.cves[0].cvss}` : 'VULN'}
                                    </span>
                                  </button>
                                )}
                              </div>
                            </td>
                            <td>
                              {isPost ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <FileText size={13} color="#6366f1" />
                                    <span>{iss.post_title || iss.file_path}</span>
                                  </div>
                                  {iss.view_url && (
                                    <a href={iss.view_url} target="_blank" rel="noopener noreferrer" className="webcare-link-subtle">
                                      <Globe size={11} color="#0ea5e9" />
                                      <span>{iss.view_url}</span>
                                      <ArrowUpRight size={11} />
                                    </a>
                                  )}
                                </div>
                              ) : isUpdate ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <Layers size={13} color="#0284c7" />
                                    <span>{iss.component_name || iss.file_path}</span>
                                  </div>
                                  <div style={{ fontSize: '11px', color: '#64748b' }}>
                                    Installed: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{iss.installed_version || 'v?'}</strong>
                                    {iss.latest_version && <span> &bull; Latest: <strong style={{ color: '#16a34a' }}>{iss.latest_version}</strong></span>}
                                  </div>
                                </div>
                              ) : isDbTable ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <Database size={13} color="#7e22ce" />
                                    <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{iss.table_name || (iss.file_path ? iss.file_path.split('.')[0] : 'Table')}</span>
                                    {iss.is_log_table && <span style={{ fontSize: '10px', color: '#c2410c', background: '#ffedd5', border: '1px solid #fed7aa', padding: '1px 5px', borderRadius: '4px', fontWeight: 700 }}>LOG</span>}
                                  </div>
                                  <div style={{ fontSize: '11px', color: '#64748b' }}>
                                    <span>Col: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{iss.column_name || (iss.file_path?.includes('.') ? iss.file_path.split('.')[1]?.split(' ')[0] : '')}</strong></span>
                                    {(iss.row_id || iss.file_path?.includes('[ID:')) && <span style={{ marginLeft: '6px' }}>Row: #{iss.row_id || iss.file_path.match(/\[ID:\s*(\d+)\]/)?.[1] || ''}</span>}
                                  </div>
                                </div>
                              ) : isUser ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <User size={13} color="#2563eb" />
                                    <span>{iss.user_login ? `${iss.user_login} (ID #${iss.user_id || '?'})` : iss.display_title || iss.file_path || 'User Account'}</span>
                                  </div>
                                  {iss.user_roles && (
                                    <div style={{ fontSize: '11px', color: '#64748b' }}>
                                      Role: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{iss.user_roles}</strong>
                                    </div>
                                  )}
                                </div>
                              ) : isCron ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <Clock size={13} color="#b45309" />
                                    <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{iss.cron_hook || iss.file_path?.replace(/^cron:/, '') || 'Cron Task'}</span>
                                  </div>
                                  {iss.cron_schedule && (
                                    <div style={{ fontSize: '11px', color: '#64748b' }}>
                                      Schedule: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{iss.cron_schedule}</strong>
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <div className="webcare-path-pill">
                                  <span>{iss.file_path}</span>
                                  {iss.line_number ? (
                                    <span style={{ color: '#0284c7', fontWeight: 700, fontSize: '11px' }}>
                                      :{iss.line_number}
                                    </span>
                                  ) : null}
                                  {iss.file_path && (
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        if (navigator.clipboard) {
                                          navigator.clipboard.writeText(iss.file_path);
                                          setCopiedIssuePath(iss.file_path);
                                          setTimeout(() => setCopiedIssuePath(null), 2000);
                                        }
                                      }}
                                      style={{ background: 'none', border: 'none', padding: '2px', cursor: 'pointer', color: copiedIssuePath === iss.file_path ? '#16a34a' : '#64748b', display: 'inline-flex', alignItems: 'center' }}
                                      title="Copy file path"
                                    >
                                      {copiedIssuePath === iss.file_path ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                                    </button>
                                  )}
                                </div>
                              )}
                            </td>
                            <td style={{ fontSize: '13px' }}>{iss.description}</td>
                            <td>
                              <span className={`webcare-status-chip webcare-status-chip-${iss.status}`}>
                                {iss.status === 'open' && <span className="webcare-pulse-dot webcare-pulse-dot-red" />}
                                {iss.status === 'quarantined' && <Archive size={11} />}
                                {iss.status === 'repaired' && <Check size={11} />}
                                <span>{iss.status === 'repaired' ? 'SOLVED' : iss.status}</span>
                              </span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                {iss.status === 'repaired' ? (
                                  <span
                                    style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '5px',
                                      background: '#ecfdf5',
                                      color: '#059669',
                                      border: '1px solid #a7f3d0',
                                      padding: '4px 10px',
                                      borderRadius: '6px',
                                      fontSize: '11px',
                                      fontWeight: 700,
                                    }}
                                  >
                                    <CheckCircle2 size={12} color="#10b981" />
                                    <span>SOLVED &amp; Restored</span>
                                  </span>
                                ) : isComment ? (
                                  <Fragment>
                                    {iss.edit_url && (
                                      <a href={iss.edit_url} target="_blank" rel="noopener noreferrer" className="webcare-btn" style={{ padding: '4px 8px', fontSize: '11px' }}>
                                        <Edit3 size={11} /> Edit
                                      </a>
                                    )}
                                    <button type="button" className="webcare-btn" style={{ background: '#fffbeb', color: '#b45309', border: '1px solid #fde68a', fontSize: '11px', padding: '4px 8px' }} onClick={() => handleModerateComment(iss, 'trash')}>
                                      <Trash2 size={11} /> Trash
                                    </button>
                                    <button type="button" className="webcare-btn" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 8px' }} onClick={() => handleModerateComment(iss, 'delete')}>
                                      <XCircle size={11} /> Delete
                                    </button>
                                  </Fragment>
                                ) : isDbTable ? (
                                  <Fragment>
                                    <button type="button" className="webcare-btn" style={{ background: '#f5f3ff', color: '#6d28d9', border: '1px solid #ddd6fe', fontSize: '11px', padding: '4px 8px' }} onClick={() => handleOpenDbInspector(iss)}>
                                      <FileText size={11} /> Inspect Row
                                    </button>
                                    <button type="button" className="webcare-btn" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 8px' }} onClick={() => handleRemediateDbRow(iss, 'delete_row')}>
                                      <Trash2 size={11} /> Delete Row
                                    </button>
                                  </Fragment>
                                ) : isPost ? (
                                  <Fragment>
                                    {iss.edit_url && (
                                      <a href={iss.edit_url} target="_blank" rel="noopener noreferrer" className="webcare-btn webcare-btn-edit-post">
                                        <Edit3 size={12} /> Edit
                                      </a>
                                    )}
                                    <button type="button" className="webcare-btn webcare-btn-view-preview" onClick={() => handleOpenPostViewer(iss)}>
                                      <FileText size={12} /> Inspect
                                    </button>
                                  </Fragment>
                                ) : isUpdate ? (
                                  <Fragment>
                                    {iss.cves && iss.cves.length > 0 && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#fee2e2', color: '#991b1b', border: '1px solid #fca5a5', padding: '4px 8px', fontSize: '11px' }}
                                        onClick={() => setCveModal({ isOpen: true, issue: iss })}
                                      >
                                        <ShieldAlert size={12} /> CVEs
                                      </button>
                                    )}
                                    {iss.update_url && (
                                      <a
                                        href={iss.update_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="webcare-btn-update-software"
                                        style={{ padding: '4px 10px', fontSize: '11px' }}
                                      >
                                        <RefreshCw size={11} /> Update Now <ArrowUpRight size={10} />
                                      </a>
                                    )}
                                  </Fragment>
                                ) : isUser ? (
                                  <Fragment>
                                    {iss.edit_url && (
                                      <a href={iss.edit_url} target="_blank" rel="noopener noreferrer" className="webcare-btn" style={{ padding: '4px 8px', fontSize: '11px' }}>
                                        <Edit3 size={11} /> Edit User
                                      </a>
                                    )}
                                    {(iss.type === 'user_missing_capabilities' || iss.type?.includes('missing_cap')) && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '11px', padding: '4px 9px', fontWeight: 600 }}
                                        onClick={() => handleRemediateUser(iss, 'assign_default_role')}
                                        title="Repair user capabilities to standard role definition"
                                      >
                                        <RotateCcw size={12} /> Repair Role
                                      </button>
                                    )}
                                    {(iss.type === 'suspicious_user_capabilities' || iss.type === 'injected_user_capabilities' || iss.type?.includes('injected_cap')) && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 9px', fontWeight: 600 }}
                                        onClick={() => handleRemediateUser(iss, 'strip_capabilities')}
                                        title="Strip unauthorized injected capabilities"
                                      >
                                        <ShieldAlert size={12} /> Strip Privileges
                                      </button>
                                    )}
                                    {(iss.type === 'ghost_admin_user' || iss.type === 'rogue_admin_user' || iss.type === 'rogue_admin') && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 9px', fontWeight: 600 }}
                                        onClick={() => handleRemediateUser(iss, 'delete_user')}
                                        title="Safely delete rogue user account with automated snapshot backup"
                                      >
                                        <Trash2 size={12} /> Delete Account
                                      </button>
                                    )}
                                  </Fragment>
                                ) : isCron ? (
                                  <Fragment>
                                    <button
                                      type="button"
                                      className="webcare-btn"
                                      style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 9px', fontWeight: 600 }}
                                      onClick={() => handleDeleteCronHook(iss)}
                                      title="Delete rogue or suspicious scheduled cron task"
                                    >
                                      <Trash2 size={12} /> Delete Cron Task
                                    </button>
                                  </Fragment>
                                ) : isHook && !isPhysicalFile ? (
                                  <Fragment>
                                    <button
                                      type="button"
                                      className="webcare-btn"
                                      style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5', fontSize: '11px', padding: '4px 9px', fontWeight: 600 }}
                                      onClick={() => handleDeleteCronHook(iss)}
                                      title="Remove suspicious hook callback"
                                    >
                                      <Trash2 size={12} /> Remove Hook
                                    </button>
                                  </Fragment>
                                ) : (
                                  <Fragment>
                                    {/* Visual Code Diff (FIM) Button */}
                                    {isFimEligible && (
                                      <button
                                        type="button"
                                        className="webcare-btn-diff"
                                        style={{ padding: '4px 9px', fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => {
                                          setVisualDiffModal({
                                            isOpen: true,
                                            filePath: iss.file_path,
                                            issueId: iss.id,
                                          });
                                        }}
                                        title="Compare this file against official WordPress.org release code diff"
                                      >
                                        <FileCode size={12} /> Code Diff (FIM)
                                      </button>
                                    )}

                                    {/* Auto-Cure Plugin */}
                                    {isPlugin && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleAutoCurePlugin(iss)}
                                        title="Restore bit-for-bit clean copy from official WordPress.org release"
                                      >
                                        <RotateCcw size={12} /> Repair Plugin
                                      </button>
                                    )}

                                    {/* Auto-Cure Core */}
                                    {isCore && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleAutoCureCore(iss)}
                                        title="Restore bit-for-bit clean copy from official WordPress.org core release"
                                      >
                                        <RotateCcw size={12} /> Repair Core
                                      </button>
                                    )}

                                    {/* Auto-Cure Theme */}
                                    {isTheme && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleAutoCureTheme(iss)}
                                        title="Restore bit-for-bit clean copy from official WordPress.org release"
                                      >
                                        <RotateCcw size={12} /> Repair Theme
                                      </button>
                                    )}

                                    {/* Auto-Cure Webshell */}
                                    {isInjectedWrapper && !isCore && !isPlugin && !isTheme && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#fdf4ff', color: '#9333ea', border: '1px solid #f0abfc', fontSize: '11px', padding: '4px 9px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleAutoCureStrip(iss)}
                                        title="Strip prepended malicious eval/base64 wrapper while keeping legitimate file code intact"
                                      >
                                        <Sparkles size={12} /> Strip Webshell
                                      </button>
                                    )}

                                    {/* Unsafe Permissions 1-Click Fix Action */}
                                    {iss.type === 'wp_debug_enabled' && iss.status === 'open' && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #6ee7b7', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        disabled={disablingWpDebug}
                                        onClick={() => handleDisableWpDebug(iss)}
                                        title="1-Click Fix: Intelligently comment out debugging and disable WP_DEBUG in wp-config.php"
                                      >
                                        <ShieldCheck size={12} color="#059669" /> {disablingWpDebug ? 'Disabling...' : '1-Click Fix: Disable Debugging'}
                                      </button>
                                    )}

                                    {iss.type === 'unsafe_permissions' && iss.status === 'open' && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #6ee7b7', fontSize: '11px', padding: '4px 9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                        onClick={() => handleFixPermissions(iss)}
                                        title="1-Click Fix: Harden permissions immediately to safe 0644 (or 0755 for directory)"
                                      >
                                        <ShieldCheck size={12} color="#059669" /> Fix Permissions
                                      </button>
                                    )}

                                    {/* View File */}
                                    {isPhysicalFile && iss.can_view !== false && (
                                      <button
                                        type="button"
                                        className="webcare-btn-view-file-alt"
                                        style={{ padding: '4px 9px', fontSize: '11px' }}
                                        onClick={() => handleOpenFileViewer(iss)}
                                        title="Inspect file contents"
                                      >
                                        <Eye size={12} /> View File
                                      </button>
                                    )}

                                    {/* Quarantine */}
                                    {canQuarantineIssue(iss) && (
                                      <button
                                        type="button"
                                        className="webcare-btn-quarantine-alt"
                                        style={{ padding: '4px 9px', fontSize: '11px' }}
                                        onClick={() => handleQuarantine(iss)}
                                        title="Safely isolate in quarantine"
                                      >
                                        <Archive size={12} /> Quarantine
                                      </button>
                                    )}

                                    {/* Delete Rogue / Unknown File */}
                                    {isUnknownFile && isPhysicalFile && iss.status === 'open' && (
                                      <button
                                        type="button"
                                        className="webcare-btn"
                                        style={{
                                          background: '#fef2f2',
                                          color: '#dc2626',
                                          border: '1px solid #fca5a5',
                                          fontSize: '11px',
                                          padding: '4px 9px',
                                          fontWeight: 600,
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '4px',
                                        }}
                                        onClick={() => handleDeleteRogueFile(iss)}
                                        title="Permanently delete this unrecognized rogue file from server"
                                      >
                                        <Trash2 size={12} /> Delete File
                                      </button>
                                    )}
                                  </Fragment>
                                )}
                              </div>
                            </td>
                          </tr>

                          {/* Expanded Detail View */}
                          {isExpanded && (
                            <tr key={`targeted-expanded-${iss.id}`} style={{ background: 'var(--webcare-bg-surface, #f8fafc)' }}>
                              <td></td>
                              <td colSpan={6} style={{ padding: '18px 24px' }}>
                                <SafeErrorBoundary fallbackTitle="Targeted Finding Details Error">
                                <div style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', lineHeight: 1.6, marginBottom: '10px' }}>
                                  <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Description:</strong> {iss.description}
                                </div>

                                {iss.evidence && (
                                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '10px', fontFamily: 'monospace', background: '#f1f5f9', padding: '6px 12px', borderRadius: '6px' }}>
                                    <strong>Signature / Vector Rule:</strong> {iss.evidence}
                                  </div>
                                )}

                                {/* Database Record Forensics & Quarantine Card */}
                                {isDbTable && (
                                  <div style={{ background: 'var(--webcare-bg-card, #ffffff)', border: '1px solid #e9d5ff', borderRadius: '10px', padding: '16px', marginTop: '12px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Database size={15} color="#7e22ce" />
                                        <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                                          Database Record: {iss.table_name || iss.file_path.split('.')[0]} {iss.row_id ? `[Row #${iss.row_id}]` : ''}
                                        </strong>
                                      </div>
                                      <div style={{ display: 'flex', gap: '8px' }}>
                                        <button type="button" className="webcare-btn" style={{ background: '#f5f3ff', color: '#6d28d9', border: '1px solid #ddd6fe', fontSize: '11px', padding: '4px 9px' }} onClick={() => handleOpenDbInspector(iss)}>
                                          <FileText size={12} /> Inspect Full Row Data
                                        </button>
                                        <button type="button" className="webcare-btn" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '11px', padding: '4px 9px' }} onClick={() => handleRemediateDbRow(iss, 'delete_row')}>
                                          <Trash2 size={12} /> Delete Row (Auto-Backup)
                                        </button>
                                      </div>
                                    </div>
                                    {iss.code_snippet && (
                                      <pre style={{ background: '#fff1f2', color: '#991b1b', border: '1px solid #fecdd3', padding: '10px', borderRadius: '6px', fontSize: '12px', margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: '180px', overflowY: 'auto' }}>
                                        {iss.code_snippet}
                                      </pre>
                                    )}

                                    {/* Full MySQL Database Row Inspection Table */}
                                    {(() => {
                                      const parsed = parseDbFinding(iss);
                                      const activeRow = iss.db_row || dbRowCache[iss.id]?.row;
                                      const isLoading = dbRowCache[iss.id]?.loading;
                                      const loadErr = dbRowCache[iss.id]?.error;

                                      return (
                                        <div style={{ marginTop: '14px', borderTop: '1px solid #f3e8ff', paddingTop: '12px' }}>
                                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                              <Database size={14} color="#7e22ce" />
                                              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                                Complete Database Row Record {activeRow ? `(${Object.keys(activeRow).length} Columns)` : ''}
                                              </span>
                                            </div>
                                            <button
                                              type="button"
                                              className="webcare-btn"
                                              style={{ fontSize: '11px', padding: '3px 8px', background: '#f5f3ff', color: '#6d28d9', border: '1px solid #ddd6fe', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                              onClick={() => loadDbRow(iss)}
                                            >
                                              <RotateCcw size={11} /> {activeRow ? 'Refresh Row' : 'Load Full Row'}
                                            </button>
                                          </div>
                                          {isLoading && (
                                            <div style={{ padding: '12px', display: 'flex', alignItems: 'center', gap: '8px', color: '#64748b', fontSize: '12px', background: '#faf5ff', borderRadius: '6px' }}>
                                              <Loader2 size={14} className="webcare-spin" color="#7e22ce" /> Querying complete record columns from MySQL database...
                                            </div>
                                          )}
                                          {loadErr && !activeRow && (
                                            <div style={{ padding: '8px 10px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '6px', color: '#dc2626', fontSize: '12px' }}>
                                              {loadErr}
                                            </div>
                                          )}
                                          {!activeRow && !isLoading && !loadErr && (
                                            <div style={{ padding: '10px 12px', background: '#f8fafc', border: '1px dashed #cbd5e1', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                              <span style={{ fontSize: '12px', color: '#64748b' }}>Full row columns not yet loaded for record #{parsed.rowId || iss.row_id || 'N/A'}.</span>
                                              <button type="button" className="webcare-btn" style={{ fontSize: '11px', padding: '3px 8px', background: '#7e22ce', color: '#ffffff', border: 'none', fontWeight: 600 }} onClick={() => loadDbRow(iss)}>
                                                <Database size={11} /> Inspect Full Row
                                              </button>
                                            </div>
                                          )}
                                          {activeRow && (
                                            <div style={{ border: '1px solid #e2e8f0', borderRadius: '8px', overflow: 'hidden', background: '#ffffff' }}>
                                              <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
                                                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                                                  <thead>
                                                    <tr style={{ background: '#faf5ff', borderBottom: '1px solid #e9d5ff', textAlign: 'left', position: 'sticky', top: 0, zIndex: 1 }}>
                                                      <th style={{ padding: '8px 10px', width: '200px', color: '#6b21a8', fontWeight: 700 }}>Column Name</th>
                                                      <th style={{ padding: '8px 10px', color: '#6b21a8', fontWeight: 700 }}>Stored Database Value</th>
                                                    </tr>
                                                  </thead>
                                                  <tbody>
                                                    {Object.entries(activeRow).map(([col, val], idx) => {
                                                      const isFlagged = col === parsed.columnName || col === iss.column_name;
                                                      const isPk = col === (iss.db_primary_key || 'id');
                                                      const strVal = val === null ? 'NULL' : String(val);
                                                      return (
                                                        <tr key={col} style={{ borderBottom: idx < Object.keys(activeRow).length - 1 ? '1px solid #f1f5f9' : 'none', background: isFlagged ? '#fff1f2' : idx % 2 === 0 ? '#ffffff' : '#fcfcfd' }}>
                                                          <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                              <code style={{ fontWeight: 700, color: isFlagged ? '#e11d48' : 'var(--webcare-text-primary, #0f172a)' }}>{col}</code>
                                                              {isPk && <span style={{ fontSize: '9px', background: '#e0e7ff', color: '#4338ca', padding: '1px 4px', borderRadius: '4px', fontWeight: 700 }}>PK</span>}
                                                              {isFlagged && <span style={{ fontSize: '9px', background: '#fee2e2', color: '#b91c1c', padding: '1px 4px', borderRadius: '4px', fontWeight: 800 }}>FLAGGED</span>}
                                                            </div>
                                                          </td>
                                                          <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
                                                            <div style={{ fontFamily: 'monospace', color: val === null ? '#94a3b8' : isFlagged ? '#991b1b' : '#334155', wordBreak: 'break-all', whiteSpace: 'pre-wrap', maxHeight: '140px', overflowY: 'auto' }}>
                                                              {strVal}
                                                            </div>
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
                                    })()}
                                  </div>
                                )}

                                {/* Filesystem Forensics Card for Unsafe Permissions & Rogue Files */}
                                {(iss.type === 'unsafe_permissions' || iss.type === 'wp_debug_enabled' || (Boolean(iss.file_path && iss.file_path.endsWith('wp-config.php')) && (iss.type?.includes('debug') || iss.description?.includes('WP_DEBUG'))) || Boolean(iss.fs_forensics)) && (
                                  <FilesystemForensicsCard
                                    issue={iss}
                                    onFixPermissions={handleFixPermissions}
                                    onDisableWpDebug={handleDisableWpDebug}
                                    onOpenFileViewer={handleOpenFileViewer}
                                    onQuarantine={handleQuarantine}
                                    onDeleteFile={handleDeleteRogueFile}
                                    onAutoCure={handleAutoCureIssue}
                                  />
                                )}

                                {/* Malicious Code Snippet Box with Auto-Cure Actions (Physical Files Only, Suppressed for Unsafe Permissions & Empty Snippets) */}
                                {isPhysicalFile && iss.type !== 'unsafe_permissions' && (Boolean(iss.code_snippet) || isInjectedWrapper || isUnknownFile) && (
                                  <div style={{ background: 'var(--webcare-bg-card, #ffffff)', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '16px', marginTop: '12px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                                      <div style={{ fontSize: '12px', color: '#475569', fontWeight: 700 }}>
                                        Flagged Code Inspection {iss.line_number ? `(Line #${iss.line_number})` : ''}:
                                      </div>
                                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                        {iss.status === 'repaired' ? (
                                          <span
                                            style={{
                                              display: 'inline-flex',
                                              alignItems: 'center',
                                              gap: '5px',
                                              background: '#ecfdf5',
                                              color: '#059669',
                                              border: '1px solid #a7f3d0',
                                              padding: '4px 10px',
                                              borderRadius: '6px',
                                              fontSize: '12px',
                                              fontWeight: 700,
                                            }}
                                          >
                                            <CheckCircle2 size={13} color="#10b981" />
                                            <span>Issue Solved & Restored</span>
                                          </span>
                                        ) : (
                                          <Fragment>
                                            {isPlugin && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleAutoCurePlugin(iss)}
                                                title="Restore bit-for-bit clean copy from official WordPress.org release"
                                              >
                                                <RotateCcw size={13} /> Auto-Cure: Restore WP.org File
                                              </button>
                                            )}
                                            {isCore && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleAutoCureCore(iss)}
                                                title="Restore bit-for-bit clean copy from official WordPress.org core release"
                                              >
                                                <RotateCcw size={13} /> Auto-Cure: Restore WP.org Core File
                                              </button>
                                            )}
                                            {isTheme && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #86efac', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleAutoCureTheme(iss)}
                                                title="Restore bit-for-bit clean copy from official WordPress.org release"
                                              >
                                                <RotateCcw size={13} /> Auto-Cure: Restore WP.org Theme File
                                              </button>
                                            )}
                                            {isInjectedWrapper && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#fdf4ff', color: '#9333ea', border: '1px solid #f0abfc', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleAutoCureStrip(iss)}
                                                title="Strip prepended malicious eval/base64 wrapper while keeping legitimate file code intact"
                                              >
                                                <Sparkles size={13} /> Auto-Cure: Strip Webshell
                                              </button>
                                            )}
                                            {isUnknownFile && iss.status === 'open' && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleDeleteRogueFile(iss)}
                                                title="Permanently remove unknown/untracked file from filesystem (backed up to WebCare Vault for 14 days)"
                                              >
                                                <Trash2 size={13} /> Delete Rogue File
                                              </button>
                                            )}
                                            {canQuarantineIssue(iss) && (
                                              <button
                                                type="button"
                                                className="webcare-btn"
                                                style={{ background: '#fff7ed', color: '#c2410c', border: '1px solid #fed7aa', fontSize: '12px', padding: '5px 12px' }}
                                                onClick={() => handleQuarantine(iss)}
                                                title="Move suspicious file to secure encrypted quarantine storage"
                                              >
                                                <Archive size={13} /> Quarantine File
                                              </button>
                                            )}
                                          </Fragment>
                                        )}
                                        {isFimEligible && (
                                          <button
                                            type="button"
                                            className="webcare-btn-diff"
                                            onClick={() => {
                                              setVisualDiffModal({
                                                isOpen: true,
                                                filePath: iss.file_path,
                                                issueId: iss.id,
                                              });
                                            }}
                                          >
                                            <FileCode size={13} /> Visual Code Diff (FIM)
                                          </button>
                                        )}
                                        {iss.can_view !== false && (
                                          <button
                                            type="button"
                                            className="webcare-btn webcare-btn-view-file"
                                            onClick={() => handleOpenFileViewer(iss)}
                                          >
                                            <Eye size={13} /> Open Full Code Viewer & Jump to Line #{iss.line_number || 1}
                                          </button>
                                        )}
                                      </div>
                                    </div>

                                    {iss.code_snippet ? (
                                      <pre style={{ background: 'var(--webcare-bg-code, #090d16)', color: 'var(--webcare-text-code, #38bdf8)', padding: '14px', borderRadius: '8px', overflowX: 'auto', fontSize: '12px', margin: 0, fontFamily: 'monospace' }}>
                                        {iss.code_snippet}
                                      </pre>
                                    ) : (
                                      <div style={{ fontSize: '12px', color: '#94a3b8', fontStyle: 'italic', padding: '8px 0' }}>
                                        No isolated snippet available. Click "View File"{isFimEligible ? ' or "Visual Code Diff (FIM)"' : ''} above to inspect the file.
                                      </div>
                                    )}
                                  </div>
                                )}
                                </SafeErrorBoundary>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </Fragment>
            )}
          </div>
          )}
        </div>
      )}

      {/* VIEW 3: SCAN LOGS & HISTORY */}
      {navTab === 'logs' && (
        <ScanLogsPage
          apiRequest={apiRequest}
          scanHistory={scanHistory}
          historyLoading={historyLoading}
          loadScanHistory={loadScanHistory}
          handleClearAllScanHistory={handleClearAllScanHistory}
          selectedScanDetail={selectedScanDetail}
          setSelectedScanDetail={setSelectedScanDetail}
          loadScanLogDetail={loadScanLogDetail}
          scanning={scanning}
          targetedScanning={targetedScanning}
          handleNavTabChange={handleNavTabChange}
          setVisualDiffModal={setVisualDiffModal}
          handleOpenFileViewer={handleOpenFileViewer}
          handleOpenChangelog={handleOpenChangelog}
          canQuarantineIssue={canQuarantineIssue}
          handleQuarantine={handleQuarantine}
          handleRemediateUser={handleRemediateUser}
          handleRemediateDbRow={handleRemediateDbRow}
          handleDeleteCronHook={handleDeleteCronHook}
          handleModerateComment={handleModerateComment}
          handleFixPermissions={handleFixPermissions}
          handleDisableWpDebug={handleDisableWpDebug}
          handleOpenDbInspector={handleOpenDbInspector}
          handleOpenPostViewer={handleOpenPostViewer}
          setWhitelistModal={setWhitelistModal}
          setCveModal={setCveModal}
          handleUpdateIssue={handleUpdateIssue}
          dbRowCache={dbRowCache}
          loadDbRow={loadDbRow}
          copiedIssuePath={copiedIssuePath}
          setCopiedIssuePath={setCopiedIssuePath}
        />
      )}

      {/* VIEW: SYSTEM FORENSICS & DEEP DIAGNOSTICS */}
      {navTab === 'forensics' && (
        <ForensicsPage
          apiRequest={apiRequest}
          onNavigateToDashboard={() => handleNavTabChange('dashboard')}
          onNavigateToSupport={() => handleNavTabChange('about')}
          scannedFiles={scannedFiles}
          initialSubTab={(() => {
            const valid = ['persistence', 'watchdog', 'baseline', 'files', 'attack_chain', 'attack-chains', 'correlation', 'whitelist', 'allowlist', 'transactions', 'self_defense', 'self-defense', 'preloaders', 'snapshots'];
            if (initialForensicsSubTab && valid.includes(initialForensicsSubTab as any)) return initialForensicsSubTab;
            const urlParams = new URLSearchParams(window.location.search);
            const section = urlParams.get('section');
            if (section && valid.includes(section as any)) return section as any;
            const tab = urlParams.get('tab');
            const subtab = urlParams.get('subtab');
            if (tab && valid.includes(tab as any)) return tab as any;
            if (subtab && valid.includes(subtab as any)) return subtab as any;
            return 'persistence';
          })()}
          initialNestedSubTab={initialWatchdogSubTab || ((new URLSearchParams(window.location.search).get('section') as any) || (new URLSearchParams(window.location.search).get('subtab') as any) || 'watchdog')}
          onSubTabChange={(sub, nested) => {
            setInitialForensicsSubTab(sub);
            if (nested) setInitialWatchdogSubTab(nested);
            try {
              const url = new URL(window.location.href);
              url.searchParams.set('tab', 'diagnostics');
              url.searchParams.set('section', sub);
              url.searchParams.delete('subtab');
              window.history.pushState({ tab: 'diagnostics', section: sub }, '', url.toString());
            } catch (e) {}
          }}
          onOpenFileViewer={handleOpenFileViewer}
          onRefreshScanData={loadLatestScan}
        />
      )}

      {/* VIEW 4: WebCare UNIFIED VAULT SUITE (QUARANTINE, DATABASE, ROLLBACK, SECRETS) */}
      {(navTab === 'vault' || navTab === 'quarantine' || navTab === 'backup') && (
        <WebCareVaultPage
          apiRequest={apiRequest}
          initialTab={
            navTab === 'quarantine'
              ? 'quarantine'
              : navTab === 'backup'
              ? 'database'
              : ((new URLSearchParams(window.location.search).get('tab') as any) || 'quarantine')
          }
          onNavigateToDashboard={() => handleNavTabChange('dashboard')}
        />
      )}

      {/* VIEW 5: SERVER & HOST INFRASTRUCTURE TELEMETRY */}
      {navTab === 'server' && (
        <SafeErrorBoundary fallbackTitle="Server Telemetry Page Error">
          <ServerTelemetryPage
            apiRequest={apiRequest}
            onNavigateToDashboard={() => handleNavTabChange('dashboard')}
            onNavigateToFirewall={(subTab) => handleNavTabChange('firewall', subTab)}
            onNavigateToSettings={(subTab) => handleNavTabChange('settings', subTab)}
          />
        </SafeErrorBoundary>
      )}

      {/* 6. Vulnerabilities & Updates Dedicated Sub-Page */}
      {navTab === 'vulnerabilities' && (
        <VulnerabilitiesPage
          apiRequest={apiRequest}
          onInspectCve={(cveList, componentName, version, updateUrl) => {
            setCveModal({
              isOpen: true,
              issue: {
                id: 0,
                scan_id: 0,
                engine: 'wordpress-updates',
                type: 'vulnerable_software',
                severity: 'critical',
                confidence: 100,
                file_path: componentName,
                component_name: componentName,
                installed_version: version,
                update_url: updateUrl,
                description: `${componentName} (v${version}) has ${cveList.length} documented CVE security advisory(s).`,
                status: 'open',
                cves: cveList
              }
            });
          }}
        />
      )}


      {/* 6. Web Application Firewall (WAF Lite) Page */}
      {navTab === 'firewall' && (
        <FirewallPage
          apiRequest={apiRequest}
          onNavigateToDashboard={() => handleNavTabChange('dashboard')}
          onNavigateToWafLogs={() => handleNavTabChange('waf_logs')}
          onNavigateToVpatch={() => handleNavTabChange('firewall', 'vpatch')}
          onNavigateToSettings={(subTab) => handleNavTabChange('settings', subTab)}
          onNavigateToServerTelemetry={() => handleNavTabChange('server')}
          initialSubTab={initialFirewallSubTab || ((new URLSearchParams(window.location.search).get('tab') as any) || 'stream')}
          initialSupplyChainSubTab={initialSupplyChainSubTab || ((new URLSearchParams(window.location.search).get('subtab') as any) || 'sbom')}
          initialBehavioralSubTab={initialBehavioralSubTab || ((new URLSearchParams(window.location.search).get('subtab') as any) || 'learning')}
          initialAiDefenseSubTab={initialAiDefenseSubTab || ((new URLSearchParams(window.location.search).get('subtab') as any) || 'ghost')}
          onSubTabChange={(sub, nested) => handleNavTabChange('firewall', sub, nested)}
        />
      )}

      {/* 6b. Dedicated WAF Incident Logs & Forensics Page */}
      {navTab === 'waf_logs' && (
        <SafeErrorBoundary fallbackTitle="WAF Incident Logs Page Error">
          <WafLogsPage
            apiRequest={apiRequest}
            onNavigateToFirewallRules={() => handleNavTabChange('firewall', 'rules')}
            onNavigateToDashboard={() => handleNavTabChange('dashboard')}
            onNavigateToFirewall={(subTab) => handleNavTabChange('firewall', subTab)}
          />
        </SafeErrorBoundary>
      )}

      {/* 6c. Dedicated Virtual Patching & 0-Day Studio Page */}
      {navTab === 'vpatch' && (
        <SafeErrorBoundary fallbackTitle="Virtual Patching Page Error">
          <VirtualPatchPage
            apiRequest={apiRequest}
            onNavigateToFirewall={(subTab) => handleNavTabChange('firewall', subTab)}
            onNavigateToWafLogs={() => handleNavTabChange('waf_logs')}
            onNavigateToDashboard={() => handleNavTabChange('dashboard')}
          />
        </SafeErrorBoundary>
      )}

      {/* 7. File Integrity Monitoring (FIM) & Code Diff Page */}
      {navTab === 'fim' && (
        <SafeErrorBoundary fallbackTitle="File Integrity (FIM) Page Error">
          <FileIntegrityPage
            apiRequest={apiRequest}
            initialFilePath={initialFimFile}
            initialSubTab={((new URLSearchParams(window.location.search).get('tab') as any) === 'permissions' ? 'permissions' : 'fim')}
            onSubTabChange={(sub) => handleNavTabChange('fim', sub)}
            onNavigateToDashboard={() => handleNavTabChange('dashboard')}
          />
        </SafeErrorBoundary>
      )}

      {/* 8. Multi-Factor Authentication (2FA) & Login Security Page */}
      {navTab === 'auth' && (
        <SafeErrorBoundary fallbackTitle="Login Security & 2FA Page Error">
          <AuthSecurityPage
            apiRequest={apiRequest}
            onNavigateToDashboard={() => handleNavTabChange('dashboard')}
            initialSubTab={initialAuthSubTab || ((new URLSearchParams(window.location.search).get('tab') as any) || '2fa')}
            initialNestedSubTab={initialIdentitySubTab || ((new URLSearchParams(window.location.search).get('subtab') as any) || 'sessions')}
            onSubTabChange={(sub, nested) => handleNavTabChange('auth', sub, nested)}
          />
        </SafeErrorBoundary>
      )}

      {/* 9. Dedicated Notifications & Alerts Center Page */}
      {navTab === 'notifications' && (
        <SafeErrorBoundary fallbackTitle="Notification Center Error">
          <NotificationsPage
            apiRequest={apiRequest}
            onNavigateToSettings={() => handleNavTabChange('settings', 'webhooks')}
          />
        </SafeErrorBoundary>
      )}

      {/* 9b. Dedicated Activity & Forensic Audit Logs Page */}
      {navTab === 'activity_logs' && (
        <SafeErrorBoundary fallbackTitle="Activity Logs Error">
          <ActivityLogsPage
            apiRequest={apiRequest}
          />
        </SafeErrorBoundary>
      )}

      {/* 10. Settings & Automation Hub Page */}
      {navTab === 'settings' && (
        <SettingsPage
          apiRequest={apiRequest}
          initialSubTab={initialSettingsSubTab}
          onNavigateToDashboard={() => handleNavTabChange('dashboard')}
          onNavigateToNotifications={() => handleNavTabChange('notifications')}
          onNavigateToActivityLogs={() => handleNavTabChange('activity_logs')}
        />
      )}

      {/* 11. About WebCare Pro & Professional Services Tab View */}
      {navTab === 'about' && <AboutServicesPage />}

      {/* =========================================================================
          POPUP MODAL 1: ADVANCED SOURCE CODE INSPECTION MODAL
          ========================================================================= */}
      {fileViewer.isOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setFileViewer((prev) => ({ ...prev, isOpen: false }));
            }
          }}
        >
          <div className="webcare-modal-window">
            {/* Modal Header */}
            <div className="webcare-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
                <div className="webcare-modal-icon-badge">
                  {fileViewer.data?.is_image ? <ImageIcon size={22} color="#38bdf8" /> : <FileCode size={22} color="#38bdf8" />}
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3
                      className="webcare-file-viewer-title"
                      style={{
                        margin: 0,
                        fontSize: '18px',
                        fontWeight: 700,
                        color: '#ffffff',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        letterSpacing: '-0.2px',
                      }}
                    >
                      {fileViewer.data?.filename || fileViewer.filePath.split('/').pop() || 'File Source Inspection'}
                    </h3>
                    {fileViewer.issue && (
                      <span className={`webcare-badge webcare-badge-${fileViewer.issue.severity}`} style={{ fontSize: '11px', textTransform: 'uppercase' }}>
                        {fileViewer.issue.severity} Threat: {fileViewer.issue.type}
                      </span>
                    )}
                    {fileViewer.data?.is_image && (
                      <span className="webcare-badge" style={{
                        background: fileViewer.data.image_security?.threat_warning ? 'rgba(239, 68, 68, 0.2)' : (fileViewer.data.image_security?.magic_bytes_match ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)'),
                        color: fileViewer.data.image_security?.threat_warning ? '#f87171' : (fileViewer.data.image_security?.magic_bytes_match ? '#34d399' : '#fbbf24'),
                        border: `1px solid ${fileViewer.data.image_security?.threat_warning ? 'rgba(239, 68, 68, 0.4)' : (fileViewer.data.image_security?.magic_bytes_match ? 'rgba(16, 185, 129, 0.4)' : 'rgba(245, 158, 11, 0.4)')}`,
                        fontWeight: 700,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        {fileViewer.data.image_security?.threat_warning ? (
                          <>⚠️ Disguised File / Polyglot</>
                        ) : (fileViewer.data.image_security?.magic_bytes_match ? (
                          <>✓ Validated Binary ({fileViewer.data.image_security.detected_type})</>
                        ) : (
                          <>⚠️ Unverified Image Binary</>
                        ))}
                      </span>
                    )}
                    {fileViewer.data?.is_writable ? (
                      <span className="webcare-badge" style={{ background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.4)' }}>
                        Writable
                      </span>
                    ) : (
                      <span className="webcare-badge" style={{ background: 'rgba(100, 116, 139, 0.2)', color: '#94a3b8' }}>
                        Read-Only
                      </span>
                    )}
                    {fileViewer.data?.is_masked && (
                      <span className="webcare-badge" style={{
                        background: 'rgba(16, 185, 129, 0.15)',
                        color: '#10b981',
                        border: '1px solid rgba(16, 185, 129, 0.35)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontWeight: 600
                      }}>
                        <Lock size={11} /> Sensitive Credentials Masked
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'monospace', marginTop: '3px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '520px' }}>
                      {fileViewer.data?.full_path || fileViewer.filePath}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        const targetToCopy = fileViewer.data?.full_path || fileViewer.filePath;
                        if (targetToCopy && navigator.clipboard) {
                          navigator.clipboard.writeText(targetToCopy);
                          setCopiedFilePathModal(true);
                          setTimeout(() => setCopiedFilePathModal(false), 2000);
                        }
                      }}
                      style={{
                        background: copiedFilePathModal ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                        border: `1px solid ${copiedFilePathModal ? 'rgba(16, 185, 129, 0.5)' : 'rgba(255, 255, 255, 0.15)'}`,
                        color: copiedFilePathModal ? '#34d399' : '#cbd5e1',
                        borderRadius: '4px',
                        padding: '1px 6px',
                        fontSize: '11px',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontWeight: 600,
                        transition: 'all 0.15s ease',
                      }}
                      title="Copy full file path to clipboard"
                    >
                      {copiedFilePathModal ? <Check size={11} color="#34d399" /> : <Copy size={11} />}
                      <span>{copiedFilePathModal ? 'Copied Path!' : 'Copy Path'}</span>
                    </button>
                    {(fileViewer.data?.sha256 || fileViewer.issue?.sha256 || fileViewer.issue?.file_sha256) && (
                      <button
                        type="button"
                        onClick={() => {
                          const targetHash = fileViewer.data?.sha256 || fileViewer.issue?.sha256 || fileViewer.issue?.file_sha256;
                          if (targetHash && navigator.clipboard) {
                            navigator.clipboard.writeText(targetHash);
                            setCopiedFileShaModal(true);
                            setTimeout(() => setCopiedFileShaModal(false), 2000);
                          }
                        }}
                        style={{
                          background: copiedFileShaModal ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                          border: `1px solid ${copiedFileShaModal ? 'rgba(16, 185, 129, 0.5)' : 'rgba(255, 255, 255, 0.15)'}`,
                          color: copiedFileShaModal ? '#34d399' : '#38bdf8',
                          borderRadius: '4px',
                          padding: '1px 6px',
                          fontSize: '11px',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontWeight: 600,
                          transition: 'all 0.15s ease',
                        }}
                        title="Copy cryptographic SHA-256 hash to clipboard"
                      >
                        {copiedFileShaModal ? <Check size={11} color="#34d399" /> : <Copy size={11} />}
                        <span>{copiedFileShaModal ? 'Copied SHA-256!' : 'Copy SHA-256'}</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Header Right Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                {/* View Mode Switcher for Images */}
                {fileViewer.data?.is_image && (
                  <div style={{ display: 'inline-flex', background: '#090d16', padding: '3px', borderRadius: '7px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
                    <button
                      type="button"
                      onClick={() => setFileViewer((prev) => ({ ...prev, activeTab: 'image' }))}
                      style={{
                        padding: '4px 10px',
                        fontSize: '11px',
                        fontWeight: 700,
                        borderRadius: '5px',
                        border: 'none',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        background: fileViewer.activeTab === 'image' ? '#4f46e5' : 'transparent',
                        color: fileViewer.activeTab === 'image' ? '#ffffff' : '#94a3b8',
                      }}
                    >
                      <ImageIcon size={12} /> Image Preview
                    </button>
                    <button
                      type="button"
                      onClick={() => setFileViewer((prev) => ({ ...prev, activeTab: 'code' }))}
                      style={{
                        padding: '4px 10px',
                        fontSize: '11px',
                        fontWeight: 700,
                        borderRadius: '5px',
                        border: 'none',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        background: fileViewer.activeTab === 'code' ? '#4f46e5' : 'transparent',
                        color: fileViewer.activeTab === 'code' ? '#ffffff' : '#94a3b8',
                      }}
                    >
                      <FileCode size={12} /> Raw / Hex Source
                    </button>
                  </div>
                )}
                {fileViewer.issue?.line_number && (
                  <button
                    type="button"
                    className="webcare-threat-jump-btn"
                    onClick={handleScrollToThreatLine}
                    title="Center and scroll directly to detected malicious line"
                  >
                    <AlertTriangle size={13} />
                    <span>Jump to Line #{fileViewer.issue.line_number}</span>
                  </button>
                )}

                <button
                  type="button"
                  className="webcare-modal-action-btn"
                  onClick={() => handleAiAnalyzeCode(fileViewer.data?.content, fileViewer.filePath, fileViewer.issue?.type, fileViewer.issue?.line_number)}
                  disabled={!fileViewer.data}
                  title="Analyze suspicious code with AI (ChatGPT, Gemini, Claude)"
                  style={{ background: 'linear-gradient(135deg, #7c3aed, #6366f1)', color: '#fff', border: 'none' }}
                >
                  <Sparkles size={14} />
                  <span>Analyze with AI</span>
                </button>

                {/* Multi-Format Forensic Copy Dropdown */}
                <div style={{ position: 'relative' }} ref={fileCopyDropdownRef}>
                  <button
                    type="button"
                    className="webcare-modal-action-btn"
                    onClick={() => setFileCopyDropdownOpen((prev) => !prev)}
                    disabled={!fileViewer.data}
                    title="Copy full forensic metadata and code in multiple formats"
                    style={{
                      background: fileCopyFeedback ? 'rgba(16, 185, 129, 0.25)' : 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                      color: '#ffffff',
                      border: `1px solid ${fileCopyFeedback ? '#10b981' : '#0284c7'}`,
                      boxShadow: '0 2px 6px rgba(2, 132, 199, 0.3)',
                    }}
                  >
                    {fileCopyFeedback ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                    <span>{fileCopyFeedback || 'Copy...'}</span>
                    <ChevronDown size={13} style={{ marginLeft: '2px', opacity: 0.8 }} />
                  </button>

                  {fileCopyDropdownOpen && (
                    <div
                      style={{
                        position: 'absolute',
                        top: 'calc(100% + 6px)',
                        right: 0,
                        zIndex: 999999,
                        background: '#0f172a',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        borderRadius: '10px',
                        padding: '6px',
                        minWidth: '260px',
                        boxShadow: '0 12px 30px rgba(0, 0, 0, 0.55)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px',
                        animation: 'webcareModalIn 0.15s ease-out',
                      }}
                    >
                      <div
                        style={{
                          fontSize: '10.5px',
                          fontWeight: 800,
                          textTransform: 'uppercase',
                          color: '#94a3b8',
                          padding: '6px 10px 4px 10px',
                          letterSpacing: '0.5px',
                          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                        }}
                      >
                        Copy File &amp; Forensics
                      </div>

                      <button
                        type="button"
                        onClick={() => handleCopyFileBundle('forensic_text')}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '6px',
                          background: 'transparent',
                          border: 'none',
                          color: '#f8fafc',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <Terminal size={14} color="#38bdf8" />
                          <span>Forensic Report (Text + Meta + Code)</span>
                        </span>
                        <span style={{ fontSize: '10.5px', color: '#38bdf8' }}>TXT</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleCopyFileBundle('markdown')}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '6px',
                          background: 'transparent',
                          border: 'none',
                          color: '#f8fafc',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <FileText size={14} color="#c084fc" />
                          <span>Markdown Copy (GitHub Table + Code)</span>
                        </span>
                        <span style={{ fontSize: '10.5px', color: '#c084fc' }}>.MD</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleCopyFileBundle('html')}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '6px',
                          background: 'transparent',
                          border: 'none',
                          color: '#f8fafc',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <Globe size={14} color="#f472b6" />
                          <span>HTML Copy (Styled Standalone Document)</span>
                        </span>
                        <span style={{ fontSize: '10.5px', color: '#f472b6' }}>HTML</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleCopyFileBundle('csv')}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '6px',
                          background: 'transparent',
                          border: 'none',
                          color: '#f8fafc',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <Database size={14} color="#34d399" />
                          <span>CSV Style Copy (Spreadsheet Export)</span>
                        </span>
                        <span style={{ fontSize: '10.5px', color: '#34d399' }}>CSV</span>
                      </button>

                      <div style={{ height: '1px', background: 'rgba(255, 255, 255, 0.08)', margin: '4px 0' }} />

                      <button
                        type="button"
                        onClick={() => handleCopyFileBundle('text')}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '6px',
                          background: 'transparent',
                          border: 'none',
                          color: '#cbd5e1',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = '#1e293b'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <FileCode size={14} color="#94a3b8" />
                          <span>Normal Copy (Raw Code Only)</span>
                        </span>
                        <span style={{ fontSize: '10.5px', color: '#64748b' }}>Code</span>
                      </button>
                    </div>
                  )}
                </div>

                {/* Auto-Cure: Restore Official WP.org for Modified Files */}
                {fileViewer.issue && fileViewer.issue.status === 'open' && (() => {
                  const issue = fileViewer.issue;
                  const filePath = issue.file_path || fileViewer.filePath || '';
                  const isPlugin = Boolean(filePath.includes('/plugins/'));
                  const isCore = Boolean((filePath.includes('/wp-admin/') || filePath.includes('/wp-includes/') || issue.type?.includes('core')) && !filePath.endsWith('wp-config.php') && !filePath.endsWith('.htaccess'));
                  const isTheme = Boolean(filePath.includes('/themes/') || issue.type?.includes('theme'));
                  const isUnknown = Boolean(issue.type?.includes('unknown') || issue.type?.includes('unrecognized'));
                  const isChecksumsUnavailable = issue.type === 'plugin_checksums_unavailable' ||
                    issue.type === 'theme_checksums_unavailable' ||
                    issue.type === 'core_checksums_unavailable' ||
                    (issue.severity === 'info' && Boolean(issue.description?.toLowerCase().includes('checksums unavailable')));
                  const isModified = !isChecksumsUnavailable && Boolean(
                    issue.type?.includes('modified') ||
                    Boolean(issue.type?.includes('missing_core_file')) ||
                    issue.description?.toLowerCase().includes('modified') ||
                    issue.description?.toLowerCase().includes('checksum mismatch') ||
                    issue.description?.toLowerCase().includes('mismatch')
                  );

                  if (isUnknown || isChecksumsUnavailable || (!isCore && !isPlugin && !isTheme)) return null;
                  if (!isModified && !issue.type?.includes('modified')) return null;

                  return (
                    <button
                      type="button"
                      className="webcare-modal-action-btn"
                      style={{
                        background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                        color: '#ffffff',
                        border: '1px solid #047857',
                        fontWeight: 700,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)',
                      }}
                      onClick={async () => {
                        await handleAutoCureIssue(issue);
                        setFileViewer((prev) => ({ ...prev, isOpen: false }));
                      }}
                      title="Restore bit-for-bit clean copy from official WordPress.org release"
                    >
                      <RotateCcw size={14} />
                      <span>Auto-Cure: Restore Official WP.org</span>
                    </button>
                  );
                })()}

                {fileViewer.issue && canQuarantineIssue(fileViewer.issue) && (
                  <button
                    type="button"
                    className="webcare-modal-action-btn webcare-modal-action-danger"
                    onClick={() => {
                      if (fileViewer.issue) handleQuarantine(fileViewer.issue);
                    }}
                    title="Quarantine file now"
                  >
                    <Archive size={14} />
                    <span>Quarantine</span>
                  </button>
                )}

                {((fileViewer.issue && (fileViewer.issue.type === 'wp_debug_enabled' || (Boolean(fileViewer.filePath?.endsWith('wp-config.php')) && (fileViewer.issue.type?.includes('debug') || fileViewer.issue.description?.includes('WP_DEBUG'))))) || (Boolean(fileViewer.filePath?.endsWith('wp-config.php')) && Boolean(fileViewer.data?.content?.includes('WP_DEBUG')))) && (fileViewer.issue?.status !== 'repaired' && fileViewer.issue?.status !== 'resolved') && (
                  <button
                    type="button"
                    className="webcare-modal-action-btn"
                    style={{
                      background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                      color: '#ffffff',
                      border: '1px solid #047857',
                      boxShadow: '0 2px 6px rgba(5, 150, 105, 0.35)',
                      fontWeight: 700,
                      gap: '6px'
                    }}
                    onClick={() => {
                      const targetIssue: any = fileViewer.issue || {
                        id: 0,
                        type: 'wp_debug_enabled',
                        file_path: fileViewer.filePath,
                        description: 'WP_DEBUG is enabled in wp-config.php',
                      };
                      handleDisableWpDebug(targetIssue);
                      setFileViewer((prev) => ({ ...prev, isOpen: false }));
                    }}
                    title="1-Click turn off WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY in wp-config.php"
                  >
                    <ShieldCheck size={14} color="#ffffff" />
                    <span>Disable Debug</span>
                  </button>
                )}

                <button
                  type="button"
                  className="webcare-modal-close-btn"
                  onClick={() => setFileViewer((prev) => ({ ...prev, isOpen: false }))}
                  title="Close popup (Esc)"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Diagnostics & Forensic Metadata Toolbar */}
            <div className="webcare-modal-toolbar" style={{ flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '11.5px', color: '#94a3b8', flexWrap: 'wrap' }}>
                <span>Size: <strong style={{ color: '#e2e8f0' }}>{fileViewer.data?.size_formatted || '...'}</strong></span>
                <span>Permissions: <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{fileViewer.data?.permissions || '...'}</strong></span>
                <span>Ownership: <strong style={{ color: '#a78bfa', fontFamily: 'monospace' }}>{fileViewer.data?.ownership || '...'}</strong></span>
                {fileViewer.data?.ctime && (
                  <span>Created (ctime): <strong style={{ color: '#e2e8f0' }}>{fileViewer.data.ctime}</strong></span>
                )}
                {fileViewer.data?.mtime && (
                  <span>Modified (mtime): <strong style={{ color: '#fbbf24' }}>{fileViewer.data.mtime}</strong></span>
                )}
                {fileViewer.data?.atime && (
                  <span>Accessed (atime): <strong style={{ color: '#94a3b8' }}>{fileViewer.data.atime}</strong></span>
                )}
                <span>MIME: <strong style={{ color: '#34d399', fontFamily: 'monospace' }}>{fileViewer.data?.mime_type || (fileViewer.data?.image_mime || 'text/plain')}</strong></span>
                {fileViewer.data?.is_image && fileViewer.data.image_dimensions?.width && (
                  <span>Dimensions: <strong style={{ color: '#38bdf8' }}>{fileViewer.data.image_dimensions.width} × {fileViewer.data.image_dimensions.height} px</strong></span>
                )}
                {!fileViewer.data?.is_image && (
                  <span>Lines: <strong style={{ color: '#e2e8f0' }}>{fileViewer.data?.line_count ?? '...'}</strong></span>
                )}
                {fileViewer.data?.is_truncated && (
                  <span style={{ color: '#f59e0b', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <AlertTriangle size={12} /> Truncated at 750KB limit
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {!fileViewer.data?.is_image && (
                  <button
                    type="button"
                    onClick={() => setFileViewer((prev) => ({ ...prev, wordWrap: !prev.wordWrap }))}
                    style={{
                      background: fileViewer.wordWrap ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.08)',
                      border: `1px solid ${fileViewer.wordWrap ? '#818cf8' : 'rgba(255, 255, 255, 0.15)'}`,
                      color: fileViewer.wordWrap ? '#c7d2fe' : '#cbd5e1',
                      padding: '5px 10px',
                      borderRadius: '6px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      transition: 'all 0.15s ease',
                    }}
                    title="Toggle soft word wrapping for long minified lines"
                  >
                    <WrapText size={13} color={fileViewer.wordWrap ? '#818cf8' : '#94a3b8'} />
                    <span>{fileViewer.wordWrap ? 'Wrap: On' : 'Word Wrap'}</span>
                  </button>
                )}

                {fileViewer.data?.is_image && fileViewer.activeTab === 'image' ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <button
                      type="button"
                      onClick={() => setFileViewer((prev) => ({ ...prev, imageZoom: Math.max(25, prev.imageZoom - 25) }))}
                      style={{ background: '#1e293b', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#cbd5e1', padding: '4px 8px', borderRadius: '5px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 600 }}
                      title="Zoom Out"
                    >
                      <ZoomOut size={13} />
                    </button>
                    <span style={{ fontSize: '12px', color: '#94a3b8', minWidth: '45px', textAlign: 'center', fontWeight: 600 }}>
                      {fileViewer.imageZoom}%
                    </span>
                    <button
                      type="button"
                      onClick={() => setFileViewer((prev) => ({ ...prev, imageZoom: Math.min(300, prev.imageZoom + 25) }))}
                      style={{ background: '#1e293b', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#cbd5e1', padding: '4px 8px', borderRadius: '5px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 600 }}
                      title="Zoom In"
                    >
                      <ZoomIn size={13} />
                    </button>
                    <button
                      type="button"
                      onClick={() => setFileViewer((prev) => ({ ...prev, imageZoom: 100 }))}
                      style={{ background: '#1e293b', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#cbd5e1', padding: '4px 8px', borderRadius: '5px', cursor: 'pointer', fontSize: '11px', fontWeight: 600 }}
                      title="Reset Zoom"
                    >
                      Reset
                    </button>
                  </div>
                ) : (
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <Search
                      size={13}
                      style={{
                        position: 'absolute',
                        left: '10px',
                        color: '#64748b',
                        pointerEvents: 'none',
                      }}
                    />
                    <input
                      type="text"
                      placeholder="Filter or search in file..."
                      value={fileViewer.searchQuery}
                      onChange={(e) => setFileViewer((prev) => ({ ...prev, searchQuery: e.target.value }))}
                      className="webcare-modal-search-input"
                      style={{
                        paddingLeft: '28px !important' as any,
                        background: '#090d16 !important' as any,
                        color: '#ffffff !important' as any,
                        border: '1px solid rgba(255, 255, 255, 0.18) !important' as any,
                      }}
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Modal Body: Loading, Error, Image Preview, or Code Viewer */}
            <div className="webcare-modal-body">
              {fileViewer.loading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '360px', color: '#94a3b8', gap: '12px' }}>
                  <Loader2 size={36} className="webcare-spin" color="#38bdf8" />
                  <div style={{ fontSize: '14px' }}>Loading file securely from server...</div>
                </div>
              )}

              {!fileViewer.loading && fileViewer.error && (
                <div style={{ padding: '40px', textAlign: 'center', color: '#f87171' }}>
                  <XCircle size={44} style={{ margin: '0 auto 12px auto' }} />
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '17px', color: '#fca5a5' }}>File Inspection Restricted</h4>
                  <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#94a3b8', maxWidth: '520px', marginInline: 'auto', lineHeight: 1.5 }}>
                    {fileViewer.error.includes('<')
                      ? (fileViewer.error.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() || 'Access to inspect this file content was restricted by server policy.')
                      : fileViewer.error}
                  </p>
                </div>
              )}

              {!fileViewer.loading && !fileViewer.error && fileViewer.data && (
                fileViewer.data.is_image && fileViewer.activeTab === 'image' ? (
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    minHeight: '400px',
                    padding: '30px',
                    background: 'radial-gradient(circle at center, #0f172a 0%, #050811 100%)',
                    overflow: 'auto',
                    position: 'relative',
                  }}>
                    {/* Binary Validation & Threat Warning Banner */}
                    {fileViewer.data.image_security?.threat_warning && (
                      <div style={{
                        maxWidth: '800px',
                        width: '100%',
                        marginBottom: '20px',
                        padding: '14px 18px',
                        background: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid rgba(239, 68, 68, 0.45)',
                        borderRadius: '8px',
                        color: '#fca5a5',
                        fontSize: '13px',
                        lineHeight: 1.5,
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '12px'
                      }}>
                        <AlertTriangle size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
                        <div>
                          <strong style={{ color: '#f87171', display: 'block', marginBottom: '2px', fontSize: '14px' }}>
                            Security Warning: Deceptive Image File
                          </strong>
                          {fileViewer.data.image_security.threat_warning}
                          <div style={{ marginTop: '8px' }}>
                            <button
                              type="button"
                              onClick={() => setFileViewer((prev) => ({ ...prev, activeTab: 'code' }))}
                              style={{
                                background: '#dc2626',
                                color: '#ffffff',
                                border: 'none',
                                padding: '4px 10px',
                                borderRadius: '5px',
                                fontSize: '11px',
                                fontWeight: 700,
                                cursor: 'pointer'
                              }}
                            >
                              Inspect Raw Injected Code
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {fileViewer.data.image_security?.magic_bytes_match && !fileViewer.data.image_security?.threat_warning && (
                      <div style={{
                        maxWidth: '800px',
                        width: '100%',
                        marginBottom: '16px',
                        padding: '8px 14px',
                        background: 'rgba(16, 185, 129, 0.1)',
                        border: '1px solid rgba(16, 185, 129, 0.3)',
                        borderRadius: '6px',
                        color: '#6ee7b7',
                        fontSize: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <CheckCircle2 size={15} color="#10b981" />
                          <span>
                            <strong>Binary Integrity Verified:</strong> Magic header conforms to valid <strong>{fileViewer.data.image_security.detected_type}</strong> format. No disguised executables or active PHP polyglots detected.
                          </span>
                        </div>
                      </div>
                    )}

                    {fileViewer.data.image_base64 ? (
                      <div style={{
                        padding: '16px',
                        background: 'repeating-conic-gradient(#1e293b 0% 25%, #0f172a 0% 50%) 50% / 20px 20px',
                        borderRadius: '10px',
                        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        maxWidth: '100%',
                        maxHeight: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}>
                        <img
                          src={fileViewer.data.image_base64}
                          alt={fileViewer.data.filename}
                          style={{
                            maxWidth: '100%',
                            maxHeight: '520px',
                            objectFit: 'contain',
                            transform: `scale(${fileViewer.imageZoom / 100})`,
                            transformOrigin: 'center center',
                            transition: 'transform 0.15s ease-out',
                            borderRadius: '4px',
                          }}
                        />
                      </div>
                    ) : (
                      <div style={{ textAlign: 'center', color: '#94a3b8', padding: '40px' }}>
                        <ImageIcon size={48} color="#64748b" style={{ margin: '0 auto 12px auto' }} />
                        <h4 style={{ margin: '0 0 6px 0', color: '#e2e8f0' }}>Image Data Unavailable</h4>
                        <p style={{ margin: 0, fontSize: '13px' }}>The image could not be rendered as a preview. Switch to "Raw / Hex Source" above to inspect.</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ position: 'relative', flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                    {/* Sensitive Credentials Masking Notice */}
                    {fileViewer.data.is_masked && (
                      <div style={{
                        margin: '12px 18px 0 18px',
                        padding: '9px 14px',
                        borderRadius: '7px',
                        background: 'rgba(56, 189, 248, 0.08)',
                        border: '1px solid rgba(56, 189, 248, 0.25)',
                        color: '#38bdf8',
                        fontSize: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        zIndex: 10
                      }}>
                        <Lock size={14} color="#38bdf8" />
                        <span>
                          <strong>Sensitive Credentials Masked:</strong> Database name, username, password, host, and cryptographic salt keys are automatically redacted (<code>••••••••••••••••</code>) to prevent accidental shoulder-surfing and credential exposure.
                        </span>
                      </div>
                    )}

                    {/* Quick Floating "Copy Code Only" Button on Top Right above code */}
                    <button
                      type="button"
                      onClick={() => handleCopyFileBundle('text')}
                      style={{
                        position: 'absolute',
                        top: '12px',
                        right: '18px',
                        zIndex: 20,
                        background: copiedFileContent ? 'rgba(16, 185, 129, 0.9)' : 'rgba(30, 41, 59, 0.85)',
                        backdropFilter: 'blur(6px)',
                        border: `1px solid ${copiedFileContent ? '#10b981' : 'rgba(255, 255, 255, 0.2)'}`,
                        color: copiedFileContent ? '#ffffff' : '#e2e8f0',
                        borderRadius: '6px',
                        padding: '5px 10px',
                        fontSize: '11.5px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
                        transition: 'all 0.15s ease',
                      }}
                      onMouseEnter={(e) => {
                        if (!copiedFileContent) {
                          e.currentTarget.style.background = '#334155';
                          e.currentTarget.style.color = '#ffffff';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.35)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!copiedFileContent) {
                          e.currentTarget.style.background = 'rgba(30, 41, 59, 0.85)';
                          e.currentTarget.style.color = '#e2e8f0';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.2)';
                        }
                      }}
                      title="Copy raw code snippet only to clipboard"
                    >
                      {copiedFileContent ? <Check size={12} color="#ffffff" /> : <Copy size={12} color="#38bdf8" />}
                      <span>{copiedFileContent ? 'Code Copied!' : 'Copy Code'}</span>
                    </button>

                    <div className={`webcare-code-viewer-container ${fileViewer.wordWrap ? 'webcare-wrap-lines' : ''}`}>
                      {fileViewer.data.content.split('\n').map((line, idx) => {
                        const lineNum = idx + 1;
                        const isThreatLine = fileViewer.issue?.line_number === lineNum;
                        const isSearchMatch = fileViewer.searchQuery && line.toLowerCase().includes(fileViewer.searchQuery.toLowerCase());

                        return (
                          <div
                            key={lineNum}
                            ref={isThreatLine ? threatLineRef : undefined}
                            className={`webcare-code-line ${isThreatLine ? 'webcare-threat-line' : ''} ${isSearchMatch ? 'webcare-search-match' : ''}`}
                          >
                            <div className="webcare-code-gutter">
                              {isThreatLine && <span title="Threat Vector Flagged" style={{ marginRight: '4px' }}>⚠️</span>}
                              {lineNum}
                            </div>
                            <div className="webcare-code-text">
                              {isThreatLine && (
                                <span className="webcare-code-threat-tag">
                                  {(fileViewer.issue?.confidence_score ?? 0) >= 90 ? 'High-Confidence Alert:' : 'File Review Recommended:'} {fileViewer.issue?.type || 'REVIEW'}
                                </span>
                              )}
                              {line}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )
              )}
            </div>

            {/* Modal Footer */}
            <div className="webcare-modal-footer">
              <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Terminal size={13} />
                  <span>Path: <strong style={{ color: '#cbd5e1' }}>{fileViewer.filePath}</strong></span>
                </div>
                {(fileViewer.data?.sha256 || fileViewer.issue?.sha256 || fileViewer.issue?.file_sha256) && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Shield size={12} color="#38bdf8" />
                    <span>SHA-256: <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{(fileViewer.data?.sha256 || fileViewer.issue?.sha256 || fileViewer.issue?.file_sha256)?.substring(0, 16)}...</strong></span>
                  </div>
                )}
              </div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>
                Press <kbd style={{ background: '#1e293b', color: '#cbd5e1', padding: '2px 5px', borderRadius: '4px', border: '1px solid #334155' }}>Esc</kbd> to close
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          POPUP MODAL 2: POST / PAGE CONTENT & SPAM INSPECTOR MODAL
          ========================================================================= */}
      {postViewer.isOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setPostViewer((prev) => ({ ...prev, isOpen: false }));
            }
          }}
        >
          <div className="webcare-modal-window webcare-modal-window-light">
            {/* Modal Header */}
            <div className="webcare-post-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
                <div className="webcare-modal-icon-badge" style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}>
                  <Globe size={22} color="#ffffff" />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {postViewer.data?.title || postViewer.issue?.post_title || 'Post / Page Content Forensic'}
                    </h3>
                    <span className="webcare-type-badge-post">
                      {(postViewer.data?.post_type || postViewer.issue?.post_type || 'post').toUpperCase()} #{postViewer.data?.post_id || postViewer.issue?.post_id || ''}
                    </span>
                    {postViewer.data?.post_status && (
                      <span className="webcare-badge" style={{ background: '#ecfdf5', color: '#047857' }}>
                        {postViewer.data.post_status}
                      </span>
                    )}
                    {postViewer.issue && (
                      <span className={`webcare-badge webcare-badge-${postViewer.issue.severity}`}>
                        {postViewer.issue.severity} Threat
                      </span>
                    )}
                  </div>
                  {postViewer.data?.view_url && (
                    <div style={{ marginTop: '4px' }}>
                      <a
                        href={postViewer.data.view_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="webcare-link-subtle"
                        style={{ fontSize: '12px' }}
                      >
                        <Globe size={12} color="#3b82f6" />
                        <span>{postViewer.data.view_url}</span>
                        <ArrowUpRight size={12} />
                      </a>
                    </div>
                  )}
                </div>
              </div>

              {/* Header Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                {(postViewer.data?.edit_url || postViewer.issue?.edit_url) && (
                  <a
                    href={postViewer.data?.edit_url || postViewer.issue?.edit_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-btn webcare-btn-edit-post"
                    style={{ padding: '7px 14px', fontSize: '13px' }}
                    title="Open WordPress Block/Classic editor in a new tab"
                  >
                    <Edit3 size={15} /> Edit in WordPress <ArrowUpRight size={13} />
                  </a>
                )}

                {(postViewer.data?.view_url || postViewer.issue?.view_url) && (
                  <a
                    href={postViewer.data?.view_url || postViewer.issue?.view_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-btn"
                    style={{ background: 'var(--webcare-bg-surface, #f1f5f9)', color: 'var(--webcare-text-primary, #0f172a)', border: '1px solid var(--webcare-border, #cbd5e1)', padding: '7px 12px', fontSize: '13px' }}
                    title="Visit live published page"
                  >
                    <ExternalLink size={14} /> Visit URL
                  </a>
                )}

                <button
                  type="button"
                  className="webcare-modal-close-btn-light"
                  onClick={() => setPostViewer((prev) => ({ ...prev, isOpen: false }))}
                  title="Close popup (Esc)"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '24px', flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {postViewer.loading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '280px', color: '#64748b', gap: '12px' }}>
                  <Loader2 size={36} className="webcare-spin" color="#6366f1" />
                  <div style={{ fontSize: '14px' }}>Loading post content from database...</div>
                </div>
              )}

              {!postViewer.loading && postViewer.error && (
                <div style={{ padding: '36px', textAlign: 'center', color: '#ef4444' }}>
                  <XCircle size={40} style={{ margin: '0 auto 10px auto' }} />
                  <h4>Unable to Load Post Data</h4>
                  <p style={{ color: '#64748b' }}>{postViewer.error}</p>
                </div>
              )}

              {!postViewer.loading && !postViewer.error && (
                <Fragment>
                  {/* Threat Diagnosis Card */}
                  {postViewer.issue && (
                    <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '10px', padding: '16px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#991b1b', fontWeight: 700, fontSize: '14px', marginBottom: '6px' }}>
                        <AlertTriangle size={17} />
                        <span>Threat Analysis: {postViewer.issue.type} ({postViewer.issue.engine})</span>
                      </div>
                      <p style={{ margin: '0 0 10px 0', fontSize: '13px', color: '#7f1d1d' }}>
                        {postViewer.issue.description}
                      </p>
                      {postViewer.issue.evidence && (
                        <div style={{ fontSize: '12px', color: '#991b1b', background: '#fee2e2', padding: '8px 12px', borderRadius: '6px', marginBottom: '8px' }}>
                          <strong>Detection Pattern:</strong> {postViewer.issue.evidence}
                        </div>
                      )}
                      {postViewer.issue.code_snippet && (
                        <div>
                          <div style={{ fontSize: '11px', color: '#7f1d1d', fontWeight: 600, marginBottom: '4px' }}>Detected Suspicious Payload:</div>
                          <pre style={{ background: '#450a0a', color: '#fca5a5', padding: '10px 14px', borderRadius: '6px', overflowX: 'auto', fontSize: '12px', margin: 0, fontFamily: 'monospace' }}>
                            {postViewer.issue.code_snippet}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Post Metadata Strip */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px 18px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Post ID</div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>#{postViewer.data?.post_id || postViewer.issue?.post_id}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Author</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>{postViewer.data?.author || 'WordPress Admin'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Post Type</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', textTransform: 'capitalize' }}>{postViewer.data?.post_type || 'post'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Modified Date</div>
                      <div style={{ fontSize: '13px', color: '#334155' }}>{postViewer.data?.modified || 'N/A'}</div>
                    </div>
                  </div>

                  {/* Raw Post Database Content */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileText size={15} color="#6366f1" /> Raw Database Post Content
                      </div>
                      <button
                        type="button"
                        className="webcare-btn"
                        style={{ background: 'var(--webcare-bg-surface, #f1f5f9)', color: 'var(--webcare-text-secondary, #334155)', border: '1px solid var(--webcare-border, #cbd5e1)', padding: '4px 10px', fontSize: '12px' }}
                        onClick={handleCopyPostContent}
                      >
                        {copiedPostContent ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                        <span>{copiedPostContent ? 'Copied' : 'Copy Content'}</span>
                      </button>
                    </div>
                    <pre style={{ background: 'var(--webcare-bg-code, #090d16)', color: 'var(--webcare-text-code, #38bdf8)', padding: '16px', borderRadius: '8px', overflow: 'auto', maxHeight: '280px', fontSize: '12px', lineHeight: '1.6', margin: 0, border: '1px solid var(--webcare-border-code, #1e293b)' }}>
                      {postViewer.data?.content || '(No content stored in this post)'}
                    </pre>
                  </div>
                </Fragment>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px 24px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: '#64748b' }}>
                💡 Click <strong>"Edit in WordPress"</strong> to open the block editor and remove spam/injected scripts safely.
              </div>
              <button
                type="button"
                className="webcare-btn"
                style={{ background: '#e2e8f0', color: '#334155', padding: '6px 14px', fontSize: '13px' }}
                onClick={() => setPostViewer((prev) => ({ ...prev, isOpen: false }))}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          POPUP MODAL: DATABASE RECORD FORENSICS & INSPECTOR MODAL
          ========================================================================= */}
      {dbInspectorModal.isOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setDbInspectorModal((prev) => ({ ...prev, isOpen: false }));
            }
          }}
        >
          <div className="webcare-modal-window webcare-modal-window-light" style={{ maxWidth: '980px', width: '95%' }}>
            {/* Modal Header */}
            <div className="webcare-post-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
                <div className="webcare-modal-icon-badge" style={{ background: 'linear-gradient(135deg, #ec4899, #be185d)' }}>
                  <Database size={22} color="#ffffff" />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', fontFamily: 'monospace' }}>
                      {dbInspectorModal.data?.table || dbInspectorModal.issue?.table_name || 'Database Record'}
                    </h3>
                    <span className="webcare-type-badge-db" style={{ background: '#fdf2f8', color: '#9d174d', borderColor: '#fbcfe8' }}>
                      ROW #{dbInspectorModal.data?.row_id || dbInspectorModal.issue?.row_id || ''}
                    </span>
                    {dbInspectorModal.data?.primary_key && (
                      <span className="webcare-badge" style={{ background: '#f1f5f9', color: '#475569' }}>
                        PK: {dbInspectorModal.data.primary_key}
                      </span>
                    )}
                    {dbInspectorModal.data?.is_log_table && (
                      <span className="webcare-badge" style={{ background: '#fef3c7', color: '#b45309' }}>
                        LOG / AUDIT TABLE
                      </span>
                    )}
                    {dbInspectorModal.issue && (
                      <span className={`webcare-badge webcare-badge-${dbInspectorModal.issue.severity}`}>
                        {dbInspectorModal.issue.severity.toUpperCase()} THREAT
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                    Database Table Forensic Inspector &bull; Live MySQL record inspection with pre-action auto-backup
                  </div>
                </div>
              </div>

              {/* Header Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                {dbInspectorModal.issue && (dbInspectorModal.data?.row || (dbInspectorModal.data && typeof dbInspectorModal.data === 'object' && Object.keys(dbInspectorModal.data).length > 0) || dbInspectorModal.issue?.db_row || dbRowCache[dbInspectorModal.issue.id]?.row) && (
                  <Fragment>
                    {dbInspectorModal.issue.column_name && (
                      <button
                        type="button"
                        className="webcare-btn"
                        style={{ background: '#fffbeb', color: '#b45309', border: '1px solid #fde68a', padding: '7px 12px', fontSize: '12px', fontWeight: 600 }}
                        onClick={() => {
                          if (dbInspectorModal.issue) {
                            handleRemediateDbRow(dbInspectorModal.issue, 'cleanse_field');
                            setDbInspectorModal((prev) => ({ ...prev, isOpen: false }));
                          }
                        }}
                        title={`Cleanse only column '${dbInspectorModal.issue.column_name}' while keeping row intact`}
                      >
                        <RotateCcw size={13} /> Cleanse Column
                      </button>
                    )}
                    <button
                      type="button"
                      className="webcare-btn"
                      style={{ background: '#fff1f2', color: '#e11d48', border: '1px solid #fecdd3', padding: '7px 14px', fontSize: '12px', fontWeight: 600 }}
                      onClick={() => {
                        if (dbInspectorModal.issue) {
                          handleRemediateDbRow(dbInspectorModal.issue, 'delete_row');
                          setDbInspectorModal((prev) => ({ ...prev, isOpen: false }));
                        }
                      }}
                      title="Delete this malicious log row from MySQL with pre-action auto-backup"
                    >
                      <Trash2 size={13} /> Delete Row (Auto-Backup)
                    </button>
                  </Fragment>
                )}

                <button
                  type="button"
                  className="webcare-modal-close-btn-light"
                  onClick={() => setDbInspectorModal((prev) => ({ ...prev, isOpen: false }))}
                  title="Close popup (Esc)"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '24px', flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {dbInspectorModal.loading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '280px', color: '#64748b', gap: '12px' }}>
                  <Loader2 size={36} className="webcare-spin" color="#be185d" />
                  <div style={{ fontSize: '14px' }}>Querying MySQL row data from database...</div>
                </div>
              )}

              {!dbInspectorModal.loading && dbInspectorModal.error && (
                <div style={{ padding: '36px', textAlign: 'center', color: '#ef4444' }}>
                  <XCircle size={40} style={{ margin: '0 auto 10px auto' }} />
                  <h4>Unable to Query Database Record</h4>
                  <p style={{ color: '#64748b' }}>{dbInspectorModal.error}</p>
                </div>
              )}

              {!dbInspectorModal.loading && !dbInspectorModal.error && (() => {
                const rowObj = (dbInspectorModal.data?.row && typeof dbInspectorModal.data.row === 'object' ? dbInspectorModal.data.row : null)
                  || (dbInspectorModal.data && !dbInspectorModal.data.row && typeof dbInspectorModal.data === 'object' && Object.keys(dbInspectorModal.data).length > 0 ? dbInspectorModal.data : null)
                  || dbInspectorModal.issue?.db_row
                  || (dbInspectorModal.issue ? dbRowCache[dbInspectorModal.issue.id]?.row : null);

                if (!rowObj || typeof rowObj !== 'object' || Object.keys(rowObj).length === 0) {
                  return (
                    <div style={{ padding: '36px', textAlign: 'center', color: '#64748b' }}>
                      <Database size={40} style={{ margin: '0 auto 10px auto', opacity: 0.5 }} />
                      <h4>No Row Data Returned</h4>
                      <p>The record might have been removed or cannot be retrieved from MySQL.</p>
                      <button
                        type="button"
                        className="webcare-btn"
                        style={{ marginTop: '12px', background: '#f5f3ff', color: '#6d28d9', border: '1px solid #ddd6fe' }}
                        onClick={() => {
                          if (dbInspectorModal.issue) handleOpenDbInspector(dbInspectorModal.issue);
                        }}
                      >
                        <RotateCcw size={12} /> Retry Query
                      </button>
                    </div>
                  );
                }

                return (
                <Fragment>
                  {/* Context Intelligence Advisory */}
                  {dbInspectorModal.data.is_log_table ? (
                    <div style={{ background: '#fff7ed', border: '1px solid #fed7aa', borderRadius: '8px', padding: '14px 18px', display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                      <AlertTriangle size={20} color="#ea580c" style={{ flexShrink: 0, marginTop: '2px' }} />
                      <div style={{ fontSize: '13px', color: '#9a3412', lineHeight: '1.5' }}>
                        <strong>Redirection / Access Log Context:</strong> This table stores historical HTTP requests logged by a WordPress plugin. An external attacker probe sent a URL containing a malicious payload (e.g. suspicious encoded script strings), and the plugin recorded it here. It is an audit record of a past probe rather than executed server code. You can safely delete this row to clean your audit log.
                      </div>
                    </div>
                  ) : (
                    <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', padding: '14px 18px', display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                      <ShieldCheck size={20} color="#16a34a" style={{ flexShrink: 0, marginTop: '2px' }} />
                      <div style={{ fontSize: '13px', color: '#166534', lineHeight: '1.5' }}>
                        <strong>Auto-Backup Security Guarantee:</strong> Any deletion or cleansing action creates an encrypted, isolated JSON snapshot in <code>.backups/remediation/</code> prior to modification, ensuring full rollback capability if needed.
                      </div>
                    </div>
                  )}

                  {/* Flagged Column Highlight */}
                  {dbInspectorModal.issue?.column_name && (
                    <div style={{ background: '#fff1f2', border: '1px solid #fecdd3', borderRadius: '8px', padding: '16px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <div style={{ fontSize: '12px', color: '#991b1b', fontWeight: 700, textTransform: 'uppercase' }}>
                          Flagged Malicious Column: <code>{dbInspectorModal.issue.column_name}</code>
                        </div>
                        {(dbInspectorModal.issue?.confidence_score ?? 0) >= 90 ? (
                          <span className="webcare-badge webcare-badge-critical">Priority Review</span>
                        ) : (
                          <span className="webcare-badge webcare-badge-warning">Needs Review</span>
                        )}
                      </div>
                      <pre style={{ background: '#450a0a', color: '#fca5a5', padding: '12px', borderRadius: '6px', overflowX: 'auto', fontSize: '12px', margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: '180px' }}>
                        {String(rowObj[dbInspectorModal.issue.column_name] ?? dbInspectorModal.issue.code_snippet ?? '')}
                      </pre>
                    </div>
                  )}

                  {/* All Columns Table */}
                  <div>
                    <h4 style={{ margin: '0 0 10px 0', fontSize: '14px', color: 'var(--webcare-text-title, #0f172a)', fontWeight: 700 }}>
                      Complete MySQL Row Data ({Object.keys(rowObj).length} Columns):
                    </h4>
                    <div style={{ border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '8px', overflow: 'hidden' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                        <thead>
                          <tr style={{ background: 'var(--webcare-bg-surface, #f8fafc)', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', textAlign: 'left' }}>
                            <th style={{ padding: '10px 14px', width: '220px', color: '#475569', fontWeight: 600 }}>Column Name</th>
                            <th style={{ padding: '10px 14px', color: '#475569', fontWeight: 600 }}>Stored Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(rowObj).map(([col, val], idx) => {
                            const isFlaggedCol = col === dbInspectorModal.issue?.column_name;
                            const isPk = col === dbInspectorModal.data?.primary_key;
                            const strVal = val === null ? 'NULL' : String(val);
                            return (
                              <tr key={col} style={{ borderBottom: idx < Object.keys(rowObj).length - 1 ? '1px solid #f1f5f9' : 'none', background: isFlaggedCol ? '#fff1f2' : idx % 2 === 0 ? '#ffffff' : '#fcfcfd' }}>
                                <td style={{ padding: '10px 14px', verticalAlign: 'top' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <strong style={{ fontFamily: 'monospace', color: isFlaggedCol ? '#e11d48' : 'var(--webcare-text-primary, #0f172a)' }}>{col}</strong>
                                    {isPk && <span style={{ fontSize: '10px', background: '#e0e7ff', color: '#4338ca', padding: '1px 5px', borderRadius: '4px', fontWeight: 700 }}>PK</span>}
                                    {isFlaggedCol && <span style={{ fontSize: '10px', background: '#fee2e2', color: '#b91c1c', padding: '1px 5px', borderRadius: '4px', fontWeight: 700 }}>FLAGGED</span>}
                                  </div>
                                </td>
                                <td style={{ padding: '10px 14px', verticalAlign: 'top' }}>
                                  <div style={{ fontFamily: 'monospace', color: val === null ? '#94a3b8' : isFlaggedCol ? '#991b1b' : '#334155', wordBreak: 'break-all', whiteSpace: 'pre-wrap', maxHeight: '160px', overflowY: 'auto' }}>
                                    {strVal}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </Fragment>
                );
              })()}
            </div>

            {/* Modal Footer */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px 24px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: '#64748b' }}>
                🛡️ <strong>Safety Guarantee:</strong> Deleting or cleansing takes an automatic pre-action JSON snapshot in <code>.backups/remediation/</code> before executing MySQL modifications.
              </div>
              <button
                type="button"
                className="webcare-btn"
                style={{ background: '#e2e8f0', color: '#334155', padding: '6px 14px', fontSize: '13px' }}
                onClick={() => setDbInspectorModal((prev) => ({ ...prev, isOpen: false }))}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: CVE SECURITY ADVISORY & FORENSIC INSPECTOR */}
      {cveModal.isOpen && cveModal.issue && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.75)',
            backdropFilter: 'blur(5px)',
            zIndex: 100000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px',
            animation: 'fadeIn 0.2s ease-out',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setCveModal({ isOpen: false, issue: null });
          }}
        >
          <div
            style={{
              background: '#ffffff',
              borderRadius: '14px',
              maxWidth: '920px',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
              overflow: 'hidden',
              border: '1px solid #e2e8f0',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                background: 'linear-gradient(135deg, #090d16 0%, #1e1b4b 100%)',
                color: '#ffffff',
                padding: '20px 24px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ background: 'rgba(239, 68, 68, 0.2)', padding: '10px', borderRadius: '10px', border: '1px solid rgba(239, 68, 68, 0.4)' }}>
                  <ShieldAlert size={24} color="#f87171" />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, letterSpacing: '-0.3px', color: '#ffffff' }}>
                    CVE Security Vulnerability Intelligence
                  </h3>
                  <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>Target: <strong>{cveModal.issue.component_name || cveModal.issue.file_path}</strong></span>
                    <span>&bull;</span>
                    <span>Installed: <strong>v{cveModal.issue.installed_version || '?'}</strong></span>
                    {cveModal.issue.latest_version && (
                      <Fragment>
                        <span>&bull;</span>
                        <span>Latest: <strong style={{ color: '#4ade80' }}>v{cveModal.issue.latest_version}</strong></span>
                      </Fragment>
                    )}
                  </div>
                </div>
              </div>
              <button
                type="button"
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  border: 'none',
                  color: '#ffffff',
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
                onClick={() => setCveModal({ isOpen: false, issue: null })}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '24px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Summary Banner */}
              <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '10px', padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div style={{ maxWidth: '600px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#991b1b', fontWeight: 700, fontSize: '14px', marginBottom: '4px' }}>
                    <AlertTriangle size={16} />
                    <span>Active Vulnerability Exposure Detected</span>
                  </div>
                  <div style={{ fontSize: '13px', color: '#7f1d1d', lineHeight: 1.5 }}>
                    {cveModal.issue.description}
                  </div>
                </div>
                {cveModal.issue.update_url && (
                  <a
                    href={cveModal.issue.update_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-btn-update-software"
                    style={{ padding: '8px 16px', fontSize: '13px' }}
                  >
                    <RefreshCw size={14} /> Update Software Now <ArrowUpRight size={13} />
                  </a>
                )}
              </div>

              {/* CVE Advisories List */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <h4 style={{ margin: 0, fontSize: '15px', color: 'var(--webcare-text-title, #0f172a)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>Official CVE References & CVSS Severity Scores</span>
                    <span style={{ fontSize: '12px', background: '#fee2e2', color: '#991b1b', padding: '2px 8px', borderRadius: '12px' }}>
                      {cveModal.issue.cves?.length || 0} Advisories
                    </span>
                  </h4>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>
                    Source: National Vulnerability Database (NVD) & WebCare Pro Security Feeds
                  </span>
                </div>

                {(!cveModal.issue.cves || cveModal.issue.cves.length === 0) ? (
                  <div style={{ padding: '32px', textAlign: 'center', background: '#f8fafc', borderRadius: '8px', color: '#64748b' }}>
                    <CheckCircle2 size={32} color="#10b981" style={{ margin: '0 auto 8px auto' }} />
                    <p style={{ margin: 0, fontSize: '14px' }}>This component is outdated, but no specific public CVE exploit payload was mapped to this exact version.</p>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    {cveModal.issue.cves.map((cve) => (
                      <div
                        key={cve.cve_id}
                        style={{
                          background: '#ffffff',
                          border: '1px solid #e2e8f0',
                          borderLeft: `5px solid ${cve.cvss >= 9.0 ? '#b91c1c' : cve.cvss >= 7.0 ? '#ea580c' : '#d97706'}`,
                          borderRadius: '10px',
                          padding: '16px 20px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '10px',
                          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <span style={{ fontFamily: 'monospace', fontWeight: 800, fontSize: '14px', color: 'var(--webcare-text-primary, #0f172a)', background: 'var(--webcare-bg-surface, #f1f5f9)', padding: '3px 8px', borderRadius: '6px' }}>
                              {cve.cve_id}
                            </span>
                            <span className={
                              cve.cvss >= 9.0 ? 'webcare-cvss-badge-critical' :
                              cve.cvss >= 7.0 ? 'webcare-cvss-badge-high' : 'webcare-cvss-badge-medium'
                            }>
                              CVSS {cve.cvss} &bull; {(cve.severity || 'high').toUpperCase()}
                            </span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <span style={{ fontSize: '12px', color: '#64748b' }}>
                              Fixed in: <strong style={{ color: '#16a34a' }}>v{cve.fixed_in}</strong>
                            </span>
                            <a
                              href={cve.reference}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="webcare-link-subtle"
                              style={{ color: '#0284c7', fontWeight: 600 }}
                            >
                              NVD Advisory <ExternalLink size={12} />
                            </a>
                          </div>
                        </div>

                        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                          {cve.title}
                        </div>

                        <div style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6 }}>
                          {cve.cve_details}
                        </div>

                        <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', color: '#64748b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span><strong>Recommended Action:</strong> Upgrade {cveModal.issue.component_name || 'component'} to <strong>v{cve.fixed_in}</strong> or higher immediately.</span>
                          {cveModal.issue.update_url && (
                            <a href={cveModal.issue.update_url} target="_blank" rel="noopener noreferrer" style={{ color: '#0284c7', fontWeight: 600, textDecoration: 'none' }}>
                              Go to updates &rarr;
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px 24px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: '#64748b' }}>
                🛡️ Always take a database backup before updating major plugins or WordPress core.
              </div>
              <div style={{ display: 'flex', gap: '10px' }}>
                {cveModal.issue.update_url && (
                  <a
                    href={cveModal.issue.update_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-btn-update-software"
                  >
                    <RefreshCw size={12} /> Upgrade in WordPress
                  </a>
                )}
                <button
                  type="button"
                  className="webcare-btn"
                  style={{ background: '#e2e8f0', color: '#334155', padding: '6px 14px', fontSize: '13px' }}
                  onClick={() => setCveModal({ isOpen: false, issue: null })}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          POPUP MODAL 4: AI CYBERSECURITY FORENSIC CODE ANALYSIS MODAL
          ========================================================================= */}
      {aiModal.isOpen && (
        <div
          className="webcare-modal-backdrop"
          style={{ zIndex: 10000005 }}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setAiModal((prev) => ({ ...prev, isOpen: false }));
            }
          }}
        >
          <div className="webcare-modal-window webcare-modal-window-light" style={{ maxWidth: '850px' }}>
            {/* Modal Header */}
            <div className="webcare-post-modal-header" style={{ borderBottom: '1px solid #e2e8f0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
                <div className="webcare-modal-icon-badge" style={{ background: 'linear-gradient(135deg, #7c3aed, #6366f1)' }}>
                  <Sparkles size={22} color="#ffffff" />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                      AI Threat & Forensic Code Analysis
                    </h3>
                    <span className="webcare-badge" style={{ background: '#f5f3ff', color: '#7c3aed', border: '1px solid #ddd6fe' }}>
                      {aiModal.provider ? `${aiModal.provider.toUpperCase()} (${aiModal.model})` : 'AI Engine'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginTop: '3px', fontFamily: 'monospace' }}>
                    Target: {aiModal.filePath} &bull; Vector: {aiModal.threatType}
                  </div>
                </div>
              </div>

              <button
                type="button"
                className="webcare-modal-close-btn-light"
                onClick={() => setAiModal((prev) => ({ ...prev, isOpen: false }))}
                title="Close popup (Esc)"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Content */}
            <div style={{ padding: '24px', maxHeight: '70vh', overflowY: 'auto' }}>
              {aiModal.loading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 20px', gap: '14px', color: '#64748b' }}>
                  <Loader2 size={38} className="webcare-spin-icon" color="#7c3aed" />
                  <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    AI Cyber Forensic Engine Analyzing Code...
                  </div>
                  <p style={{ margin: 0, fontSize: '13px', color: '#64748b', textAlign: 'center', maxWidth: '420px' }}>
                    De-obfuscating potential webshell strings, evaluating execution risk, and synthesizing remediation recommendations.
                  </p>
                </div>
              )}

              {!aiModal.loading && aiModal.error && (
                <div style={{ padding: '30px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '10px', textAlign: 'center' }}>
                  <AlertTriangle size={36} color="#ef4444" style={{ margin: '0 auto 12px auto' }} />
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '16px', color: '#991b1b' }}>AI Analysis Unavailable</h4>
                  <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#7f1d1d', maxWidth: '520px', marginInline: 'auto' }}>
                    {aiModal.error}
                  </p>
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ background: '#7c3aed', color: '#fff', fontSize: '13px', margin: '0 auto' }}
                    onClick={() => {
                      setAiModal((prev) => ({ ...prev, isOpen: false }));
                      handleNavTabChange('settings');
                    }}
                  >
                    <SettingsIcon size={14} /> Open Settings to Configure AI Key
                  </button>
                </div>
              )}

              {!aiModal.loading && !aiModal.error && aiModal.analysis && (
                <AiForensicReportView
                  analysis={aiModal.analysis}
                  provider={aiModal.provider}
                  model={aiModal.model}
                  filePath={aiModal.filePath}
                  threatType={aiModal.threatType}
                />
              )}
            </div>

            {/* Modal Footer */}
            <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '14px 24px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: '#64748b' }}>
                💡 You can change AI provider & models anytime in <strong>Settings & Automation</strong>.
              </div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className="webcare-btn"
                  style={{ background: '#e2e8f0', color: '#334155', padding: '6px 16px', fontSize: '13px' }}
                  onClick={() => setAiModal((prev) => ({ ...prev, isOpen: false }))}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Component Changelog Modal */}
      <ChangelogModal
        modal={changelogModal}
        onClose={() => setChangelogModal((prev) => ({ ...prev, isOpen: false }))}
        onCopy={(text) => {
          if (navigator.clipboard) {
            navigator.clipboard.writeText(text);
            setCopiedChangelog(true);
            setTimeout(() => setCopiedChangelog(false), 2000);
          }
        }}
        copied={copiedChangelog}
      />

      {/* Visual Code Diff (FIM) In-Page Overlay Modal */}
      <VisualDiffModal
        isOpen={visualDiffModal.isOpen}
        filePath={visualDiffModal.filePath}
        issueId={visualDiffModal.issueId}
        onClose={() => setVisualDiffModal({ isOpen: false, filePath: null, issueId: null })}
        apiRequest={apiRequest}
        onRemediated={(remediatedPath, remediatedIssueId) => {
          const isMatch = (item: any) => {
            if (remediatedIssueId && item.id === remediatedIssueId) return true;
            if (remediatedPath && item.file_path) {
              if (item.file_path === remediatedPath) return true;
              const p1 = item.file_path.replace(/\\/g, '/').toLowerCase();
              const p2 = remediatedPath.replace(/\\/g, '/').toLowerCase();
              if (p1 === p2 || p1.endsWith(p2) || p2.endsWith(p1)) return true;
            }
            return false;
          };

          // 1. Immediately update deep scanner findings
          setIssues((prev) =>
            prev.map((i) => (isMatch(i) ? { ...i, status: 'repaired' } : i))
          );

          // 2. Immediately update targeted scan results if open
          if (targetedResult) {
            setTargetedResult((prev) =>
              prev
                ? {
                    ...prev,
                    issues: prev.issues.map((i) => (isMatch(i) ? { ...i, status: 'repaired' } : i)),
                  }
                : null
            );
          }

          // 3. Immediately update selected historical scan on Scan Logs & Audit History page
          setSelectedScanDetail((prev) => {
            if (!prev) return null;
            const updatedIssues = prev.issues.map((i) =>
              isMatch(i) ? { ...i, status: 'repaired' } : i
            );
            const openIssuesCount = updatedIssues.filter(
              (i) => i.status !== 'ignored' && !i.is_whitelisted && i.status !== 'repaired' && i.status !== 'quarantined'
            ).length;
            return {
              ...prev,
              issues: updatedIssues,
              scan: {
                ...prev.scan,
                issues_found: openIssuesCount,
              },
            };
          });

          // 4. Update scan history list entry
          setScanHistory((prev) =>
            prev.map((scan) => {
              if (selectedScanDetail && scan.id === selectedScanDetail.scan?.id) {
                return {
                  ...scan,
                  issues_found: Math.max(0, (scan.issues_found || 1) - 1),
                };
              }
              return scan;
            })
          );

          // 5. Background sync for latest scan and active scan detail
          loadLatestScan();
          if (selectedScanDetail?.scan?.id) {
            const currentScanId = selectedScanDetail.scan.id;
            apiRequest({ path: `/webcare-pro-security/v1/scan/history/${currentScanId}` })
              .then((res: any) => {
                if (res?.success) {
                  setSelectedScanDetail((prev: any) => {
                    if (!prev || prev.scan?.id !== currentScanId) return prev;
                    return {
                      ...prev,
                      scan: res.scan,
                      summary: res.summary,
                      issues: res.issues || [],
                      files_count: res.files_count || 0,
                      diagnostics: res.diagnostics || res.scan?.diagnostics,
                    };
                  });
                }
              })
              .catch((err) => console.error('Silent scan history sync failed', err));
          }
        }}
        onAiAnalyze={handleAiAnalyzeCode}
      />

      {/* Whitelist & False-Positive Cryptographic Hash-Locking Modal */}
      <DisableWpDebugModal
        isOpen={wpDebugModal.isOpen}
        issue={wpDebugModal.issue}
        onClose={() => setWpDebugModal({ isOpen: false, issue: null })}
        onConfirm={executeDisableWpDebug}
        isLoading={disablingWpDebug}
      />

      <WhitelistModal
        isOpen={whitelistModal.isOpen}
        issue={whitelistModal.issue}
        onClose={() => setWhitelistModal({ isOpen: false, issue: null })}
        onSuccess={() => {
          if (whitelistModal.issue?.id) {
            const targetId = whitelistModal.issue.id;
            const isMatch = (item: any) => String(item.id) === String(targetId);
            setIssues((prev) =>
              prev.map((i) => (isMatch(i) ? { ...i, status: 'ignored', is_whitelisted: true } : i))
            );
            if (targetedResult) {
              setTargetedResult((prev) =>
                prev
                  ? {
                      ...prev,
                      issues: prev.issues.map((i) => (isMatch(i) ? { ...i, status: 'ignored', is_whitelisted: true } : i)),
                    }
                  : null
              );
            }
            setSelectedScanDetail((prev) =>
              prev
                ? {
                    ...prev,
                    issues: prev.issues.map((i) => (isMatch(i) ? { ...i, status: 'ignored', is_whitelisted: true } : i)),
                  }
                : null
            );
          }
          loadLatestScan();
          loadScanHistory();
        }}
        apiRequest={apiRequest}
      />

      {/* First-Time 3D Aesthetic Welcome & Pre-Flight System Readiness Modal */}
      <WelcomeModal
        isOpen={isWelcomeModalOpen}
        onClose={() => setIsWelcomeModalOpen(false)}
        onStartScan={() => {
          setIsWelcomeModalOpen(false);
          handleStartScan('plugins_themes');
        }}
      />

      {/* Wordfence-Style Custom Scan Engine Selector Modal */}
      <CustomScanModal
        isOpen={isCustomScanModalOpen}
        onClose={() => setIsCustomScanModalOpen(false)}
        options={customScanOptions}
        onOptionsChange={(newOpts) => setCustomScanOptions(newOpts)}
        onStartScan={(optionsToRun, saveDefault) => {
          setCustomScanOptions(optionsToRun);
          setScanTarget('custom');
          if (saveDefault) {
            handleSaveCustomScanPreferences(optionsToRun);
          }
          handleStartScan('custom', optionsToRun);
        }}
        isScanning={scanning}
        onSavePreferences={handleSaveCustomScanPreferences}
      />

      {/* Global In-App Confirm Dialog */}
      <ConfirmDialog
        isOpen={confirmModal.isOpen}
        title={confirmModal.title}
        message={confirmModal.message}
        targetItem={confirmModal.targetItem}
        confirmLabel={confirmModal.confirmLabel}
        variant={confirmModal.variant}
        isLoading={confirmModal.isLoading}
        onConfirm={confirmModal.onConfirm || (() => {})}
        onClose={() => setConfirmModal((prev) => ({ ...prev, isOpen: false }))}
      />

      {/* Global In-App Floating Toast Notification */}
      {globalToast && (
        <div
          style={{
            position: 'fixed',
            top: '40px',
            right: '25px',
            zIndex: 99999999,
            padding: '12px 18px',
            borderRadius: '10px',
            background:
              globalToast.type === 'success'
                ? '#ecfdf5'
                : globalToast.type === 'error'
                ? '#fef2f2'
                : '#eff6ff',
            border: `1px solid ${
              globalToast.type === 'success'
                ? '#a7f3d0'
                : globalToast.type === 'error'
                ? '#fecaca'
                : '#bfdbfe'
            }`,
            color:
              globalToast.type === 'success'
                ? '#065f46'
                : globalToast.type === 'error'
                ? '#991b1b'
                : '#1e40af',
            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.25)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '13px',
            fontWeight: 600,
            maxWidth: '420px',
            animation: 'webcareModalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        >
          {globalToast.type === 'success' ? (
            <CheckCircle2 size={18} color="#059669" />
          ) : globalToast.type === 'error' ? (
            <AlertCircle size={18} color="#dc2626" />
          ) : (
            <ShieldAlert size={18} color="#2563eb" />
          )}
          <span style={{ flex: 1, minWidth: 0, wordBreak: 'break-word' }}>
            {globalToast.message}
          </span>
          <button
            type="button"
            onClick={() => setGlobalToast(null)}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'inherit',
              padding: '2px',
              display: 'flex',
              alignItems: 'center',
              opacity: 0.7,
            }}
          >
            <X size={15} />
          </button>
        </div>
      )}

      {/* Global Command Center / All Modules Mega-Menu */}
      <MegaMenuModal
        isOpen={megaMenuOpen}
        onClose={() => setMegaMenuOpen(false)}
        onNavigate={handleNavTabChange}
        currentTab={navTab}
      />

      {/* 1-Click Fix My Site Rescue Assistant Modal */}
      <RescueAssistantModal
        isOpen={rescueModalOpen}
        onClose={() => setRescueModalOpen(false)}
        onPauseChange={(ps) => setRescuePaused(Boolean(ps?.paused))}
      />
    </div>
  );
};

export default App;
