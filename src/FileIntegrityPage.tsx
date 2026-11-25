import { useState, useEffect, useRef, Fragment } from '@wordpress/element';
import {
  FileCode,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  RefreshCw,
  Search,
  Filter,
  Eye,
  X,
  Copy,
  Check,
  ExternalLink,
  RotateCcw,
  Sparkles,
  History,
  Undo2,
  FileWarning,
  Layers,
  Wand2,
  ArrowRight,
  Lock,
  SlidersHorizontal,
  Columns,
  CheckCircle2,
  AlertOctagon,
  Info,
  Hash,
  User,
  Tag,
  ChevronDown,
  CheckSquare,
  Square
} from 'lucide-react';
import VisualDiffModal from './VisualDiffModal';
import FilesystemPermissionHardeningCard from './components/FilesystemPermissionHardeningCard';
import { ConfirmDialog } from './components/ConfirmDialog';
import { formatRelativeTime } from './timeUtils';
import { toast } from './utils/dialog';

interface ChangeItem {
  file_path: string;
  relative_path: string;
  filename: string;
  category: string;
  mtime: number;
  modified_human: string;
  modified_iso: string;
  size: number;
  size_formatted: string;
  severity: 'critical' | 'high' | 'info' | 'clean';
  is_suspicious: boolean;
  is_verified_clean?: boolean;
  risk_reason: string;
  component_name?: string;
  component_slug?: string;
  component_type?: string;
  installed_version?: string | null;
  latest_version?: string | null;
  is_update_available?: boolean;
  integrity_status?: 'verified_clean' | 'modified' | 'rogue_file' | 'safe_config' | 'custom_component' | 'suspicious_executable' | 'unverified';
  file_permissions?: string;
  file_owner?: string;
  file_hash?: string;
  can_auto_cure?: boolean;
  can_diff?: boolean;
}

export interface FimColumnDef {
  id: string;
  label: string;
  description: string;
  defaultVisible: boolean;
  minWidth?: string;
  align?: 'left' | 'right' | 'center';
}

export const FIM_AVAILABLE_COLUMNS: FimColumnDef[] = [
  { id: 'severity', label: 'Severity', description: 'Threat severity level (Critical, High, Clean, Info)', defaultVisible: true, minWidth: '95px' },
  { id: 'integrity_status', label: 'Integrity Status', description: 'Bit-for-bit official WP.org baseline status', defaultVisible: true, minWidth: '175px' },
  { id: 'file_location', label: 'File Location & Scope', description: 'Server relative file path and audit notice', defaultVisible: true, minWidth: '280px' },
  { id: 'scope', label: 'Scope', description: 'WordPress core, plugins, themes, uploads, config', defaultVisible: true, minWidth: '90px' },
  { id: 'component_name', label: 'Plugin / Theme Name', description: 'Installed component display name', defaultVisible: true, minWidth: '160px' },
  { id: 'installed_version', label: 'Installed Version', description: 'Currently installed plugin/theme version', defaultVisible: true, minWidth: '110px' },
  { id: 'latest_version', label: 'Official Latest Version', description: 'Latest official release on WP.org', defaultVisible: true, minWidth: '135px' },
  { id: 'last_modified', label: 'Last Modified', description: 'Relative time ago & exact timestamp', defaultVisible: true, minWidth: '140px' },
  { id: 'file_size', label: 'File Size', description: 'File size on disk', defaultVisible: true, minWidth: '90px' },
  { id: 'file_permissions', label: 'File Permissions', description: 'Octal permissions (e.g. 0644, 0755)', defaultVisible: false, minWidth: '100px' },
  { id: 'file_owner', label: 'Owner & Group', description: 'OS user and group (e.g. www-data)', defaultVisible: false, minWidth: '115px' },
  { id: 'file_hash', label: 'MD5 Hash', description: 'Cryptographic MD5 hash with 1-click copy', defaultVisible: false, minWidth: '120px' },
  { id: 'actions', label: 'Remediation & Diff', description: 'Visual Diff viewer & 1-Click Auto-Cure', defaultVisible: true, minWidth: '165px', align: 'right' },
];

interface FimStats {
  total_modified: number;
  core_modified: number;
  plugins_modified: number;
  themes_modified: number;
  uploads_modified: number;
  high_risk_count: number;
  timeframe_hours: number;
}

interface DiffLine {
  type: 'unchanged' | 'added' | 'removed';
  old_line: number | null;
  new_line: number | null;
  content: string;
}

interface DiffData {
  success: boolean;
  file_path: string;
  relative_path: string;
  filename: string;
  category: string;
  is_official_compared: boolean;
  official_source_url: string | null;
  message: string;
  stats: {
    additions: number;
    deletions: number;
    total_changes: number;
    local_lines: number;
  };
  diff_lines: DiffLine[];
}

interface RemediationBackup {
  id: string;
  original_path: string;
  backup_path: string;
  backup_file: string;
  action_type: string;
  created_at: string;
  size: number;
}

interface CustomComponentItem {
  slug: string;
  name: string;
  version?: string;
  author?: string;
  type: string;
  reason: string;
}

interface FimVaultStatus {
  is_calibrated: boolean;
  calibrated_at: string | null;
  calibrated_by?: string;
  last_verified_at: string | null;
  has_tamper: boolean;
  tampered_shards: string[];
  total_files: number;
  shards?: Record<string, any>;
  vault_path?: string;
}

interface SkippedCustomData {
  plugins: CustomComponentItem[];
  themes: CustomComponentItem[];
  count: number;
}

interface FileIntegrityPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  initialFilePath?: string | null;
  initialSubTab?: 'fim' | 'permissions';
  onSubTabChange?: (tab: 'fim' | 'permissions') => void;
  onNavigateToDashboard?: () => void;
}

export default function FileIntegrityPage({ apiRequest, initialFilePath, initialSubTab = 'fim', onSubTabChange, onNavigateToDashboard }: FileIntegrityPageProps) {
  const [changes, setChanges] = useState<ChangeItem[]>([]);
  const [stats, setStats] = useState<FimStats | null>(null);
  const [skippedCustom, setSkippedCustom] = useState<SkippedCustomData | null>(null);
  const [showCustomDetails, setShowCustomDetails] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [timeframe, setTimeframe] = useState<number>(48);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [integrityFilter, setIntegrityFilter] = useState<'all' | 'high_risk' | 'altered' | 'pristine' | 'unverified'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const getStartingTab = (): 'fim' | 'permissions' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const section = urlParams.get('section') || urlParams.get('subtab');
      if (section === 'permissions') return 'permissions';
      if (section === 'checksums' || section === 'fim') return 'fim';
      const tabParam = urlParams.get('tab');
      if (tabParam === 'permissions' || tabParam === 'fim' || tabParam === 'file-changes') {
        return tabParam === 'permissions' ? 'permissions' : 'fim';
      }
    } catch (e) {}
    return initialSubTab;
  };

  const [activeTab, setActiveTab] = useState<'fim' | 'permissions'>(getStartingTab);

  const handleTabChange = (tab: 'fim' | 'permissions') => {
    setActiveTab(tab);
    const sectionName = tab === 'fim' ? 'checksums' : 'permissions';
    if (onSubTabChange) {
      onSubTabChange(tab);
    } else {
      try {
        const url = new URL(window.location.href);
        const currentPage = url.searchParams.get('page') || '';
        if (currentPage === 'webcare-pro-scanner') {
          url.searchParams.set('tab', 'file-changes');
          url.searchParams.set('section', sectionName);
        } else {
          url.searchParams.set('tab', tab);
        }
        url.searchParams.delete('subtab');
        window.history.pushState({ tab, section: sectionName }, '', url.toString());
      } catch (e) {}
    }
  };

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeTab) {
      setActiveTab(initialSubTab);
    }
  }, [initialSubTab]);

  useEffect(() => {
    const handlePopState = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const section = urlParams.get('section') || urlParams.get('subtab');
        const tab = urlParams.get('tab');
        if (section === 'permissions' || tab === 'permissions') {
          setActiveTab('permissions');
        } else {
          setActiveTab('fim');
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Vault FIM Baseline State
  const [vaultStatus, setVaultStatus] = useState<FimVaultStatus | null>(null);
  const [calibratingVault, setCalibratingVault] = useState<boolean>(false);
  const [calibrationProgress, setCalibrationProgress] = useState<number>(0);
  const [calibrationPhase, setCalibrationPhase] = useState<string>('');
  const [calibrationNotice, setCalibrationNotice] = useState<{
    type: 'success' | 'error';
    title: string;
    message: string;
  } | null>(null);
  const [recheckingDrift, setRecheckingDrift] = useState<boolean>(false);
  const [driftResult, setDriftResult] = useState<any | null>(null);

  // Full WordPress page width mode for FIM
  useEffect(() => {
    const rootEl = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
    if (rootEl) {
      rootEl.classList.add('webcare-fim-fullwidth');
      return () => {
        rootEl.classList.remove('webcare-fim-fullwidth');
      };
    }
  }, []);

  // Pagination state for FIM modified files table
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);

  // In-App Confirm Dialog State
  const [fimConfirmDialog, setFimConfirmDialog] = useState<{
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

  const requestFimConfirm = ({
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
    setFimConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setFimConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setFimConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setFimConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  // Synchronized top and bottom horizontal scrollbars for wide FIM table
  const topScrollRef = useRef<HTMLDivElement | null>(null);
  const bottomScrollRef = useRef<HTMLDivElement | null>(null);
  const tableRef = useRef<HTMLTableElement | null>(null);
  const [tableScrollWidth, setTableScrollWidth] = useState<number>(0);
  const [canScrollX, setCanScrollX] = useState<boolean>(false);
  const isSyncingScroll = useRef<boolean>(false);

  const handleTopScroll = () => {
    if (isSyncingScroll.current) return;
    isSyncingScroll.current = true;
    if (bottomScrollRef.current && topScrollRef.current) {
      bottomScrollRef.current.scrollLeft = topScrollRef.current.scrollLeft;
    }
    requestAnimationFrame(() => {
      isSyncingScroll.current = false;
    });
  };

  const handleBottomScroll = () => {
    if (isSyncingScroll.current) return;
    isSyncingScroll.current = true;
    if (topScrollRef.current && bottomScrollRef.current) {
      topScrollRef.current.scrollLeft = bottomScrollRef.current.scrollLeft;
    }
    requestAnimationFrame(() => {
      isSyncingScroll.current = false;
    });
  };

  const updateTableScrollWidth = () => {
    if (bottomScrollRef.current) {
      const scrollW = tableRef.current
        ? Math.max(tableRef.current.scrollWidth, bottomScrollRef.current.scrollWidth)
        : bottomScrollRef.current.scrollWidth;
      const clientW = bottomScrollRef.current.clientWidth;
      setTableScrollWidth(scrollW);
      setCanScrollX(scrollW > clientW + 2);
    }
  };

  // Custom column selector state (persisted in localStorage)
  const [showColumnSelector, setShowColumnSelector] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const columnDropdownRef = useRef<HTMLDivElement | null>(null);

  const [visibleColumns, setVisibleColumns] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem('webcare_fim_visible_columns_v2');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (typeof parsed === 'object' && parsed !== null) {
          return parsed;
        }
      }
    } catch (e) {}
    const defaults: Record<string, boolean> = {};
    FIM_AVAILABLE_COLUMNS.forEach((col) => {
      defaults[col.id] = col.defaultVisible;
    });
    return defaults;
  });

  const activeColumnCount = FIM_AVAILABLE_COLUMNS.filter((c) => visibleColumns[c.id]).length;

  const toggleColumn = (colId: string) => {
    setVisibleColumns((prev) => {
      const updated = { ...prev, [colId]: !prev[colId] };
      try {
        localStorage.setItem('webcare_fim_visible_columns_v2', JSON.stringify(updated));
      } catch (e) {}
      return updated;
    });
  };

  const showAllColumns = () => {
    const all: Record<string, boolean> = {};
    FIM_AVAILABLE_COLUMNS.forEach((c) => {
      all[c.id] = true;
    });
    setVisibleColumns(all);
    try {
      localStorage.setItem('webcare_fim_visible_columns_v2', JSON.stringify(all));
    } catch (e) {}
  };

  const resetDefaultColumns = () => {
    const defaults: Record<string, boolean> = {};
    FIM_AVAILABLE_COLUMNS.forEach((c) => {
      defaults[c.id] = c.defaultVisible;
    });
    setVisibleColumns(defaults);
    try {
      localStorage.setItem('webcare_fim_visible_columns_v2', JSON.stringify(defaults));
    } catch (e) {}
  };

  // Click outside to close column customizer dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (columnDropdownRef.current && !columnDropdownRef.current.contains(event.target as Node)) {
        setShowColumnSelector(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Code Diff Modal state
  const [diffModalOpen, setDiffModalOpen] = useState<boolean>(false);
  const [activeDiffFilePath, setActiveDiffFilePath] = useState<string | null>(null);

  // Remediation & Auto-Cure state
  const [backupsModalOpen, setBackupsModalOpen] = useState<boolean>(false);
  const [backups, setBackups] = useState<RemediationBackup[]>([]);
  const [loadingBackups, setLoadingBackups] = useState<boolean>(false);

  // Load Vault Baseline status
  const loadVaultStatus = async () => {
    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/integrity/vault-status',
        method: 'GET',
      });
      if (res) {
        setVaultStatus(res);
      }
    } catch (err) {
      console.error('Failed to load FIM vault status', err);
    }
  };

  // Calibrate new baseline with smooth in-page progress and non-intrusive body confirmation
  const handleCalibrateVault = async () => {
    setCalibrationNotice(null);
    setCalibratingVault(true);
    setCalibrationProgress(12);
    setCalibrationPhase('Initializing isolated vault and verifying cryptographic keys...');

    // Progress simulation while scanning large file systems
    const progressTimer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setCalibrationProgress((prev) => {
        if (prev < 40) {
          setCalibrationPhase('Scanning WordPress core files and system configuration...');
          return prev + 14;
        } else if (prev < 75) {
          setCalibrationPhase('Analyzing installed plugins, themes, and code hashes...');
          return prev + 9;
        } else if (prev < 92) {
          setCalibrationPhase('Compressing shards and signing HMAC-SHA256 manifests...');
          return prev + 4;
        }
        return prev;
      });
    }, 450);

    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/integrity/calibrate-vault',
        method: 'POST',
      });
      clearInterval(progressTimer);
      setCalibrationProgress(100);
      setCalibrationPhase('Baseline calibration complete!');

      if (res && res.success) {
        setCalibrationNotice({
          type: 'success',
          title: 'Vault Baseline Successfully Calibrated',
          message: `Tracked and cryptographically sealed ${res.total_files.toLocaleString()} files across Core, Plugins, Themes, and Root Config in ${res.duration_sec}s. Subsequent FIM visits will audit drift in milliseconds.`,
        });
        await loadVaultStatus();
        await handleRecheckDrift();
      } else {
        const errorMsg = res?.message || 'Server returned an invalid response during calibration.';
        setCalibrationNotice({
          type: 'error',
          title: 'FIM Calibration Issue',
          message: errorMsg,
        });
      }
    } catch (err: any) {
      clearInterval(progressTimer);
      const rawMsg = err?.message || err?.error || 'Unknown error';
      const cleanMsg = typeof rawMsg === 'string' ? rawMsg.replace(/<[^>]*>/g, '').trim() : 'Server communication failed.';
      setCalibrationNotice({
        type: 'error',
        title: 'Error Calibrating FIM Vault',
        message: cleanMsg,
      });
    } finally {
      clearInterval(progressTimer);
      setCalibratingVault(false);
    }
  };

  // Re-check drift against baseline
  const handleRecheckDrift = async () => {
    try {
      setRecheckingDrift(true);
      const res: any = await apiRequest({
        path: `/webcare-pro-security/v1/integrity/recheck-drift?category=${categoryFilter}&limit=250`,
        method: 'POST',
      });
      if (res) {
        setDriftResult(res);
        await loadVaultStatus();
        await loadChanges();
      }
    } catch (err) {
      console.error('Failed to audit FIM drift', err);
    } finally {
      setRecheckingDrift(false);
    }
  };

  // Load changes
  const loadChanges = async (hours = timeframe, category = categoryFilter) => {
    try {
      setLoading(true);
      const res: any = await apiRequest({
        path: `/webcare-pro-security/v1/integrity/recent-changes?hours=${hours}&category=${category}&limit=200`,
        method: 'GET',
      });

      if (res && res.changes) {
        setChanges(res.changes);
        if (res.stats) {
          setStats((prev) => ({ ...prev, ...res.stats }));
        }
        if (res.skipped_custom) {
          setSkippedCustom(res.skipped_custom);
        }
      }
    } catch (err) {
      console.error('Failed to load FIM recent changes', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVaultStatus();
  }, []);

  useEffect(() => {
    loadChanges(timeframe, categoryFilter);
  }, [timeframe, categoryFilter]);

  // Open diff modal if initialFilePath provided
  useEffect(() => {
    if (initialFilePath) {
      handleOpenDiff(initialFilePath);
    }
  }, [initialFilePath]);

  const handleOpenDiff = (filePath: string) => {
    setActiveDiffFilePath(filePath);
    setDiffModalOpen(true);
  };

  // Load backups list
  const loadBackups = async () => {
    setBackupsModalOpen(true);
    setLoadingBackups(true);
    try {
      const res: any = await apiRequest({
        path: '/webcare-pro-security/v1/remediation/backups',
        method: 'GET',
      });
      if (res && res.backups) {
        setBackups(res.backups);
      }
    } catch (err) {
      console.error('Failed to load remediation backups', err);
    } finally {
      setLoadingBackups(false);
    }
  };

  // Rollback backup
  const handleRollback = async (backupId: string, filename: string) => {
    requestFimConfirm({
      title: 'Rollback Remediation Action',
      message: 'Are you sure you want to revert this remediation action and restore the file from backup? Restoring will revert changes using the safety snapshot retained in WebCare Vault for 14 days.',
      targetItem: filename,
      confirmLabel: 'Rollback File',
      variant: 'warning',
      onConfirm: async () => {
        try {
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/rollback',
            method: 'POST',
            data: { backup_id: backupId },
          });
          if (res && res.success) {
            toast.success(res.message || 'Remediation rolled back successfully!');
            loadBackups();
            loadChanges();
          } else {
            toast.error(res?.message || 'Rollback failed.');
          }
        } catch (err: any) {
          toast.error(err?.message || 'Error during rollback.');
        }
      },
    });
  };

  const [remediating, setRemediating] = useState<boolean>(false);

  // 1-Click Auto-Cure for plugin files directly from FIM list
  const handleAutoCurePlugin = async (filePath: string) => {
    requestFimConfirm({
      title: 'Auto-Cure Plugin File',
      message: 'Are you sure you want to restore this file from the official WordPress.org release? An automated safety snapshot backup is retained in WebCare Vault for 14 days, allowing 1-click rollback at any time.',
      targetItem: filePath,
      confirmLabel: 'Restore Official Release',
      variant: 'primary',
      onConfirm: async () => {
        setRemediating(true);
        try {
          const res: any = await apiRequest({
            path: '/webcare-pro-security/v1/remediation/restore-plugin',
            method: 'POST',
            data: { file_path: filePath },
          });
          if (res && res.success) {
            toast.success(res.message || 'File successfully restored from official WordPress.org release!');
            loadChanges();
          } else {
            toast.error(res?.message || 'Auto-cure failed.');
          }
        } catch (err: any) {
          console.error(err);
          toast.error(err?.message || 'Auto-cure failed.');
        } finally {
          setRemediating(false);
        }
      },
    });
  };

  const filteredChanges = changes.filter((item) => {
    // Integrity status filter
    if (integrityFilter === 'high_risk') {
      if (item.severity !== 'high' && item.severity !== 'critical') {
        return false;
      }
    } else if (integrityFilter === 'altered') {
      if (item.integrity_status !== 'modified' && item.integrity_status !== 'rogue_file' && item.integrity_status !== 'suspicious_executable' && !item.is_suspicious) {
        return false;
      }
    } else if (integrityFilter === 'pristine') {
      if (item.integrity_status !== 'verified_clean' && !item.is_verified_clean) {
        return false;
      }
    } else if (integrityFilter === 'unverified') {
      if (item.integrity_status === 'verified_clean' || item.integrity_status === 'modified' || item.integrity_status === 'rogue_file') {
        return false;
      }
    }

    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.relative_path.toLowerCase().includes(q) ||
      item.filename.toLowerCase().includes(q) ||
      item.risk_reason.toLowerCase().includes(q) ||
      (item.component_name && item.component_name.toLowerCase().includes(q)) ||
      (item.component_slug && item.component_slug.toLowerCase().includes(q)) ||
      (item.installed_version && item.installed_version.toLowerCase().includes(q)) ||
      (item.latest_version && item.latest_version.toLowerCase().includes(q)) ||
      (item.file_permissions && item.file_permissions.toLowerCase().includes(q)) ||
      (item.file_owner && item.file_owner.toLowerCase().includes(q)) ||
      (item.file_hash && item.file_hash.toLowerCase().includes(q))
    );
  });

  // Calculate pagination
  const totalPages = pageSize === -1 ? 1 : Math.max(1, Math.ceil(filteredChanges.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const paginatedChanges = pageSize === -1
    ? filteredChanges
    : filteredChanges.slice((safeCurrentPage - 1) * pageSize, safeCurrentPage * pageSize);

  // Monitor table width and synchronization when columns, data, or window dimensions change
  useEffect(() => {
    updateTableScrollWidth();
    const handleResize = () => updateTableScrollWidth();
    window.addEventListener('resize', handleResize);

    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && bottomScrollRef.current) {
      observer = new ResizeObserver(() => {
        updateTableScrollWidth();
      });
      observer.observe(bottomScrollRef.current);
      if (tableRef.current) {
        observer.observe(tableRef.current);
      }
    }

    const timer = setTimeout(updateTableScrollWidth, 100);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (observer) {
        observer.disconnect();
      }
      clearTimeout(timer);
    };
  }, [visibleColumns, paginatedChanges, loading, activeTab]);

  return (
    <div className="webcare-page-container webcare-fim-container" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Header Card */}
      <div
        className="webcare-card"
        style={{
          borderRadius: '12px',
          padding: '24px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="webcare-badge-clean">
                {activeTab === 'fim' ? 'File Integrity Engine' : 'Filesystem Compliance'}
              </span>
              <h2 style={{ margin: 0, fontSize: '22px', fontWeight: 700 }}>
                {activeTab === 'fim' ? 'File Integrity (FIM) & One-Click Auto-Cure' : 'Filesystem Permissions & Ownership Auditor'}
              </h2>
            </div>
            {activeTab === 'fim' ? (
              <p style={{ margin: '8px 0 0 0', fontSize: '14px', maxWidth: '750px', lineHeight: 1.5 }}>
                Detects newly modified, created, or injected files across WordPress Core, Plugins, Themes, and Uploads.
                Inspect line-by-line visual diffs against official WordPress.org mirrors and apply <strong>1-Click Auto-Cure</strong> to neutralize webshell headers or restore authentic plugin releases with automated safety rollback.
              </p>
            ) : (
              <p style={{ margin: '8px 0 0 0', fontSize: '14px', maxWidth: '750px', lineHeight: 1.5 }}>
                Automated compliance engine to enforce WordPress standard directory permissions (<code>0755</code> or <code>0750</code>) and file permissions (<code>0644</code>). Identifies foreign-owned files and generates copy-paste SysAdmin shell scripts.
              </p>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {onNavigateToDashboard && (
              <button
                type="button"
                className="webcare-btn-secondary"
                onClick={onNavigateToDashboard}
              >
                ← Back to Scanner Dashboard
              </button>
            )}
            {activeTab === 'fim' && (
              <>
                {/* Remediation Vault History Button */}
                <button
                  type="button"
                  className="webcare-btn webcare-fim-btn-vault"
                  onClick={loadBackups}
                >
                  <History size={14} color="#059669" />
                  Auto-Cure Vault Backups
                </button>

                {/* Timeframe selector */}
                <div className="webcare-fim-timeframe-wrap">
                  {[
                    { label: '24h', val: 24 },
                    { label: '48h', val: 48 },
                    { label: '7 Days', val: 168 },
                    { label: '30 Days', val: 720 },
                  ].map((tf) => (
                    <button
                      key={tf.val}
                      type="button"
                      onClick={() => setTimeframe(tf.val)}
                      className={`webcare-fim-timeframe-btn ${timeframe === tf.val ? 'is-active' : ''}`}
                    >
                      {tf.label}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  className="webcare-btn webcare-fim-btn-refresh"
                  onClick={() => loadChanges()}
                  disabled={loading}
                >
                  <RefreshCw size={14} className={loading ? 'webcare-spin-icon' : ''} />
                  {loading ? 'Auditing...' : 'Refresh'}
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Primary Tab Navigation */}
      <div className="webcare-tabs-bar">
        <button
          type="button"
          className={`webcare-tab-link ${activeTab === 'fim' ? 'is-active' : ''}`}
          onClick={() => handleTabChange('fim')}
        >
          <FileCode size={18} />
          <span>File Integrity Monitoring (FIM)</span>
          {stats && stats.total_modified > 0 && (
            <span
              style={{
                background: stats.high_risk_count > 0 ? '#fee2e2' : '#e0f2fe',
                color: stats.high_risk_count > 0 ? '#dc2626' : '#0369a1',
                fontSize: '11px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '9999px',
              }}
            >
              {stats.total_modified}
            </span>
          )}
        </button>

        <button
          type="button"
          className={`webcare-tab-link ${activeTab === 'permissions' ? 'is-active' : ''}`}
          onClick={() => handleTabChange('permissions')}
        >
          <Lock size={18} />
          <span>Filesystem Permissions & Ownership</span>
        </button>
      </div>

      {activeTab === 'fim' && (
        <>
          {/* Anti-Tamper Security Alarm (Triggers if HMAC Attestation Fails) */}
          {vaultStatus?.has_tamper && (
            <div
              className="webcare-card"
              style={{
                background: '#fef2f2',
                border: '2px solid #ef4444',
                borderRadius: '12px',
                padding: '16px 20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '14px',
                boxShadow: '0 4px 12px rgba(239, 68, 68, 0.15)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '10px',
                  background: '#dc2626',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}>
                  <AlertOctagon size={24} />
                </div>
                <div>
                  <strong style={{ fontSize: '15px', color: '#991b1b', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    CRITICAL SECURITY ALERT: Vault FIM Baseline Manifest Altered Outside Plugin!
                  </strong>
                  <div style={{ fontSize: '12.5px', color: '#b91c1c', marginTop: '3px', lineHeight: 1.45 }}>
                    Cryptographic HMAC-SHA256 attestation mismatch on shard(s): <code>{vaultStatus.tampered_shards?.join(', ') || 'manifest'}</code>.
                    An attacker or unauthorized process attempted to forge or edit the trusted baseline file. Please re-calibrate immediately.
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="webcare-btn"
                onClick={handleCalibrateVault}
                disabled={calibratingVault}
                style={{
                  background: '#dc2626',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontWeight: 700,
                  fontSize: '12px',
                  cursor: 'pointer'
                }}
              >
                {calibratingVault ? 'Sealing New Baseline...' : 'Re-Calibrate & Seal Vault Now'}
              </button>
            </div>
          )}

          {/* In-Page Calibration Progress Bar */}
          {calibratingVault && (
            <div
              className="webcare-card"
              style={{
                borderRadius: '12px',
                padding: '20px 24px',
                background: 'var(--webcare-bg-surface, #ffffff)',
                border: '1px solid #6366f1',
                boxShadow: '0 4px 16px rgba(99, 102, 241, 0.12)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div
                    style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '8px',
                      background: 'rgba(99, 102, 241, 0.14)',
                      color: '#4f46e5',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <RefreshCw size={18} className="webcare-spin-icon" />
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      Calibrating & Sealing FIM Vault Baseline...
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                      {calibrationPhase}
                    </div>
                  </div>
                </div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#4f46e5' }}>
                  {calibrationProgress}%
                </div>
              </div>

              {/* Progress track */}
              <div
                style={{
                  width: '100%',
                  height: '8px',
                  background: 'var(--webcare-border-subtle, #e2e8f0)',
                  borderRadius: '9999px',
                  overflow: 'hidden',
                  position: 'relative'
                }}
              >
                <div
                  style={{
                    height: '100%',
                    width: `${calibrationProgress}%`,
                    background: 'linear-gradient(90deg, #6366f1 0%, #10b981 100%)',
                    borderRadius: '9999px',
                    transition: 'width 0.35s ease'
                  }}
                />
              </div>

              <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)', display: 'flex', justifyContent: 'space-between' }}>
                <span>Throttled execution (max 60% PHP memory limit). Large sites with 50k+ files will complete smoothly.</span>
                <span>Cryptographic HMAC-SHA256</span>
              </div>
            </div>
          )}

          {/* In-Page Confirmation Banner */}
          {calibrationNotice && (
            <div
              className="webcare-card"
              style={{
                borderRadius: '12px',
                padding: '16px 20px',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: '16px',
                background: calibrationNotice.type === 'success' ? '#f0fdf4' : '#fef2f2',
                border: calibrationNotice.type === 'success' ? '1px solid #86efac' : '1px solid #fca5a5',
                boxShadow: calibrationNotice.type === 'success' ? '0 2px 10px rgba(16, 185, 129, 0.1)' : '0 2px 10px rgba(239, 68, 68, 0.1)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: calibrationNotice.type === 'success' ? '#10b981' : '#dc2626',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0
                  }}
                >
                  {calibrationNotice.type === 'success' ? <CheckCircle2 size={20} /> : <AlertOctagon size={20} />}
                </div>
                <div>
                  <div
                    style={{
                      fontSize: '14.5px',
                      fontWeight: 700,
                      color: calibrationNotice.type === 'success' ? '#15803d' : '#b91c1c'
                    }}
                  >
                    {calibrationNotice.title}
                  </div>
                  <div
                    style={{
                      fontSize: '12.5px',
                      color: calibrationNotice.type === 'success' ? '#166534' : '#991b1b',
                      marginTop: '4px',
                      lineHeight: 1.5
                    }}
                  >
                    {calibrationNotice.message}
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCalibrationNotice(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '4px',
                  borderRadius: '6px',
                  color: calibrationNotice.type === 'success' ? '#166534' : '#991b1b',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
                title="Dismiss message"
              >
                <X size={18} />
              </button>
            </div>
          )}

          {/* FIM Vault Baseline Attestation Card */}
          <div
            className="webcare-card"
            style={{
              borderRadius: '12px',
              padding: '18px 22px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px',
              borderLeft: vaultStatus?.is_calibrated ? '4px solid #10b981' : '4px solid #f59e0b'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', maxWidth: '750px' }}>
              <div style={{
                width: '44px',
                height: '44px',
                borderRadius: '10px',
                background: vaultStatus?.is_calibrated ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                color: vaultStatus?.is_calibrated ? '#10b981' : '#f59e0b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <ShieldCheck size={24} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '14px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Vault FIM Baseline: {vaultStatus?.is_calibrated ? 'Active & Sealed (HMAC Authenticated)' : 'Baseline Not Calibrated'}
                  </strong>
                  <span className={vaultStatus?.is_calibrated ? 'webcare-smart-shield-pill-detected-emerald' : 'webcare-smart-shield-pill-empty'}>
                    {vaultStatus?.is_calibrated ? `${vaultStatus.total_files.toLocaleString()} Files Tracked in Vault` : 'Zero Files Cached'}
                  </span>
                  {vaultStatus?.last_verified_at && (
                    <span className="webcare-smart-shield-pill-detected-sky">
                      Last Verified: {vaultStatus.last_verified_at} ({formatRelativeTime(vaultStatus.last_verified_at)})
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px', lineHeight: 1.45 }}>
                  Cryptographically captures full filesystem metadata (Path, Permissions, Owner, Group, Inode Ctime, Mtime, and SHA-256 Hashes) into isolated gzip shards. Detects instant drift in under ~200ms without heavy database queries or CPU spikes.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="webcare-btn webcare-firewall-rule-card"
                onClick={handleRecheckDrift}
                disabled={recheckingDrift || !vaultStatus?.is_calibrated}
                style={{
                  padding: '8px 16px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: !vaultStatus?.is_calibrated ? 'not-allowed' : 'pointer'
                }}
                title={vaultStatus?.is_calibrated ? 'Audit current disk state against sealed Vault baseline' : 'Calibrate baseline first'}
              >
                <RefreshCw size={14} className={recheckingDrift ? 'webcare-spin-icon' : ''} />
                {recheckingDrift ? 'Auditing Drift (~0.2s)...' : 'Re-Check Files (Drift Audit)'}
              </button>

              <button
                type="button"
                className="webcare-btn"
                onClick={handleCalibrateVault}
                disabled={calibratingVault}
                style={{
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '12.5px',
                  fontWeight: 700,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                  boxShadow: '0 2px 6px rgba(16, 185, 129, 0.25)'
                }}
              >
                <Sparkles size={14} />
                {calibratingVault ? 'Scanning & Sealing Vault...' : (vaultStatus?.is_calibrated ? 'Update / Recalibrate Baseline' : 'Calibrate Known-Good Baseline')}
              </button>
            </div>
          </div>
        </>
      )}

      {activeTab === 'fim' ? (
        <>
          {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        {/* Metric 1 */}
        <div className="webcare-stat-box webcare-fim-metric-card">
          <div className="webcare-fim-metric-icon webcare-fim-icon-cyan">
            <Clock size={22} />
          </div>
          <div>
            <div className="webcare-fim-metric-label">
              Files Changed ({timeframe}h)
            </div>
            <div className="webcare-fim-metric-value">
              {stats ? stats.total_modified : '...'}
            </div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="webcare-stat-box webcare-fim-metric-card">
          <div className={`webcare-fim-metric-icon ${stats && stats.core_modified > 0 ? 'webcare-fim-icon-red' : 'webcare-fim-icon-green'}`}>
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="webcare-fim-metric-label">
              Core Files Altered
            </div>
            <div
              className="webcare-fim-metric-value"
              style={{ color: stats && stats.core_modified > 0 ? 'var(--webcare-status-critical, #dc2626)' : undefined }}
            >
              {stats ? stats.core_modified : '...'}
            </div>
          </div>
        </div>

        {/* Metric 3 — Clickable High-Risk Alterations KPI */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => {
            setCategoryFilter('all');
            setIntegrityFilter('high_risk');
            setCurrentPage(1);
            tableRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              setCategoryFilter('all');
              setIntegrityFilter('high_risk');
              setCurrentPage(1);
              tableRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }}
          className="webcare-stat-box webcare-fim-metric-card"
          title="Click to filter table to High-Risk Alterations only"
          style={{
            cursor: 'pointer',
            outline: integrityFilter === 'high_risk' ? '2px solid #e11d48' : undefined,
            outlineOffset: integrityFilter === 'high_risk' ? '-2px' : undefined,
          }}
        >
          <div className={`webcare-fim-metric-icon ${stats && stats.high_risk_count > 0 ? 'webcare-fim-icon-rose' : 'webcare-fim-icon-green'}`}>
            <AlertTriangle size={22} />
          </div>
          <div>
            <div className="webcare-fim-metric-label">
              High-Risk Alterations
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <div
                className="webcare-fim-metric-value"
                style={{ color: stats && stats.high_risk_count > 0 ? 'var(--webcare-status-high, #e11d48)' : undefined }}
              >
                {stats ? stats.high_risk_count : '...'}
              </div>
              {stats && stats.high_risk_count > 0 && (
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#e11d48' }}>
                  View →
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="webcare-stat-box webcare-fim-metric-card">
          <div className="webcare-fim-metric-icon webcare-fim-icon-blue">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="webcare-fim-metric-label">
              Remediation Engine
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
              <span style={{ color: 'var(--webcare-status-clean, #16a34a)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Check size={14} /> Auto-Cure Ready
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Custom & Premium Components Notice */}
      {skippedCustom && skippedCustom.count > 0 && (
        <div
          className="webcare-card"
          style={{
            background: '#ffffff',
            border: '1px solid #e2e8f0',
            borderLeft: '4px solid #0284c7',
            borderRadius: '10px',
            padding: '14px 18px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div
                style={{
                  background: '#f0f9ff',
                  color: '#0284c7',
                  width: '34px',
                  height: '34px',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Sparkles size={18} />
              </div>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
                  Custom & Premium Components Detected ({skippedCustom.count})
                </div>
                <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
                  Skipped from WP.org repository integrity verification since official baseline checksums are not hosted on WordPress.org.
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowCustomDetails(!showCustomDetails)}
              style={{
                background: showCustomDetails ? '#e2e8f0' : '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '6px',
                padding: '5px 12px',
                fontSize: '12px',
                fontWeight: 600,
                color: '#334155',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {showCustomDetails ? 'Hide Components ▲' : `View ${skippedCustom.count} Components ▼`}
            </button>
          </div>

          {showCustomDetails && (
            <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid #f1f5f9' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {skippedCustom.plugins.map((p) => (
                  <div
                    key={p.slug}
                    style={{
                      background: '#f8fafc',
                      border: '1px solid #e2e8f0',
                      borderRadius: '6px',
                      padding: '6px 12px',
                      fontSize: '12px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <span
                      style={{
                        background: p.type === 'premium' ? '#ecfdf5' : '#eff6ff',
                        color: p.type === 'premium' ? '#059669' : '#2563eb',
                        fontWeight: 700,
                        fontSize: '10px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.3px',
                      }}
                    >
                      {p.type === 'premium' ? 'Commercial' : 'Custom'} Plugin
                    </span>
                    <strong style={{ color: '#0f172a' }}>{p.name}</strong>
                    {p.version && <span style={{ color: '#64748b' }}>v{p.version}</span>}
                    <span style={{ fontSize: '11px', color: '#94a3b8' }}>({p.reason})</span>
                  </div>
                ))}

                {skippedCustom.themes.map((t) => (
                  <div
                    key={t.slug}
                    style={{
                      background: '#f8fafc',
                      border: '1px solid #e2e8f0',
                      borderRadius: '6px',
                      padding: '6px 12px',
                      fontSize: '12px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <span
                      style={{
                        background: '#faf5ff',
                        color: '#7c3aed',
                        fontWeight: 700,
                        fontSize: '10px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.3px',
                      }}
                    >
                      {t.type === 'child_theme' ? 'Child Theme' : 'Custom Theme'}
                    </span>
                    <strong style={{ color: '#0f172a' }}>{t.name}</strong>
                    {t.version && <span style={{ color: '#64748b' }}>v{t.version}</span>}
                    <span style={{ fontSize: '11px', color: '#94a3b8' }}>({t.reason})</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filter Tabs & Search Bar */}
      <div className="webcare-card webcare-fim-filter-card webcare-overflow-visible">
        {/* Category Tabs */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {[
            { id: 'all', label: 'All Scopes' },
            { id: 'core', label: `Core (${stats ? stats.core_modified : 0})` },
            { id: 'plugins', label: `Plugins (${stats ? stats.plugins_modified : 0})` },
            { id: 'themes', label: `Themes (${stats ? stats.themes_modified : 0})` },
            { id: 'uploads', label: `Uploads (${stats ? stats.uploads_modified : 0})` },
            { id: 'config', label: 'Config / Environment' },
          ].map((cat) => (
            <button
              key={cat.id}
              type="button"
              className={`webcare-fim-scope-btn ${categoryFilter === cat.id ? 'is-active' : ''}`}
              onClick={() => setCategoryFilter(cat.id)}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Search & Column Customizer Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', minWidth: '260px' }}>
            <Search size={15} style={{ position: 'absolute', left: '10px', top: '9px', color: '#94a3b8' }} />
            <input
              type="text"
              placeholder="Filter by filename, plugin, version, hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="webcare-fim-search-input"
            />
          </div>

          {/* Customize Columns Dropdown Button */}
          <div style={{ position: 'relative', zIndex: 110 }} ref={columnDropdownRef}>
            <button
              type="button"
              onClick={() => setShowColumnSelector(!showColumnSelector)}
              className={`webcare-fim-columns-btn ${showColumnSelector ? 'is-open' : ''}`}
              title="Select which columns to display in the FIM table"
            >
              <SlidersHorizontal size={14} />
              <span>Columns ({activeColumnCount}/{FIM_AVAILABLE_COLUMNS.length})</span>
            </button>

            {/* Floating Columns Selector Dropdown */}
            {showColumnSelector && (
              <div className="webcare-fim-columns-dropdown">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', paddingBottom: '10px', borderBottom: '1px solid var(--webcare-border-subtle, #f1f5f9)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Columns size={15} color="var(--webcare-primary, #0284c7)" />
                    <strong className="webcare-fim-dropdown-title">Display Columns</strong>
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      type="button"
                      onClick={showAllColumns}
                      className="webcare-fim-dropdown-link"
                    >
                      Show All
                    </button>
                    <span style={{ color: '#cbd5e1' }}>•</span>
                    <button
                      type="button"
                      onClick={resetDefaultColumns}
                      className="webcare-fim-dropdown-link"
                      style={{ color: '#94a3b8' }}
                    >
                      Reset Defaults
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '360px', overflowY: 'auto', paddingRight: '4px' }}>
                  {FIM_AVAILABLE_COLUMNS.map((col) => {
                    const isChecked = !!visibleColumns[col.id];
                    return (
                      <label
                        key={col.id}
                        className={`webcare-fim-column-label ${isChecked ? 'is-checked' : ''}`}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => toggleColumn(col.id)}
                            style={{ accentColor: '#4f46e5', cursor: 'pointer' }}
                          />
                          <span className="webcare-fim-column-text">
                            {col.label}
                          </span>
                        </div>
                        {col.defaultVisible ? (
                          <span style={{ fontSize: '10px', color: '#94a3b8' }}>Default</span>
                        ) : (
                          <span style={{ fontSize: '10px', color: '#8b5cf6', background: 'rgba(139, 92, 246, 0.12)', padding: '1px 5px', borderRadius: '3px', fontWeight: 600 }}>Dev</span>
                        )}
                      </label>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Secondary Filter: Integrity Status Quick Pills */}
        <div style={{ width: '100%', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', paddingTop: '10px', borderTop: '1px solid var(--webcare-border-subtle, #f1f5f9)' }}>
          <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Integrity State:</span>
          {[
            { id: 'all', label: 'All Files' },
            { id: 'high_risk', label: `High-Risk Only (${stats ? stats.high_risk_count : 0})`, color: '#e11d48' },
            { id: 'altered', label: 'Altered / Tampered Only', color: '#ef4444' },
            { id: 'pristine', label: 'Official Matches (Pristine)', color: '#10b981' },
            { id: 'unverified', label: 'Custom / Unverified', color: '#8b5cf6' },
          ].map((filter) => (
            <button
              key={filter.id}
              type="button"
              onClick={() => setIntegrityFilter(filter.id as any)}
              className={`webcare-fim-status-pill ${integrityFilter === filter.id ? 'is-active' : ''}`}
              style={{
                backgroundColor: integrityFilter === filter.id ? (filter.color || '#4f46e5') : undefined,
                color: integrityFilter === filter.id ? '#ffffff' : undefined,
              }}
            >
              {filter.label}
            </button>
          ))}
        </div>
      </div>

      {/* Changes Table Card */}
      <div
        className="webcare-card webcare-fim-table-card"
        style={{
          borderRadius: '10px',
          overflow: 'hidden',
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* Table Header Bar */}
        <div className="webcare-fim-table-toolbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <div className="webcare-fim-table-title">
              <span>Recently Modified Files</span>
              <span className="webcare-fim-count-pill">
                {filteredChanges.length}
              </span>
            </div>
            <span className="webcare-fim-divider">•</span>
            <span className="webcare-fim-timeframe-note">
              Showing files altered within the last <strong>{timeframe} hours</strong>
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            {/* Page Size Switcher */}
            <div className="webcare-fim-pagesize-wrap">
              <span>Show:</span>
              {[25, 50, 100, -1].map((size) => (
                <button
                  key={size}
                  type="button"
                  onClick={() => setPageSize(size)}
                  className={`webcare-fim-pagesize-btn ${pageSize === size ? 'active' : ''}`}
                >
                  {size === -1 ? 'All' : size}
                </button>
              ))}
            </div>

            {/* Clear Filter button if searching */}
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="webcare-fim-clear-search-btn"
              >
                <X size={12} /> Clear Search
              </button>
            )}
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: '#64748b' }}>
            <RefreshCw size={32} className="webcare-spin-icon" style={{ margin: '0 auto 12px auto', color: '#0284c7' }} />
            <div>Auditing filesystem integrity and modification records...</div>
          </div>
        ) : filteredChanges.length === 0 ? (
          <div className="webcare-empty-state-clean">
            <div className="webcare-empty-state-icon-wrap">
              <ShieldCheck size={34} />
            </div>
            <h4 className="webcare-empty-state-title">
              Core & Component Files 100% Intact
            </h4>
            <p className="webcare-empty-state-desc">
              No files were altered or created within the selected {timeframe}-hour audit window.
              All monitored WordPress files match official cryptographic signatures.
            </p>
          </div>
        ) : (
          <>
            {canScrollX && (
              <div
                className="webcare-top-scrollbar-wrap"
                ref={topScrollRef}
                onScroll={handleTopScroll}
                title="Scroll horizontally to view all columns"
                aria-label="Horizontal scrollbar top"
              >
                <div style={{ width: `${tableScrollWidth}px`, height: '1px' }} />
              </div>
            )}
            <div
              className="webcare-fim-table-wrap"
              ref={bottomScrollRef}
              onScroll={handleBottomScroll}
            >
              <table className="webcare-fim-table" ref={tableRef}>
                <thead>
                  <tr>
                    {visibleColumns.severity && (
                      <th style={{ minWidth: '95px' }}>Severity</th>
                    )}
                    {visibleColumns.integrity_status && (
                      <th style={{ minWidth: '175px' }}>Integrity Status</th>
                    )}
                    {visibleColumns.file_location && (
                      <th style={{ minWidth: '280px' }}>File Location & Scope</th>
                    )}
                    {visibleColumns.scope && (
                      <th style={{ minWidth: '90px' }}>Scope</th>
                    )}
                    {visibleColumns.component_name && (
                      <th style={{ minWidth: '160px' }}>Plugin / Theme Name</th>
                    )}
                    {visibleColumns.installed_version && (
                      <th style={{ minWidth: '110px' }}>Installed Version</th>
                    )}
                    {visibleColumns.latest_version && (
                      <th style={{ minWidth: '135px' }}>Official Latest Version</th>
                    )}
                    {visibleColumns.last_modified && (
                      <th style={{ minWidth: '140px' }}>Last Modified</th>
                    )}
                    {visibleColumns.file_size && (
                      <th style={{ minWidth: '90px' }}>File Size</th>
                    )}
                    {visibleColumns.file_permissions && (
                      <th style={{ minWidth: '100px' }}>Permissions</th>
                    )}
                    {visibleColumns.file_owner && (
                      <th style={{ minWidth: '115px' }}>Owner & Group</th>
                    )}
                    {visibleColumns.file_hash && (
                      <th style={{ minWidth: '120px' }}>MD5 Hash</th>
                    )}
                    {visibleColumns.actions && (
                      <th style={{ minWidth: '165px', textAlign: 'right' }}>Remediation & Diff</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {paginatedChanges.map((item, idx) => {
                    const statusClass =
                      item.integrity_status === 'rogue_file' || item.severity === 'critical'
                        ? 'status-rogue'
                        : item.integrity_status === 'modified' || item.severity === 'high'
                        ? 'status-modified'
                        : item.integrity_status === 'verified_clean' || item.is_verified_clean
                        ? 'status-clean'
                        : item.integrity_status === 'safe_config'
                        ? 'status-config'
                        : item.integrity_status === 'custom_component'
                        ? 'status-custom'
                        : '';

                    return (
                      <tr
                        key={idx}
                        className={`webcare-fim-row ${statusClass}`}
                      >
                        {/* Severity */}
                        {visibleColumns.severity && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            <span className={`webcare-badge webcare-badge-${item.severity}`}>
                              {item.severity === 'clean' ? 'Verified Clean' : item.severity}
                            </span>
                          </td>
                        )}

                        {/* Integrity Status */}
                        {visibleColumns.integrity_status && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {item.integrity_status === 'verified_clean' || item.is_verified_clean ? (
                              <span className="webcare-status-chip webcare-status-chip-repaired">
                                <CheckCircle2 size={13} /> Pristine (Official Match)
                              </span>
                            ) : item.integrity_status === 'modified' ? (
                              <span className="webcare-status-chip webcare-status-chip-quarantined">
                                <AlertTriangle size={13} /> Altered / Modified
                              </span>
                            ) : item.integrity_status === 'rogue_file' ? (
                              <span className="webcare-status-chip webcare-status-chip-open">
                                <FileWarning size={13} /> Rogue File
                              </span>
                            ) : item.integrity_status === 'safe_config' ? (
                              <span className="webcare-status-chip webcare-status-chip-ignored">
                                <Shield size={13} /> Safe Config
                              </span>
                            ) : item.integrity_status === 'custom_component' ? (
                              <span className="webcare-badge" style={{ background: 'rgba(139, 92, 246, 0.12)', color: '#a855f7', border: '1px solid rgba(139, 92, 246, 0.25)' }}>
                                <Sparkles size={13} /> Custom / Untracked
                              </span>
                            ) : item.integrity_status === 'suspicious_executable' ? (
                              <span className="webcare-status-chip webcare-status-chip-open">
                                <AlertOctagon size={13} /> Upload Script
                              </span>
                            ) : (
                              <span className="webcare-status-chip webcare-status-chip-ignored">
                                Unverified
                              </span>
                            )}
                          </td>
                        )}

                        {/* File Location & Scope */}
                        {visibleColumns.file_location && (
                          <td style={{ verticalAlign: 'middle', minWidth: '280px' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <FileCode size={14} className="webcare-fim-file-icon" style={{ flexShrink: 0 }} />
                                <span className="webcare-fim-filename">
                                  {item.filename}
                                </span>
                              </div>
                              <div className="webcare-fim-filepath">
                                {item.relative_path}
                              </div>
                              <div className={`webcare-fim-risk-note ${item.is_suspicious ? 'suspicious' : item.is_verified_clean ? 'clean' : ''}`}>
                                {item.risk_reason}
                              </div>
                            </div>
                          </td>
                        )}

                        {/* Scope */}
                        {visibleColumns.scope && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            <span className={`webcare-fim-scope-tag webcare-fim-scope-${item.category}`}>
                              {item.category}
                            </span>
                          </td>
                        )}

                        {/* Plugin / Theme Name */}
                        {visibleColumns.component_name && (
                          <td style={{ verticalAlign: 'middle' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                              <strong className="webcare-fim-component-name">
                                {item.component_name || (item.category === 'core' ? 'WordPress Core' : 'N/A')}
                              </strong>
                              {item.component_slug && (
                                <span className="webcare-fim-component-slug">
                                  {item.component_slug}
                                </span>
                              )}
                            </div>
                          </td>
                        )}

                        {/* Installed Version */}
                        {visibleColumns.installed_version && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {item.installed_version ? (
                              <span className="webcare-fim-version-tag">
                                v{item.installed_version}
                              </span>
                            ) : (
                              <span className="webcare-fim-dash">—</span>
                            )}
                          </td>
                        )}

                        {/* Official Latest Version */}
                        {visibleColumns.latest_version && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {item.latest_version ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span className="webcare-fim-latest-version-txt">
                                  v{item.latest_version}
                                </span>
                                {item.is_update_available ? (
                                  <span className="webcare-fim-update-pill">
                                    Update
                                  </span>
                                ) : (
                                  <span className="webcare-fim-latest-pill">
                                    Latest
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="webcare-fim-dash">—</span>
                            )}
                          </td>
                        )}

                        {/* Last Modified */}
                        {visibleColumns.last_modified && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            <div className="webcare-fim-mod-human">
                              {item.modified_human}
                            </div>
                            <div className="webcare-fim-mod-iso">
                              {item.modified_iso}
                            </div>
                          </td>
                        )}

                        {/* File Size */}
                        {visibleColumns.file_size && (
                          <td className="webcare-fim-filesize" style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {item.size_formatted}
                          </td>
                        )}

                        {/* File Permissions */}
                        {visibleColumns.file_permissions && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <code className="webcare-fim-perm-code">
                                {item.file_permissions || '0644'}
                              </code>
                              {item.file_permissions === '0777' ? (
                                <span className="webcare-fim-perm-insecure">
                                  Insecure
                                </span>
                              ) : (
                                <span className="webcare-fim-perm-safe">
                                  Safe
                                </span>
                              )}
                            </div>
                          </td>
                        )}

                        {/* Owner & Group */}
                        {visibleColumns.file_owner && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            <code className="webcare-fim-owner-code">
                              {item.file_owner || 'www-data'}
                            </code>
                          </td>
                        )}

                        {/* MD5 Hash */}
                        {visibleColumns.file_hash && (
                          <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {item.file_hash ? (
                              <button
                                type="button"
                                onClick={() => {
                                  navigator.clipboard?.writeText(item.file_hash || '');
                                  setCopiedHash(item.file_hash || '');
                                  setTimeout(() => setCopiedHash(null), 2000);
                                }}
                                title={`Full MD5: ${item.file_hash} (Click to copy)`}
                                className="webcare-fim-hash-btn"
                              >
                                {copiedHash === item.file_hash ? (
                                  <span className="webcare-fim-hash-copied">
                                    <Check size={11} /> Copied
                                  </span>
                                ) : (
                                  <>
                                    <Copy size={11} className="webcare-fim-hash-copy-icon" />
                                    <span>{item.file_hash.substring(0, 10)}...</span>
                                  </>
                                )}
                              </button>
                            ) : (
                              <span className="webcare-fim-dash">—</span>
                            )}
                          </td>
                        )}

                        {/* Remediation & Diff Actions */}
                        {visibleColumns.actions && (
                          <td style={{ verticalAlign: 'middle', textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                              {item.can_auto_cure && item.integrity_status === 'modified' && (
                                <button
                                  type="button"
                                  className="webcare-btn webcare-fim-btn-autocure"
                                  disabled={remediating}
                                  onClick={() => handleAutoCurePlugin(item.file_path)}
                                  title="1-Click Auto-Cure: Restore clean official WP.org release bit-for-bit"
                                >
                                  <RotateCcw size={12} />
                                  Auto-Cure
                                </button>
                              )}

                              <button
                                type="button"
                                className="webcare-btn webcare-fim-btn-diff"
                                onClick={() => handleOpenDiff(item.file_path)}
                                title="Inspect unified line-by-line diff against official baseline"
                              >
                                <FileCode size={12} />
                                Diff
                              </button>
                            </div>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {pageSize !== -1 && totalPages > 1 && (
              <div className="webcare-fim-pagination-bar">
                <div className="webcare-fim-pagination-info">
                  Showing <strong>{(safeCurrentPage - 1) * pageSize + 1}</strong> to{' '}
                  <strong>{Math.min(safeCurrentPage * pageSize, filteredChanges.length)}</strong> of{' '}
                  <strong>{filteredChanges.length}</strong> files
                </div>

                <div className="webcare-fim-pagination-controls">
                  <button
                    type="button"
                    disabled={safeCurrentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="webcare-fim-page-btn"
                  >
                    Previous
                  </button>

                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter((p) => p === 1 || p === totalPages || Math.abs(p - safeCurrentPage) <= 2)
                    .map((p, idx, arr) => (
                      <Fragment key={p}>
                        {idx > 0 && arr[idx - 1] !== p - 1 && (
                          <span className="webcare-fim-page-ellipsis">...</span>
                        )}
                        <button
                          type="button"
                          onClick={() => setCurrentPage(p)}
                          className={`webcare-fim-page-btn ${safeCurrentPage === p ? 'active' : ''}`}
                        >
                          {p}
                        </button>
                      </Fragment>
                    ))}

                  <button
                    type="button"
                    disabled={safeCurrentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="webcare-fim-page-btn"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
        </>
      ) : (
        /* Tab 2: Filesystem Permissions & Ownership Auditor */
        <FilesystemPermissionHardeningCard
          apiRequest={apiRequest}
          onPermissionsFixed={() => loadChanges()}
        />
      )}

      {/* =========================================================================
          POPUP MODAL: GIT-STYLE VISUAL CODE DIFF VIEWER WITH AUTO-CURE
          ========================================================================= */}
      <VisualDiffModal
        isOpen={diffModalOpen}
        filePath={activeDiffFilePath}
        onClose={() => {
          setDiffModalOpen(false);
          setActiveDiffFilePath(null);
        }}
        apiRequest={apiRequest}
        onRemediated={() => {
          loadChanges();
        }}
      />

      {/* =========================================================================
          POPUP MODAL: AUTO-CURE SAFETY BACKUPS & ROLLBACK VAULT
          ========================================================================= */}
      {backupsModalOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setBackupsModalOpen(false);
            }
          }}
        >
          <div
            className="webcare-modal-window webcare-fim-modal-window"
            style={{
              maxWidth: '850px',
              width: '90vw',
              maxHeight: '80vh',
              display: 'flex',
              flexDirection: 'column',
              borderRadius: '12px',
              overflow: 'hidden',
            }}
          >
            {/* Modal Header */}
            <div className="webcare-fim-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <History size={20} color="#0284c7" />
                <h3 className="webcare-fim-modal-title">
                  Auto-Cure Safety Backups & Rollback Vault
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setBackupsModalOpen(false)}
                className="webcare-fim-modal-close"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="webcare-fim-modal-body" style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
              {loadingBackups ? (
                <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                  <RefreshCw size={28} className="webcare-spin-icon" style={{ margin: '0 auto 10px auto', color: '#0284c7' }} />
                  <div>Loading safety backup archives...</div>
                </div>
              ) : backups.length === 0 ? (
                <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                  <ShieldCheck size={40} color="#16a34a" style={{ margin: '0 auto 10px auto' }} />
                  <div className="webcare-fim-modal-empty-title">No Remediation Backups Found</div>
                  <div className="webcare-fim-modal-empty-desc">
                    Every time an Auto-Cure or malware stripping action is executed, a snapshot is saved here for 1-click rollback.
                  </div>
                </div>
              ) : (
                <table className="webcare-table-modern webcare-fim-modal-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr className="webcare-fim-modal-thead-row">
                      <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Target File</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Remediation Action</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: '12px' }}>Timestamp</th>
                      <th style={{ padding: '10px 14px', textAlign: 'right', fontSize: '12px' }}>Rollback</th>
                    </tr>
                  </thead>
                  <tbody>
                    {backups.map((bak) => (
                      <tr key={bak.id} className="webcare-fim-modal-row">
                        <td style={{ padding: '12px 14px', fontFamily: 'monospace', fontSize: '12px' }}>
                          <span className="webcare-fim-modal-filename">{bak.original_path.split(/[\\/]/).pop()}</span>
                          <div className="webcare-fim-modal-filepath">{bak.original_path}</div>
                        </td>
                        <td style={{ padding: '12px 14px', fontSize: '12px' }}>
                          <span
                            className={`webcare-fim-modal-action-tag ${bak.action_type === 'webshell_strip' ? 'webshell' : 'wp-restore'}`}
                          >
                            {bak.action_type === 'webshell_strip' ? 'Webshell Stripped' : 'WP.org Restored'}
                          </span>
                        </td>
                        <td className="webcare-fim-modal-time" style={{ padding: '12px 14px', fontSize: '12px', whiteSpace: 'nowrap' }}>
                          {bak.created_at}
                        </td>
                        <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                          <button
                            type="button"
                            className="webcare-btn webcare-fim-btn-rollback"
                            onClick={() => handleRollback(bak.id, bak.original_path.split(/[\\/]/).pop() || '')}
                          >
                            <Undo2 size={12} />
                            Rollback
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Modal Footer */}
            <div className="webcare-fim-modal-footer">
              <button
                type="button"
                className="webcare-btn webcare-fim-modal-btn-close"
                onClick={() => setBackupsModalOpen(false)}
              >
                Close Vault
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={fimConfirmDialog.isOpen}
        title={fimConfirmDialog.title}
        message={fimConfirmDialog.message}
        targetItem={fimConfirmDialog.targetItem}
        confirmLabel={fimConfirmDialog.confirmLabel}
        variant={fimConfirmDialog.variant}
        isLoading={fimConfirmDialog.isLoading}
        onConfirm={fimConfirmDialog.onConfirm || (() => {})}
        onClose={() => setFimConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
}
