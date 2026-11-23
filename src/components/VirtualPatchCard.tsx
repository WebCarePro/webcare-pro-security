import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Layers,
  Flame,
  AlertTriangle,
  RotateCcw,
  Trash2,
  Lock,
  ChevronRight,
  ChevronDown,
  Info,
  Server,
  Database,
  Cloud,
  CheckCircle2,
  ExternalLink,
  Sparkles,
  Loader2,
  Phone,
  ArrowUpRight,
  PlusCircle,
  X,
  Play,
  Check,
  Sliders,
  Search,
  Eye,
  AlertOctagon,
  Package
} from 'lucide-react';

interface VirtualPatch {
  patch_id: string;
  cve_id: string;
  component: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  vector_type?: string;
  php_rule?: {
    target_uris: string[];
    regex?: string;
    headers?: string[];
    methods?: string[];
    parameters?: string[];
  };
  cf_expression?: string;
  enabled?: boolean;
  hits?: number;
  last_hit?: string;
  applied_at?: string;
  deployed_to_cloudflare?: boolean;
  cloudflare_rule_id?: string;
  is_synthesized?: boolean;
  simulation?: {
    status: 'passed' | 'warning' | 'failed';
    attack_match_rate: number;
    benign_pass_rate: number;
    avg_latency_us: number;
    false_positives: number;
    traces: Array<{
      type: string;
      name: string;
      payload: string;
      blocked: boolean;
      latency_us: number;
      passed: boolean;
    }>;
  };
}

interface VirtualPatchListResponse {
  success: boolean;
  catalog: VirtualPatch[];
  active_patches: VirtualPatch[];
  cloudflare_ready: boolean;
}

interface VirtualPatchCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onPatchUpdated?: () => void;
  onNavigateToSettings?: () => void;
  onNavigateToSupport?: () => void;
}

export function VirtualPatchCard({
  apiRequest,
  onPatchUpdated,
  onNavigateToSettings,
  onNavigateToSupport
}: VirtualPatchCardProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [patching, setPatching] = useState<string | null>(null);
  const [data, setData] = useState<VirtualPatchListResponse | null>(null);
  const [synthesizedPatches, setSynthesizedPatches] = useState<VirtualPatch[]>([]);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Synthesizer Studio State
  const [showSynthesizerModal, setShowSynthesizerModal] = useState<boolean>(false);
  const [synthesizing, setSynthesizing] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [deployToCloudflare, setDeployToCloudflare] = useState<boolean>(false);
  const [candidatePatch, setCandidatePatch] = useState<VirtualPatch | null>(null);
  const [simulationReport, setSimulationReport] = useState<any | null>(null);

  // Live CVE Intelligence & Local Correlator State
  const [cveSearchQuery, setCveSearchQuery] = useState<string>('');
  const [cveSearching, setCveSearching] = useState<boolean>(false);
  const [cveResult, setCveResult] = useState<any | null>(null);
  const [deactivatingComponent, setDeactivatingComponent] = useState<boolean>(false);

  const [synthForm, setSynthForm] = useState<{
    cve_id: string;
    component: string;
    title: string;
    vector_type: string;
    target_uris: string;
    parameters: string;
    custom_regex: string;
    severity: 'critical' | 'high' | 'medium';
  }>({
    cve_id: '',
    component: '',
    title: '',
    vector_type: 'sqli',
    target_uris: '/wp-admin/admin-ajax.php',
    parameters: 'id, search, query',
    custom_regex: '',
    severity: 'high',
  });

  const handleCveLookup = async (e?: any) => {
    if (e && e.preventDefault) {
      e.preventDefault();
    }
    const cleanId = cveSearchQuery.trim().toUpperCase();
    if (!cleanId) {
      return;
    }

    setCveSearching(true);
    setFeedback(null);
    setCveResult(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/cve-lookup',
        method: 'POST',
        data: { cve_id: cleanId }
      });

      if (res && res.success) {
        setCveResult(res);
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || `Failed to find intelligence for ${cleanId}.`
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || `Error connecting to CVE intelligence database.`
      });
    } finally {
      setCveSearching(false);
    }
  };

  const handleDeactivateComponent = async (pluginFile: string) => {
    if (!pluginFile) return;
    setDeactivatingComponent(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/deactivate-component',
        method: 'POST',
        data: { plugin_file: pluginFile }
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Component successfully deactivated.'
        });
        // Re-run lookup to refresh status to safe / not active
        if (cveResult?.cve_id) {
          await handleCveLookup();
        }
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to deactivate plugin.'
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error deactivating component.'
      });
    } finally {
      setDeactivatingComponent(false);
    }
  };

  const handlePreFillSynthesizerFromCve = (cveData: any) => {
    if (!cveData) return;
    setSynthForm({
      cve_id: cveData.cve_id || '',
      component: cveData.component || 'custom-plugin',
      title: `${cveData.cve_id} - ${cveData.component || 'Target Component'} Shield`,
      vector_type: cveData.vector_type || 'sqli',
      target_uris: '/wp-admin/admin-ajax.php, /',
      parameters: 'id, search, query, file',
      custom_regex: '',
      severity: (cveData.severity as any) || 'high'
    });
    setCandidatePatch(null);
    setSimulationReport(null);
    setShowSynthesizerModal(true);
  };

  const loadPatches = async () => {
    setLoading(true);
    setFeedback(null);
    try {
      const [resCatalog, resSynth] = await Promise.all([
        apiRequest({ path: '/webcare-pro-security/v1/virtual-patch/list', method: 'GET' }),
        apiRequest({ path: '/webcare-pro-security/v1/virtual-patch/synthesized', method: 'GET' }),
      ]);

      if (resCatalog && resCatalog.success) {
        setData(resCatalog);
      }
      if (resSynth && resSynth.success && Array.isArray(resSynth.patches)) {
        setSynthesizedPatches(resSynth.patches);
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to load Virtual Patch catalog.',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPatches();
  }, []);

  const handleApplyPatch = async (patchId: string, customConfig?: any) => {
    setPatching(patchId);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/apply',
        method: 'POST',
        data: {
          patch_id: patchId,
          custom_config: customConfig,
        },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || `Virtual Patch "${patchId}" applied successfully!`,
        });
        await loadPatches();
        if (onPatchUpdated) {
          onPatchUpdated();
        }
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || `Failed to apply virtual patch "${patchId}".`,
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error applying virtual patch.',
      });
    } finally {
      setPatching(null);
    }
  };

  const handleRemovePatch = async (patchId: string) => {
    setPatching(patchId);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/remove',
        method: 'POST',
        data: { patch_id: patchId },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || `Virtual Patch "${patchId}" deactivated.`,
        });
        await loadPatches();
        if (onPatchUpdated) {
          onPatchUpdated();
        }
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || `Failed to deactivate virtual patch "${patchId}".`,
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error deactivating virtual patch.',
      });
    } finally {
      setPatching(null);
    }
  };

  // Compile & Run In-Memory Synthetic Simulation
  const handleCompileAndSimulate = async () => {
    setSimulating(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/synthesize',
        method: 'POST',
        data: {
          cve_id: synthForm.cve_id,
          component: synthForm.component,
          title: synthForm.title,
          vector_type: synthForm.vector_type,
          target_uris: synthForm.target_uris,
          parameters: synthForm.parameters,
          custom_regex: synthForm.custom_regex,
          severity: synthForm.severity,
        },
      });

      if (res && res.success && res.patch) {
        setCandidatePatch(res.patch);
        setSimulationReport(res.simulation);
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to synthesize candidate patch.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Error running synthesis compilation.',
      });
    } finally {
      setSimulating(false);
    }
  };

  // Deploy Synthesized Candidate Patch
  const handleDeployCandidate = async () => {
    if (!candidatePatch) return;
    setSynthesizing(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/deploy-synthesized',
        method: 'POST',
        data: {
          patch: candidatePatch,
          deploy_to_cloudflare: deployToCloudflare,
        },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Synthesized virtual patch deployed successfully!',
        });
        setShowSynthesizerModal(false);
        setCandidatePatch(null);
        setSimulationReport(null);
        await loadPatches();
        if (onPatchUpdated) {
          onPatchUpdated();
        }
      } else {
        setFeedback({
          type: 'error',
          message: res?.message || 'Failed to deploy synthesized patch.',
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error deploying synthesized patch.',
      });
    } finally {
      setSynthesizing(false);
    }
  };

  // Toggle Synthesized Patch Active State
  const handleToggleSynthesized = async (patchId: string, currentEnabled: boolean) => {
    setPatching(patchId);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/toggle-synthesized',
        method: 'POST',
        data: {
          patch_id: patchId,
          enable: !currentEnabled,
        },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Patch state updated.',
        });
        await loadPatches();
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Error toggling patch.',
      });
    } finally {
      setPatching(null);
    }
  };

  // Delete Synthesized Patch
  const handleDeleteSynthesized = async (patchId: string) => {
    const confirmed = await showConfirm({
      title: 'Delete Virtual Patch',
      message: 'Are you sure you want to permanently delete this synthesized virtual patch?',
      confirmLabel: 'Delete Patch',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    setPatching(patchId);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/virtual-patch/delete-synthesized',
        method: 'POST',
        data: { patch_id: patchId },
      });

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: res.message || 'Synthesized patch deleted.',
        });
        await loadPatches();
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Error deleting patch.',
      });
    } finally {
      setPatching(null);
    }
  };

  const activeMap: Record<string, VirtualPatch> = {};
  if (data?.active_patches) {
    data.active_patches.forEach((p) => {
      activeMap[p.patch_id] = p;
    });
  }

  const totalHits = data?.active_patches?.reduce((acc, p) => acc + (p.hits || 0), 0) || 0;
  const totalActiveCombined = (data?.active_patches?.length || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Hero Banner */}
      <div className="webcare-vp-hero-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div className="webcare-vp-hero-icon-box">
              <ShieldAlert size={26} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h2 className="webcare-vp-hero-title">
                  Automated Two-Tier Virtual Patching &amp; Zero-Day Studio
                </h2>
                <span className="webcare-vp-hero-badge">
                  Pillar 5 &bull; In-Memory Simulation
                </span>
              </div>
              <p className="webcare-vp-hero-desc">
                Shields vulnerable plugins and WordPress core against known CVE exploits and zero-days. Wordfence relies on pre-packaged rules; WebCare lets you auto-synthesize custom hotpatches for any vector with in-memory calibrated payload simulation before activation.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="webcare-btn webcare-vp-btn-synthesize"
              onClick={() => {
                setShowSynthesizerModal(true);
                setCandidatePatch(null);
                setSimulationReport(null);
              }}
            >
              <Sparkles size={15} />
              <span>Synthesize Custom CVE Hotpatch</span>
            </button>

            <button
              type="button"
              className="webcare-btn webcare-vp-hero-btn-refresh"
              onClick={loadPatches}
              disabled={loading}
            >
              <RotateCcw size={14} className={loading ? 'webcare-spin-icon' : ''} />
              <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
            </button>
          </div>
        </div>

        {/* 4 Summary KPI Tiles */}
        <div className="webcare-vp-kpi-grid">
          <div className="webcare-vp-kpi-tile">
            <div className="webcare-vp-kpi-label">
              <ShieldCheck size={13} color="#10b981" /> Active Deployed Patches
            </div>
            <div className="webcare-vp-kpi-value">
              {totalActiveCombined} Deployed
            </div>
            <span className="webcare-vp-kpi-sub">
              {synthesizedPatches.filter(p => p.enabled).length} synthesized &bull; {data?.active_patches?.filter(p => !p.is_synthesized).length || 0} catalog
            </span>
          </div>

          <div className="webcare-vp-kpi-tile">
            <div className="webcare-vp-kpi-label">
              <Cloud size={13} color="#ea580c" /> Cloudflare Global Edge
            </div>
            <div className={`webcare-vp-kpi-value ${data?.cloudflare_ready ? 'is-ready' : 'is-warning'}`} style={{ fontSize: '16px' }}>
              {data?.cloudflare_ready ? 'Edge WAF Connected' : 'Local WAF Lite Active'}
            </div>
            <span className="webcare-vp-kpi-sub">
              {data?.cloudflare_ready ? 'Zero-overhead edge drop' : 'Sub-millisecond PHP inspection'}
            </span>
          </div>

          <div className="webcare-vp-kpi-tile">
            <div className="webcare-vp-kpi-label">
              <Activity size={13} color="#dc2626" /> Total Exploit Interceptions
            </div>
            <div className="webcare-vp-kpi-value">
              {totalHits} Blocks
            </div>
            <span className="webcare-vp-kpi-sub">Cumulative exploits stopped</span>
          </div>

          <div className="webcare-vp-kpi-tile">
            <div className="webcare-vp-kpi-label">
              <Sparkles size={13} color="#7c3aed" /> Custom Hotpatches
            </div>
            <div className="webcare-vp-kpi-value">
              {synthesizedPatches.length} Synthesized
            </div>
            <span className="webcare-vp-kpi-sub">Calibrated in-memory rules</span>
          </div>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div style={{
          padding: '12px 18px',
          borderRadius: '10px',
          background: feedback.type === 'success' ? '#ecfdf5' : '#fef2f2',
          border: `1px solid ${feedback.type === 'success' ? '#a7f3d0' : '#fecaca'}`,
          color: feedback.type === 'success' ? '#065f46' : '#991b1b',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontWeight: 600
        }}>
          {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{(feedback.message || '').replace(/<[^>]*>?/gm, '').trim()}</span>
        </div>
      )}

      {/* SECTION: Live CVE Intelligence & Site Inventory Correlator */}
      <div className="webcare-card webcare-vp-intel-card" style={{ padding: '22px 24px', borderRadius: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px', marginBottom: '16px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Search size={18} color="#4f46e5" />
              <span>Real-Time CVE Intelligence &amp; Site Vulnerability Correlator</span>
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Enter any CVE number (e.g. <code>CVE-2024-5932</code>, <code>CVE-2024-28000</code>). WebCare will query the National Vulnerability Database (NVD) in real time and correlate whether the affected plugin or theme exists on your site.
            </p>
          </div>
        </div>

        <form onSubmit={handleCveLookup} style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: '1 1 320px', maxWidth: '520px' }}>
            <input
              type="text"
              className="webcare-input"
              placeholder="e.g. CVE-2024-5932 or CVE-2024-28000"
              value={cveSearchQuery}
              onChange={(e) => setCveSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '9px 14px',
                fontSize: '13px',
                fontFamily: 'monospace',
                textTransform: 'uppercase'
              }}
            />
          </div>

          <button
            type="submit"
            className="webcare-btn webcare-btn-primary"
            disabled={cveSearching || !cveSearchQuery.trim()}
            style={{
              padding: '9px 18px',
              fontSize: '13px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            {cveSearching ? <Loader2 size={15} className="webcare-spin-icon" /> : <Search size={15} />}
            <span>{cveSearching ? 'Searching NVD Database...' : 'Lookup CVE & Check Site'}</span>
          </button>

          {/* Quick preset lookup pill buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontWeight: 600 }}>Quick Check:</span>
            <button
              type="button"
              className="webcare-btn"
              onClick={() => {
                setCveSearchQuery('CVE-2024-5932');
              }}
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'var(--webcare-bg-elevated, #f1f5f9)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                color: '#0284c7',
                fontFamily: 'monospace',
                cursor: 'pointer'
              }}
            >
              GiveWP (CVE-2024-5932)
            </button>
            <button
              type="button"
              className="webcare-btn"
              onClick={() => {
                setCveSearchQuery('CVE-2024-28000');
              }}
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'var(--webcare-bg-elevated, #f1f5f9)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                color: '#0284c7',
                fontFamily: 'monospace',
                cursor: 'pointer'
              }}
            >
              LiteSpeed (CVE-2024-28000)
            </button>
            <button
              type="button"
              className="webcare-btn"
              onClick={() => {
                setCveSearchQuery('CVE-2024-31210');
              }}
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'var(--webcare-bg-elevated, #f1f5f9)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                color: '#0284c7',
                fontFamily: 'monospace',
                cursor: 'pointer'
              }}
            >
              Core (CVE-2024-31210)
            </button>
          </div>
        </form>

        {/* Real-Time CVE Intelligence Correlation Report Result */}
        {cveResult && (
          <div className="webcare-vp-cve-intel-box" style={{ marginTop: '18px' }}>
            {/* Header info strip */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <code style={{ fontSize: '13px', fontWeight: 900, background: 'rgba(79, 70, 229, 0.1)', color: '#4f46e5', padding: '2px 8px', borderRadius: '4px' }}>
                    {cveResult.cve_id}
                  </code>
                  <span className={`webcare-badge-pill ${cveResult.severity === 'critical' ? 'webcare-badge-danger' : 'webcare-badge-warning'}`}>
                    CVSS {cveResult.cvss} &bull; {String(cveResult.severity).toUpperCase()}
                  </span>
                  <span className="webcare-smart-shield-pill-detected-purple" style={{ fontSize: '10.5px', textTransform: 'uppercase' }}>
                    VECTOR: {cveResult.vector_type || 'EXPLOIT'}
                  </span>
                  {cveResult.is_wordpress ? (
                    <span className="webcare-smart-shield-pill-detected-emerald" style={{ fontSize: '10.5px' }}>
                      WORDPRESS ECOSYSTEM
                    </span>
                  ) : (
                    <span className="webcare-badge-neutral" style={{ fontSize: '10.5px' }}>
                      EXTERNAL / NON-WP ADVISORY
                    </span>
                  )}
                </div>

                <h4 style={{ margin: '10px 0 4px 0', fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {cveResult.title}
                </h4>
              </div>
            </div>

            {/* CVE Overview Grid: Structured Meta on Left, References on Right */}
            <div className="webcare-cve-intel-grid">
              {/* Left Column: CVE Key/Value Metadata */}
              <div className="webcare-cve-meta-table-card">
                <table className="webcare-cve-meta-table">
                  <tbody>
                    <tr>
                      <td className="webcare-cve-meta-key">CVE</td>
                      <td className="webcare-cve-meta-val">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveResult.cve_id)}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: '#0284c7', fontWeight: 700, textDecoration: 'none' }}
                        >
                          {cveResult.cve_id}
                        </a>
                      </td>
                    </tr>
                    <tr>
                      <td className="webcare-cve-meta-key">CVSS</td>
                      <td className="webcare-cve-meta-val">
                        {(() => {
                          const score = parseFloat(cveResult.cvss);
                          const isScore10 = !isNaN(score) && score >= 10.0;
                          let cvssClass = 'webcare-cvss-medium';
                          if (isScore10) {
                            cvssClass = 'webcare-cvss-critical-10';
                          } else if (score >= 9.0) {
                            cvssClass = 'webcare-cvss-critical';
                          } else if (score >= 7.0) {
                            cvssClass = 'webcare-cvss-high';
                          } else if (score >= 4.0) {
                            cvssClass = 'webcare-cvss-medium';
                          } else {
                            cvssClass = 'webcare-cvss-low';
                          }

                          return (
                            <span className={`webcare-cvss-badge ${cvssClass}`}>
                              <span>{cveResult.cvss || 'N/A'}</span>
                              <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'capitalize', opacity: 0.9 }}>
                                ({cveResult.severity || (score >= 9.0 ? 'Critical' : score >= 7.0 ? 'High' : 'Medium')})
                              </span>
                            </span>
                          );
                        })()}
                      </td>
                    </tr>
                    <tr>
                      <td className="webcare-cve-meta-key">Publicly Published</td>
                      <td className="webcare-cve-meta-val">{cveResult.published_at || 'Recently Published'}</td>
                    </tr>
                    <tr>
                      <td className="webcare-cve-meta-key">Last Updated</td>
                      <td className="webcare-cve-meta-val">{cveResult.updated_at || 'Recently Updated'}</td>
                    </tr>
                    <tr>
                      <td className="webcare-cve-meta-key">Researcher / Reporter</td>
                      <td className="webcare-cve-meta-val">
                        <span style={{ color: '#0284c7', fontWeight: 600 }}>
                          {cveResult.researcher || 'Independent Security Researcher'}
                        </span>
                      </td>
                    </tr>
                    {cveResult.weakness && (
                      <tr>
                        <td className="webcare-cve-meta-key">Weakness (CWE)</td>
                        <td className="webcare-cve-meta-val" style={{ color: 'var(--webcare-text-secondary, #475569)', fontWeight: 600 }}>
                          {cveResult.weakness}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Right Column: References */}
              <div className="webcare-cve-references-card">
                <div className="webcare-cve-ref-header">
                  <span>References & Intelligence Sources</span>
                  <ExternalLink size={12} color="var(--webcare-text-muted, #64748b)" />
                </div>
                {Array.isArray(cveResult.references) && cveResult.references.length > 0 ? (
                  <ul className="webcare-cve-ref-list">
                    {cveResult.references.slice(0, 6).map((refItem: any, idx: number) => {
                      const urlStr = typeof refItem === 'string' ? refItem : (refItem?.url || '');
                      let displayHost = typeof refItem === 'object' && refItem?.host ? refItem.host : urlStr;
                      if (!displayHost && urlStr) {
                        try {
                          const parsed = new URL(urlStr);
                          displayHost = parsed.hostname + (parsed.pathname.length > 25 ? parsed.pathname.substring(0, 25) + '…' : parsed.pathname);
                        } catch {
                          displayHost = urlStr;
                        }
                      }
                      if (!urlStr) return null;
                      return (
                        <li key={idx}>
                          <a href={urlStr} target="_blank" rel="noreferrer" className="webcare-cve-ref-link">
                            {String(displayHost)}
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p style={{ margin: '8px 0', fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    No public reference advisories attached to this NVD identifier.
                  </p>
                )}
              </div>
            </div>

            {/* Structured Software & Remediation Details Table */}
            {cveResult.software && (
              <div className="webcare-cve-software-section">
                <div className="webcare-cve-software-title">
                  Vulnerability Details for {cveResult.software.name || cveResult.component || 'Target Component'}
                </div>
                <div className="webcare-cve-software-card">
                  <div className="webcare-cve-software-header">
                    <Package size={18} color="#0284c7" />
                    <span>{cveResult.software.name || cveResult.component}</span>
                  </div>

                  <table className="webcare-cve-software-table">
                    <tbody>
                      <tr className="webcare-cve-software-row">
                        <td className="webcare-cve-software-key">Software Type</td>
                        <td className="webcare-cve-software-val">
                          <span style={{ fontWeight: 600 }}>{cveResult.software.type || 'Plugin'}</span>
                        </td>
                      </tr>

                      {cveResult.software.slug && (
                        <tr className="webcare-cve-software-row">
                          <td className="webcare-cve-software-key">Software Slug</td>
                          <td className="webcare-cve-software-val">
                            <code style={{ background: 'rgba(2, 132, 199, 0.08)', color: '#0284c7', padding: '2px 6px', borderRadius: '4px', fontWeight: 700, marginRight: '8px' }}>
                              {cveResult.software.slug}
                            </code>
                            {cveResult.software.wporg_url && (
                              <a
                                href={cveResult.software.wporg_url}
                                target="_blank"
                                rel="noreferrer"
                                style={{ fontSize: '11.5px', color: '#0284c7', textDecoration: 'none', fontWeight: 600 }}
                              >
                                (view on wordpress.org)
                              </a>
                            )}
                          </td>
                        </tr>
                      )}

                      <tr className="webcare-cve-software-row">
                        <td className="webcare-cve-software-key">Patched?</td>
                        <td className="webcare-cve-software-val">
                          {cveResult.software.is_patched ? (
                            <span style={{ color: '#059669', fontWeight: 800, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                              ✓ Yes
                            </span>
                          ) : (
                            <span style={{ color: '#dc2626', fontWeight: 800, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                              ✗ No (0-Day / Unpatched)
                            </span>
                          )}
                        </td>
                      </tr>

                      <tr className="webcare-cve-software-row">
                        <td className="webcare-cve-software-key">Remediation</td>
                        <td className="webcare-cve-software-val">
                          <span style={{ color: 'var(--webcare-text-primary, #0f172a)', fontWeight: 600 }}>
                            {cveResult.software.remediation || (cveResult.software.patched_version ? `Update to version ${cveResult.software.patched_version}, or a newer patched version` : 'Apply WebCare virtual patch')}
                          </span>
                        </td>
                      </tr>

                      <tr className="webcare-cve-software-row">
                        <td className="webcare-cve-software-key">Affected Version</td>
                        <td className="webcare-cve-software-val">
                          <code style={{ background: 'rgba(239, 68, 68, 0.08)', color: '#dc2626', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                            {cveResult.software.affected_version || '<= Latest'}
                          </code>
                        </td>
                      </tr>

                      {cveResult.software.patched_version && (
                        <tr className="webcare-cve-software-row">
                          <td className="webcare-cve-software-key">Patched Version</td>
                          <td className="webcare-cve-software-val">
                            <code style={{ background: 'rgba(16, 185, 129, 0.08)', color: '#059669', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                              {cveResult.software.patched_version}
                            </code>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Advisory Description Summary */}
            <div style={{ marginTop: '14px', padding: '12px 16px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
              <div style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--webcare-text-muted, #64748b)', marginBottom: '4px' }}>
                Technical Advisory Details
              </div>
              <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.55 }}>
                {cveResult.description}
              </p>
            </div>

            {/* Local WordPress Inventory Correlation Result Banner */}
            {cveResult.correlation && (
              <div
                className={`webcare-vp-correlation-status-banner status-${cveResult.correlation.status}`}
                style={{
                  padding: '14px 18px',
                  borderRadius: '10px',
                  marginTop: '12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                  {cveResult.correlation.status === 'not_installed' && (
                    <CheckCircle2 size={22} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
                  )}
                  {cveResult.correlation.status === 'safe' && (
                    <ShieldCheck size={22} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
                  )}
                  {cveResult.correlation.status === 'vulnerable' && (
                    <AlertOctagon size={22} color="#dc2626" style={{ flexShrink: 0, marginTop: '2px' }} />
                  )}

                  <div>
                    <strong style={{ fontSize: '13.5px', display: 'block', marginBottom: '2px' }}>
                      {cveResult.correlation.status === 'not_installed' && 'Target Software is NOT Installed (Site is Clean & Immune)'}
                      {cveResult.correlation.status === 'safe' && 'Installed Software is Safe / Already Patched'}
                      {cveResult.correlation.status === 'vulnerable' && '🚨 CRITICAL MATCH: Vulnerable Software is Installed on Your Website!'}
                    </strong>
                    <div style={{ fontSize: '12.5px', lineHeight: 1.45 }}>
                      {cveResult.correlation.message}
                    </div>
                  </div>
                </div>

                {/* Contextual Operator Actions */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  {cveResult.correlation.status === 'vulnerable' && (
                    <>
                      {/* Action 1: Deploy Virtual Patch */}
                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={() => {
                          if (cveResult.has_prebuilt_patch && cveResult.patch_data) {
                            handleApplyPatch(cveResult.patch_data.patch_id);
                          } else {
                            handlePreFillSynthesizerFromCve(cveResult);
                          }
                        }}
                        style={{
                          background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                          color: '#ffffff',
                          border: 'none',
                          padding: '7px 15px',
                          fontSize: '12.5px',
                          fontWeight: 700,
                          borderRadius: '6px',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          boxShadow: '0 2px 6px rgba(16, 185, 129, 0.3)'
                        }}
                      >
                        <Zap size={13} />
                        <span>Deploy Instant Virtual Patch</span>
                      </button>

                      {/* Action 2: Deactivate Component */}
                      {cveResult.correlation.can_deactivate && cveResult.correlation.plugin_file && (
                        <button
                          type="button"
                          className="webcare-btn webcare-btn-danger-soft"
                          disabled={deactivatingComponent}
                          onClick={() => handleDeactivateComponent(cveResult.correlation.plugin_file)}
                          style={{
                            padding: '7px 14px',
                            fontSize: '12.5px',
                            fontWeight: 700,
                            borderRadius: '6px',
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          {deactivatingComponent ? <Loader2 size={13} className="webcare-spin-icon" /> : <Shield size={13} />}
                          <span>Deactivate Plugin Now</span>
                        </button>
                      )}
                    </>
                  )}

                  {cveResult.correlation.status === 'not_installed' && (
                    <span style={{ fontSize: '11.5px', color: '#047857', fontWeight: 700, background: '#ecfdf5', border: '1px solid #a7f3d0', padding: '4px 10px', borderRadius: '6px' }}>
                      ✓ Zero Action Required
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* SECTION 1: Synthesized Zero-Day Hotpatches Ledger */}
      {synthesizedPatches.length > 0 && (
        <div className="webcare-vp-catalog-card">
          <div className="webcare-vp-catalog-header" style={{ padding: '18px 24px' }}>
            <div>
              <h3 className="webcare-vp-catalog-title" style={{ margin: 0, fontSize: '16px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles size={18} color="#7c3aed" /> Active Synthesized Zero-Day Hotpatches ({synthesizedPatches.length})
              </h3>
              <p className="webcare-vp-catalog-desc" style={{ margin: '4px 0 0 0', fontSize: '13px' }}>
                Custom hotpatches generated by the Automated Rule Synthesizer, pre-calibrated with 100% attack match rates.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '18px 24px' }}>
            {synthesizedPatches.map((patch) => {
              const isBusy = patching === patch.patch_id;
              return (
                <div
                  key={patch.patch_id}
                  className="webcare-firewall-rule-card"
                  style={{
                    padding: '16px 20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    border: patch.enabled ? '1px solid rgba(124, 58, 237, 0.35)' : '1px solid var(--webcare-border, #e2e8f0)',
                    background: patch.enabled ? 'var(--webcare-bg-surface, rgba(124, 58, 237, 0.02))' : undefined,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
                        <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                          {patch.title}
                        </span>
                        <code style={{ fontSize: '11px', background: 'rgba(124, 58, 237, 0.1)', color: '#7c3aed', padding: '1px 6px', borderRadius: '4px', fontWeight: 700 }}>
                          {patch.patch_id}
                        </code>
                        <span className="webcare-smart-shield-pill-detected-purple" style={{ textTransform: 'uppercase', fontSize: '10px' }}>
                          {patch.vector_type || 'HOTPATCH'}
                        </span>
                        {patch.simulation?.avg_latency_us && (
                          <span style={{ fontSize: '10.5px', color: '#0284c7', fontWeight: 600 }}>
                            ⚡ {patch.simulation.avg_latency_us}us
                          </span>
                        )}
                      </div>
                      <p style={{ margin: '2px 0 6px 0', fontSize: '12.5px', color: 'var(--webcare-text-secondary, #475569)' }}>
                        {patch.description}
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <button
                        type="button"
                        className={`webcare-btn ${patch.enabled ? 'webcare-btn-danger-soft' : 'webcare-action-btn-clean'}`}
                        onClick={() => handleToggleSynthesized(patch.patch_id, !!patch.enabled)}
                        disabled={isBusy}
                        style={{
                          padding: '6px 12px',
                          fontSize: '12px',
                          fontWeight: 700,
                          borderRadius: '6px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          cursor: 'pointer'
                        }}
                      >
                        {isBusy ? <Loader2 size={12} className="webcare-spin-icon" /> : <Shield size={12} />}
                        <span>{patch.enabled ? 'Deactivate' : 'Activate'}</span>
                      </button>

                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={() => handleDeleteSynthesized(patch.patch_id)}
                        disabled={isBusy}
                        style={{
                          background: 'none',
                          border: '1px solid var(--webcare-border, #e2e8f0)',
                          color: '#dc2626',
                          padding: '6px 10px',
                          borderRadius: '6px',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center'
                        }}
                        title="Delete synthesized hotpatch"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>

                  {patch.php_rule?.regex && (
                    <div className="webcare-vp-rule-code-box">
                      <strong>Regex:</strong> <code>{patch.php_rule.regex}</code>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SECTION 2: Curated High-Impact CVE Catalog */}
      <div className="webcare-vp-catalog-card">
        <div
          className="webcare-vp-catalog-header"
          style={{
            padding: '18px 24px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div>
            <h3 className="webcare-vp-catalog-title" style={{ margin: 0, fontSize: '16px', fontWeight: 800 }}>
              Curated High-Impact WordPress CVE Catalog ({data?.catalog?.length || 0})
            </h3>
            <p className="webcare-vp-catalog-desc" style={{ margin: '4px 0 0 0', fontSize: '13px' }}>
              Deploy instant virtual patches to block exploit payloads before vendors publish updates or before maintenance windows.
            </p>
          </div>
        </div>

        <div style={{ padding: '18px 24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {data?.catalog && data.catalog.map((patch) => {
            const isActive = !!activeMap[patch.patch_id]?.enabled;
            const isBusy = patching === patch.patch_id;

            return (
              <div
                key={patch.patch_id}
                className="webcare-firewall-rule-card"
                style={{
                  padding: '16px 20px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  border: isActive ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid var(--webcare-border, #e2e8f0)',
                  background: isActive ? 'var(--webcare-bg-surface, rgba(16, 185, 129, 0.02))' : undefined,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
                      <strong style={{ fontSize: '14px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                        {patch.title}
                      </strong>
                      <code style={{ fontSize: '11px', background: 'rgba(2, 132, 199, 0.1)', color: '#0284c7', padding: '1px 6px', borderRadius: '4px', fontWeight: 700 }}>
                        {patch.cve_id}
                      </code>
                      <span className={patch.severity === 'critical' ? 'webcare-badge-pill webcare-badge-danger' : 'webcare-badge-pill webcare-badge-warning'}>
                        {patch.severity.toUpperCase()}
                      </span>
                    </div>

                    <p style={{ margin: '2px 0 6px 0', fontSize: '12.5px', color: 'var(--webcare-text-secondary, #475569)' }}>
                      {patch.description}
                    </p>
                  </div>

                  <div>
                    {isActive ? (
                      <button
                        type="button"
                        className="webcare-btn webcare-btn-danger-soft"
                        onClick={() => handleRemovePatch(patch.patch_id)}
                        disabled={isBusy}
                        style={{
                          padding: '7px 14px',
                          fontSize: '12.5px',
                          fontWeight: 700,
                          borderRadius: '6px',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        {isBusy ? <Loader2 size={13} className="webcare-spin-icon" /> : <Shield size={13} />}
                        <span>Deactivate Shield</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="webcare-btn"
                        onClick={() => handleApplyPatch(patch.patch_id)}
                        disabled={isBusy}
                        style={{
                          background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                          color: '#ffffff',
                          border: 'none',
                          padding: '7px 16px',
                          fontSize: '12.5px',
                          fontWeight: 700,
                          borderRadius: '6px',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          boxShadow: '0 2px 6px rgba(16, 185, 129, 0.3)'
                        }}
                      >
                        {isBusy ? <Loader2 size={13} className="webcare-spin-icon" /> : <Zap size={13} />}
                        <span>Deploy Shield</span>
                      </button>
                    )}
                  </div>
                </div>

                {patch.php_rule?.regex && (
                  <div className="webcare-vp-rule-code-box">
                    <strong>PHP WAF Rule:</strong> <code>{patch.php_rule.regex}</code>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* SYNTHESIZER STUDIO MODAL */}
      {showSynthesizerModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px'
          }}
          onClick={() => setShowSynthesizerModal(false)}
        >
          <div
            style={{
              background: 'var(--webcare-bg-card, #ffffff)',
              borderRadius: '14px',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              width: '100%',
              maxWidth: '820px',
              maxHeight: '92vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              overflow: 'hidden'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{
              padding: '18px 24px',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--webcare-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Sparkles size={20} color="#7c3aed" />
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Automated CVE Hotpatch Synthesizer &amp; Synthetic Simulation Studio
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowSynthesizerModal(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--webcare-text-muted, #64748b)' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
                <div>
                  <label className="webcare-label">CVE or Vulnerability ID</label>
                  <input
                    type="text"
                    className="webcare-input"
                    placeholder="e.g. CVE-2024-99999 or ZERO-DAY-AUTH"
                    value={synthForm.cve_id}
                    onChange={(e) => setSynthForm({ ...synthForm, cve_id: e.target.value })}
                  />
                </div>

                <div>
                  <label className="webcare-label">Target Plugin / Component</label>
                  <input
                    type="text"
                    className="webcare-input"
                    placeholder="e.g. elementor-pro, woocommerce-custom"
                    value={synthForm.component}
                    onChange={(e) => setSynthForm({ ...synthForm, component: e.target.value })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
                <div>
                  <label className="webcare-label">Exploit Vector Type</label>
                  <select
                    className="webcare-input"
                    value={synthForm.vector_type}
                    onChange={(e) => setSynthForm({ ...synthForm, vector_type: e.target.value })}
                  >
                    <option value="sqli">SQL Injection (SQLi)</option>
                    <option value="rce">Remote Code Execution (RCE)</option>
                    <option value="file_upload">Arbitrary File Upload</option>
                    <option value="auth_bypass">Authentication / Privilege Bypass</option>
                    <option value="path_traversal">Path Traversal &amp; LFI</option>
                    <option value="ssrf">SSRF &amp; Cloud Metadata</option>
                    <option value="custom">Custom Regex Pattern</option>
                  </select>
                </div>

                <div>
                  <label className="webcare-label">Severity Level</label>
                  <select
                    className="webcare-input"
                    value={synthForm.severity}
                    onChange={(e) => setSynthForm({ ...synthForm, severity: e.target.value as any })}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="webcare-label">Target URIs (comma-separated)</label>
                <input
                  type="text"
                  className="webcare-input"
                  placeholder="/wp-admin/admin-ajax.php, /wp-json/plugin/v1/"
                  value={synthForm.target_uris}
                  onChange={(e) => setSynthForm({ ...synthForm, target_uris: e.target.value })}
                />
              </div>

              <div>
                <label className="webcare-label">Vulnerable Parameters (comma-separated)</label>
                <input
                  type="text"
                  className="webcare-input"
                  placeholder="e.g. id, search, file, query"
                  value={synthForm.parameters}
                  onChange={(e) => setSynthForm({ ...synthForm, parameters: e.target.value })}
                />
              </div>

              {synthForm.vector_type === 'custom' && (
                <div>
                  <label className="webcare-label">Custom Regex Pattern</label>
                  <input
                    type="text"
                    className="webcare-input"
                    placeholder="/(\.\.\/|union\s+select)/i"
                    value={synthForm.custom_regex}
                    onChange={(e) => setSynthForm({ ...synthForm, custom_regex: e.target.value })}
                  />
                </div>
              )}

              {/* Simulation Trigger Button */}
              <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <button
                  type="button"
                  className="webcare-btn"
                  onClick={handleCompileAndSimulate}
                  disabled={simulating}
                  style={{
                    background: 'linear-gradient(135deg, #7c3aed 0%, #6366f1 100%)',
                    color: '#ffffff',
                    border: 'none',
                    padding: '9px 18px',
                    fontSize: '13px',
                    fontWeight: 700,
                    borderRadius: '8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: simulating ? 'not-allowed' : 'pointer'
                  }}
                >
                  {simulating ? <Loader2 size={15} className="webcare-spin-icon" /> : <Play size={15} />}
                  <span>Compile &amp; Run In-Memory Dry-Run Simulation</span>
                </button>
              </div>

              {/* Simulation Calibration Benchmark Report */}
              {simulationReport && (
                <div style={{
                  padding: '16px 20px',
                  borderRadius: '10px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle2 size={16} color="#16a34a" /> In-Memory Simulation Benchmark Results
                    </strong>
                    <span className="webcare-smart-shield-pill-detected-emerald" style={{ fontSize: '10px' }}>
                      STATUS: {simulationReport.status.toUpperCase()}
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '10px' }}>
                    <div style={{ background: 'var(--webcare-bg-elevated, #ffffff)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                      <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Attack Match Rate</div>
                      <div style={{ fontSize: '18px', fontWeight: 900, color: '#16a34a', marginTop: '2px' }}>
                        {simulationReport.attack_match_rate}%
                      </div>
                    </div>

                    <div style={{ background: 'var(--webcare-bg-elevated, #ffffff)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                      <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Benign Pass Rate</div>
                      <div style={{ fontSize: '18px', fontWeight: 900, color: '#0284c7', marginTop: '2px' }}>
                        {simulationReport.benign_pass_rate}%
                      </div>
                    </div>

                    <div style={{ background: 'var(--webcare-bg-elevated, #ffffff)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                      <div style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Execution Latency</div>
                      <div style={{ fontSize: '18px', fontWeight: 900, color: '#7c3aed', marginTop: '2px' }}>
                        {simulationReport.avg_latency_us} us
                      </div>
                      <span style={{ fontSize: '10px', color: '#16a34a' }}>&lt; 0.08ms overhead</span>
                    </div>
                  </div>

                  {/* Traces */}
                  <div>
                    <div style={{ fontSize: '11.5px', fontWeight: 700, marginBottom: '6px' }}>Payload Test Traces:</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxHeight: '160px', overflowY: 'auto' }}>
                      {simulationReport.traces.map((t: any, i: number) => (
                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 8px', background: 'var(--webcare-bg-card, #ffffff)', borderRadius: '4px', fontSize: '11px' }}>
                          <span style={{ color: t.type === 'attack' ? '#dc2626' : '#16a34a', fontWeight: 600 }}>{t.name}</span>
                          <span style={{ color: t.passed ? '#16a34a' : '#dc2626', fontWeight: 800 }}>{t.passed ? '✓ PASSED' : '✗ FAILED'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Cloudflare Edge Option */}
              {candidatePatch && (
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={deployToCloudflare}
                    onChange={(e) => setDeployToCloudflare(e.target.checked)}
                    style={{ width: '16px', height: '16px', accentColor: '#ea580c' }}
                  />
                  <span>Push compiled wirefilter expression to Cloudflare Global Edge WAF</span>
                </label>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '14px 24px',
              borderTop: '1px solid var(--webcare-border, #e2e8f0)',
              background: 'var(--webcare-bg-elevated, #f8fafc)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setShowSynthesizerModal(false)}
                style={{ background: 'none', border: '1px solid var(--webcare-border, #e2e8f0)', color: 'var(--webcare-text-primary, #0f172a)', padding: '7px 16px', borderRadius: '6px', fontSize: '12.5px' }}
              >
                Cancel
              </button>

              <button
                type="button"
                className="webcare-btn"
                onClick={handleDeployCandidate}
                disabled={synthesizing || !candidatePatch}
                style={{
                  background: candidatePatch ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)' : '#94a3b8',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 20px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: candidatePatch ? 'pointer' : 'not-allowed',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                {synthesizing && <Loader2 size={14} className="webcare-spin-icon" />}
                <span>Deploy Hotpatch Now</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Solo Freelancer 1-on-1 Assistance Banner */}
      {onNavigateToSupport && (
        <div className="webcare-vp-expert-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="webcare-vp-expert-icon-box">
              <Phone size={18} />
            </div>
            <div>
              <div className="webcare-vp-expert-title">
                Need Custom Exploit Shielding or 0-Day Virtual Patching?
              </div>
              <div className="webcare-vp-expert-desc">
                Connect directly with Mir Alamin (WebCare Pro) to inspect zero-day threat vectors, configure Cloudflare edge security rules, and audit vulnerable code.
              </div>
            </div>
          </div>

          <button
            type="button"
            className="webcare-btn"
            onClick={onNavigateToSupport}
            style={{
              background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
              color: '#ffffff',
              border: 'none',
              fontSize: '12px',
              fontWeight: 700,
              padding: '8px 16px',
              borderRadius: '8px',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span>Connect With Mir Alamin Directly</span>
            <ArrowUpRight size={13} />
          </button>
        </div>
      )}
    </div>
  );
}
