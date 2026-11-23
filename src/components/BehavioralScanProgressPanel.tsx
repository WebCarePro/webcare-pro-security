import React, { useEffect, useId, useRef, useState } from '@wordpress/element';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Cpu,
  FileCode,
  Gauge,
  Hourglass,
  Layers,
  Pause,
  Play,
  Radar,
  RotateCcw,
  Shield,
  ShieldAlert,
  Terminal,
  X
} from 'lucide-react';
import {
  BehavioralScanProgress,
  PHASE_STEPS,
  formatDuration,
  formatEta
} from '../utils/scanTelemetry';

interface BehavioralScanProgressPanelProps {
  scanning: boolean;
  isPaused?: boolean;
  scanProgress: BehavioralScanProgress | null;
  liveElapsedSeconds: number;
  rulesCount?: number;
  vaultSummary?: any;
  scanError?: string | null;
  mode?: 'studio' | 'wizard';
  onDismiss?: () => void;
  onPause?: () => void;
  onResume?: () => void;
  onCancel?: () => void;
}

export const BehavioralScanProgressPanel: React.FC<BehavioralScanProgressPanelProps> = ({
  scanning,
  isPaused = false,
  scanProgress,
  liveElapsedSeconds,
  rulesCount = 0,
  vaultSummary = null,
  scanError = null,
  mode = 'studio',
  onDismiss,
  onPause,
  onResume,
  onCancel,
}) => {
  const progressId = useId();
  const labelId = useId();
  const counters = scanProgress?.counters || vaultSummary?.counters || {};

  const totalFiles = Number(scanProgress?.total_files ?? vaultSummary?.total_files ?? 0);
  const effectivePaused = Boolean(
    !scanning &&
      (isPaused || scanProgress?.status === 'paused' || scanProgress?.is_stale)
  );
  const isCompleted =
    !scanning &&
    !effectivePaused &&
    Boolean(
      scanProgress?.is_completed ||
        scanProgress?.status === 'completed' ||
        scanProgress?.status === 'idle_with_results' ||
        vaultSummary?.last_scan
    );
  const processedFiles = isCompleted
    ? totalFiles || Number(counters.files_tokenized ?? 0)
    : Number(scanProgress?.processed_files ?? counters.files_tokenized ?? 0);
  const remainingFiles = isCompleted
    ? 0
    : Math.max(0, Number(scanProgress?.remaining_files ?? Math.max(0, totalFiles - processedFiles)));

  const pctRaw =
    totalFiles > 0
      ? Math.min(100, Math.round((processedFiles / totalFiles) * 1000) / 10)
      : isCompleted
      ? 100
      : Number(scanProgress?.progress_pct ?? 0);

  const isIndeterminate = scanning && totalFiles === 0;
  const elapsedToShow = scanning
    ? liveElapsedSeconds
    : effectivePaused
    ? Number(scanProgress?.elapsed_seconds ?? 0)
    : Number(scanProgress?.elapsed_seconds ?? vaultSummary?.last_duration_seconds ?? 0);

  const serverSpeed = Number(
    scanProgress?.files_per_sec ??
      (isCompleted ? vaultSummary?.last_files_per_sec : 0) ??
      0
  );
  const derivedSpeed =
    serverSpeed > 0
      ? serverSpeed
      : processedFiles > 0 && elapsedToShow > 0.2
      ? Math.round((processedFiles / elapsedToShow) * 10) / 10
      : 0;

  let etaSeconds: number | null =
    scanProgress?.estimated_remaining_seconds !== undefined
      ? scanProgress.estimated_remaining_seconds
      : null;
  if ((scanning || effectivePaused) && etaSeconds === null && processedFiles >= 5 && derivedSpeed > 0) {
    etaSeconds = Math.ceil(remainingFiles / derivedSpeed);
  }
  if (isCompleted) {
    etaSeconds = 0;
  }

  const currentPhase = Math.max(1, Math.min(6, Number(scanProgress?.current_phase ?? (isCompleted ? 6 : 1))));
  const phaseLabel =
    scanProgress?.phase_label ||
    PHASE_STEPS.find((s) => s.id === currentPhase)?.label ||
    'AST Tokenization';

  const totalComponents = Number(
    scanProgress?.total_components ?? vaultSummary?.total_components ?? 0
  );
  const componentsScanned = isCompleted
    ? totalComponents
    : Number(scanProgress?.components_scanned ?? 0);

  const endpointsMapped =
    Number(counters.ajax_hooks_found || 0) + Number(counters.rest_routes_found || 0);
  const risksDetected =
    Number(counters.permissive_rest_routes || 0) + Number(counters.taint_sinks_found || 0);
  const missingAbspath = Number(counters.missing_abspath_files ?? 0);
  const tamperedFiles = Number(counters.tampered_files_found ?? 0);
  const cveCount = Number(counters.cve_vulnerabilities ?? 0);
  const outdatedCount = Number(counters.outdated_components ?? 0);
  const synthesizedRules = rulesCount || Number(counters.rules_synthesized ?? 0);

  // Polite announcement string updated ONLY on major lifecycle boundaries (start, phase change, error, finish)
  const [announcement, setAnnouncement] = useState('');
  const lastPhaseRef = useRef<number | null>(null);
  const wasScanningRef = useRef<boolean>(false);

  useEffect(() => {
    if (scanError) {
      setAnnouncement(`Behavioral AST scan stopped: ${scanError}`);
      wasScanningRef.current = false;
      return;
    }
    if (scanning && !wasScanningRef.current) {
      wasScanningRef.current = true;
      lastPhaseRef.current = currentPhase;
      setAnnouncement(
        totalFiles > 0
          ? `Behavioral AST scan started across ${totalFiles} PHP files.`
          : 'Behavioral AST scan started.'
      );
      return;
    }
    if (scanning && lastPhaseRef.current !== currentPhase) {
      lastPhaseRef.current = currentPhase;
      setAnnouncement(`Scan phase ${currentPhase} of 6: ${phaseLabel}.`);
      return;
    }
    if (!scanning && wasScanningRef.current) {
      wasScanningRef.current = false;
      setAnnouncement(
        `Behavioral AST scan complete. Scanned ${processedFiles} files and synthesized ${synthesizedRules} rules.`
      );
    }
  }, [scanning, currentPhase, phaseLabel, totalFiles, processedFiles, synthesizedRules, scanError]);

  const statusTone = (scanError && !isCompleted)
    ? 'is-error'
    : scanning
    ? 'is-scanning'
    : effectivePaused
    ? 'is-paused'
    : isCompleted
    ? 'is-complete'
    : 'is-idle';

  return (
    <section
      className={`webcare-ast-telemetry-card ${statusTone} ${mode === 'wizard' ? 'is-wizard' : ''}`}
      aria-labelledby={labelId}
    >
      {/* Screen-reader polite status notifications ONLY at lifecycle transitions */}
      <div className="webcare-sr-only" role="status" aria-live="polite" aria-atomic="true">
        {announcement}
      </div>

      {/* Top Header Row */}
      <div className="webcare-ast-telemetry-header">
        <div className="webcare-ast-telemetry-title-wrap">
          <div className={`webcare-ast-pulse-dot ${statusTone}`} aria-hidden="true" />
          <div>
            <label id={labelId} htmlFor={progressId} className="webcare-ast-telemetry-title">
              {(scanError && !isCompleted)
                ? 'AST Scan Interrupted'
                : scanning
                ? `Phase ${currentPhase}/6: ${phaseLabel}`
                : effectivePaused
                ? scanProgress?.is_stale
                  ? `Paused Scan Session Ready to Resume • Phase ${currentPhase}/6`
                  : `Behavioral AST Scan Paused • Phase ${currentPhase}/6: ${phaseLabel}`
                : isCompleted
                ? 'Behavioral AST Scan Complete • Vault Sealed'
                : 'Awaiting Initial Behavioral AST Scan'}
            </label>
            <div className="webcare-ast-telemetry-subtitle">
              {scanning
                ? totalFiles > 0
                  ? `Analyzing ${processedFiles.toLocaleString()} of ${totalFiles.toLocaleString()} queued PHP files (${remainingFiles.toLocaleString()} remaining)${scanProgress?.background_cron_scheduled ? ' • WP-Cron fallback armed' : ''}`
                  : 'Enumerating plugins, themes, and PHP entry scripts...'
                : effectivePaused
                ? `${processedFiles.toLocaleString()} of ${totalFiles.toLocaleString()} files scanned (${remainingFiles.toLocaleString()} remaining) • Click Resume Scan to continue from saved checkpoint`
                : isCompleted
                ? `Inspected ${processedFiles.toLocaleString()} PHP files across ${totalComponents} extensions in ${formatDuration(elapsedToShow)}`
                : 'Click "Run Full Behavioral Scan" to tokenize PHP extensions, map routes, and verify checksums.'}
            </div>
          </div>
        </div>

        <div className="webcare-ast-telemetry-badges">
          {scanning && onPause && (
            <button
              type="button"
              onClick={onPause}
              className="webcare-ast-ctrl-btn is-pause"
              title="Pause scan cleanly without losing progress"
            >
              <Pause size={12} />
              <span>Pause</span>
            </button>
          )}
          {effectivePaused && onResume && (
            <button
              type="button"
              onClick={onResume}
              className="webcare-ast-ctrl-btn is-resume"
              title="Resume AST scan from saved checkpoint"
            >
              <Play size={12} />
              <span>Resume Scan</span>
            </button>
          )}
          {(scanning || effectivePaused) && onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="webcare-ast-ctrl-btn is-cancel"
              title="Cancel this scan session and keep existing Vault rules"
            >
              <RotateCcw size={12} />
              <span>Cancel</span>
            </button>
          )}
          <span className={`webcare-ast-pct-pill ${statusTone}`}>
            {isIndeterminate ? 'Initializing...' : `${pctRaw.toFixed(1)}%`}
          </span>
          {!scanning && onDismiss && (
            <button
              type="button"
              className="webcare-ast-close-btn"
              onClick={onDismiss}
              aria-label="Hide scan telemetry panel"
            >
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Error banner if interrupted */}
      {(scanError && !isCompleted) && (
        <div className="webcare-ast-error-banner" role="alert">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>{scanError}</span>
        </div>
      )}

      {/* Semantic Native <progress> Bar */}
      <div className="webcare-ast-progress-wrap">
        <progress
          id={progressId}
          className={`webcare-ast-progress ${statusTone}`}
          max={100}
          value={isIndeterminate ? undefined : pctRaw}
          aria-labelledby={labelId}
        />
      </div>

      {/* Core Progress KPIs Requested: Total/Scanned, Speed (files/s), Elapsed, Time Remaining */}
      <div className="webcare-ast-kpi-grid">
        <div className="webcare-ast-kpi-card">
          <div className="webcare-ast-kpi-label">
            <FileCode size={13} aria-hidden="true" /> Files Checked / Total
          </div>
          <div className="webcare-ast-kpi-value webcare-tabular-nums">
            {processedFiles.toLocaleString()} <span className="webcare-ast-kpi-denom">/ {totalFiles.toLocaleString()}</span>
          </div>
          <div className="webcare-ast-kpi-sub webcare-tabular-nums">
            {remainingFiles.toLocaleString()} left • {componentsScanned}/{totalComponents} extensions
          </div>
        </div>

        <div className="webcare-ast-kpi-card">
          <div className="webcare-ast-kpi-label">
            <Gauge size={13} aria-hidden="true" /> Processing Speed
          </div>
          <div className="webcare-ast-kpi-value webcare-tabular-nums is-accent">
            {derivedSpeed.toFixed(1)} <span className="webcare-ast-kpi-unit">files/s</span>
          </div>
          <div className="webcare-ast-kpi-sub webcare-tabular-nums">
            {scanProgress?.last_batch_files
              ? `Last batch: ${scanProgress.last_batch_files} files (${scanProgress.last_batch_ms || 0}ms)`
              : scanning
              ? 'Warming up PHP tokenizer...'
              : 'Average AST throughput'}
          </div>
        </div>

        <div className="webcare-ast-kpi-card">
          <div className="webcare-ast-kpi-label">
            <Clock size={13} aria-hidden="true" /> Time Elapsed
          </div>
          <div className="webcare-ast-kpi-value webcare-tabular-nums">
            {formatDuration(elapsedToShow)}
          </div>
          <div className="webcare-ast-kpi-sub">
            {scanning ? 'Live scan duration' : isCompleted ? 'Total scan runtime' : 'Not started'}
          </div>
        </div>

        <div className="webcare-ast-kpi-card">
          <div className="webcare-ast-kpi-label">
            <Hourglass size={13} aria-hidden="true" /> Time Remaining (ETA)
          </div>
          <div
            className={`webcare-ast-kpi-value webcare-tabular-nums ${
              isCompleted ? 'is-clean' : ''
            }`}
          >
            {formatEta(etaSeconds, scanning, isCompleted, effectivePaused)}
          </div>
          <div className="webcare-ast-kpi-sub">
            {isCompleted
              ? 'All queued files scanned'
              : scanning && etaSeconds !== null
              ? `At ${derivedSpeed.toFixed(1)} files/sec pace`
              : scanning
              ? 'Computing ETA from batch rate...'
              : 'Ready on next scan'}
          </div>
        </div>
      </div>

      {/* Live Current Target Bar (Active Component + PHP File Path) */}
      {(scanning || scanProgress?.current_component || scanProgress?.current_file) && (
        <div className="webcare-ast-live-target-bar">
          <div className="webcare-ast-live-target-item">
            <Cpu size={13} aria-hidden="true" />
            <span className="webcare-ast-live-key">Current Component:</span>
            <strong>{scanProgress?.current_component || 'Preparing file queue...'}</strong>
          </div>
          {scanProgress?.current_file && (
            <div className="webcare-ast-live-target-file">
              <Terminal size={13} aria-hidden="true" />
              <code className="webcare-ast-file-code">{scanProgress.current_file}</code>
            </div>
          )}
        </div>
      )}

      {/* 6-Stage Behavioral Pipeline Stepper */}
      <div className="webcare-ast-phase-stepper" aria-label="AST analysis pipeline stages">
        {PHASE_STEPS.map((step) => {
          const isStepDone = isCompleted || currentPhase > step.id;
          const isStepActive = scanning && currentPhase === step.id;
          return (
            <div
              key={step.id}
              className={`webcare-ast-phase-step ${
                isStepDone ? 'is-done' : isStepActive ? 'is-active' : 'is-pending'
              }`}
              title={step.label}
            >
              <span className="webcare-ast-step-num" aria-hidden="true">
                {isStepDone ? <Check size={11} /> : step.id}
              </span>
              <span className="webcare-ast-step-label">{step.shortLabel}</span>
            </div>
          );
        })}
      </div>

      {/* Detailed Forensic Discovery Counters Grid */}
      <div className="webcare-ast-counters-grid">
        <div className="webcare-ast-counter-tile">
          <div className="webcare-ast-counter-label">
            <Layers size={12} aria-hidden="true" /> Endpoints Mapped
          </div>
          <div className="webcare-ast-counter-val webcare-tabular-nums">{endpointsMapped}</div>
          <div className="webcare-ast-counter-sub">
            {counters.ajax_hooks_found || 0} AJAX • {counters.rest_routes_found || 0} REST
          </div>
        </div>

        <div className="webcare-ast-counter-tile">
          <div className="webcare-ast-counter-label is-high">
            <Radar size={12} aria-hidden="true" /> REST / Taint Sinks
          </div>
          <div className="webcare-ast-counter-val is-high webcare-tabular-nums">{risksDetected}</div>
          <div className="webcare-ast-counter-sub">
            {counters.permissive_rest_routes || 0} REST • {counters.taint_sinks_found || 0} Sinks
          </div>
        </div>

        <div className="webcare-ast-counter-tile">
          <div className="webcare-ast-counter-label is-critical">
            <ShieldAlert size={12} aria-hidden="true" /> Missing ABSPATH
          </div>
          <div className="webcare-ast-counter-val is-critical webcare-tabular-nums">
            {missingAbspath}
          </div>
          <div className="webcare-ast-counter-sub">
            {tamperedFiles > 0 ? `${tamperedFiles} tamper alerts` : 'Direct HTTP entry checks'}
          </div>
        </div>

        <div className="webcare-ast-counter-tile">
          <div className="webcare-ast-counter-label is-warn">
            <Activity size={12} aria-hidden="true" /> CVEs &amp; Outdated
          </div>
          <div className="webcare-ast-counter-val is-warn webcare-tabular-nums">
            {cveCount} / {outdatedCount}
          </div>
          <div className="webcare-ast-counter-sub">Advisories • Pending updates</div>
        </div>

        <div className="webcare-ast-counter-tile">
          <div className="webcare-ast-counter-label is-indigo">
            <Shield size={12} aria-hidden="true" /> Rules Synthesized
          </div>
          <div className="webcare-ast-counter-val is-indigo webcare-tabular-nums">
            {synthesizedRules}
          </div>
          <div className="webcare-ast-counter-sub">
            {isCompleted ? (
              <span className="webcare-ast-inline-clean">
                <CheckCircle2 size={11} aria-hidden="true" /> HMAC Vault Sealed
              </span>
            ) : (
              'Tailored firewall rules'
            )}
          </div>
        </div>
      </div>
    </section>
  );
};
