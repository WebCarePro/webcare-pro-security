import { useState, useEffect, useRef, useCallback } from '@wordpress/element';
import { apiRequest } from './api';

export interface BehavioralScanCounters {
  files_tokenized?: number;
  ajax_hooks_found?: number;
  unprotected_ajax_hooks?: number;
  rest_routes_found?: number;
  permissive_rest_routes?: number;
  missing_abspath_files?: number;
  tampered_files_found?: number;
  taint_sinks_found?: number;
  cve_vulnerabilities?: number;
  outdated_components?: number;
  abandoned_components?: number;
  rules_synthesized?: number;
}

export interface BehavioralScanProgress {
  success?: boolean;
  session_id?: string;
  status?: string;
  progress_pct?: number;
  current_phase?: number;
  phase_label?: string;
  phase_labels?: Record<string, string>;
  total_files?: number;
  processed_files?: number;
  remaining_files?: number;
  total_components?: number;
  components_scanned?: number;
  current_component?: string;
  current_file?: string;
  files_per_sec?: number;
  batch_files_per_sec?: number;
  last_batch_files?: number;
  last_batch_ms?: number;
  started_at?: number;
  completed_at?: number | null;
  elapsed_seconds?: number;
  estimated_remaining_seconds?: number | null;
  is_stale?: boolean;
  background_cron_scheduled?: boolean;
  updated_at?: number;
  counters?: BehavioralScanCounters;
  is_completed?: boolean;
  message?: string;
}

export const PHASE_STEPS: Array<{ id: number; shortLabel: string; label: string }> = [
  { id: 1, shortLabel: 'Census', label: 'Extension & Version Census' },
  { id: 2, shortLabel: 'Hooks & AST', label: 'Hook Registrations & functions.php AST' },
  { id: 3, shortLabel: 'REST Surface', label: 'REST API & Public Route Attack-Surface' },
  { id: 4, shortLabel: 'Taint & Sinks', label: 'Source-to-Sink Taint & Vulnerability Hunter' },
  { id: 5, shortLabel: 'Direct Scripts', label: 'Direct-Access Script & Missing ABSPATH Discovery' },
  { id: 6, shortLabel: 'Synthesis', label: 'Modular Firewall Rule Synthesis & Simulation' },
];

/**
 * Format elapsed seconds as crisp tabular duration (e.g. "00:24", "1m 14s", or "1h 05m 10s").
 */
export function formatDuration(totalSeconds: number): string {
  const clean = Math.max(0, Math.floor(totalSeconds));
  const hrs = Math.floor(clean / 3600);
  const mins = Math.floor((clean % 3600) / 60);
  const secs = clean % 60;
  const pad = (n: number) => String(n).padStart(2, '0');

  if (hrs > 0) {
    return `${hrs}h ${pad(mins)}m ${pad(secs)}s`;
  }
  if (mins > 0) {
    return `${mins}m ${pad(secs)}s`;
  }
  return `00:${pad(secs)}`;
}

/**
 * Format estimated time remaining for the live telemetry grid.
 */
export function formatEta(
  etaSeconds: number | null | undefined,
  isScanning: boolean,
  isCompleted: boolean,
  isPaused = false
): string {
  if (isCompleted) {
    return '00:00 (Done)';
  }
  if (!isScanning && !isPaused) {
    return 'Idle';
  }
  if (etaSeconds === null || etaSeconds === undefined || Number.isNaN(etaSeconds)) {
    return isPaused ? 'Paused' : 'Calculating...';
  }
  if (etaSeconds <= 1) {
    return isPaused ? '< 2s left (Paused)' : '< 2s left';
  }
  return isPaused ? `~${formatDuration(etaSeconds)} left (Paused)` : `~${formatDuration(etaSeconds)} left`;
}

interface UseBehavioralScanRunnerOptions {
  onScanComplete?: (finalProgress: BehavioralScanProgress) => Promise<void> | void;
  onScanError?: (message: string) => void;
}

/**
 * Shared sequential batch scan controller with jitter-free 1-second elapsed timer.
 * Uses awaited sequential batches instead of overlapping setInterval calls so WordPress
 * option writes never race under slow batches.
 */
export function useBehavioralScanRunner(options: UseBehavioralScanRunnerOptions = {}) {
  const [scanning, setScanning] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [scanProgress, setScanProgress] = useState<BehavioralScanProgress | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [liveElapsedSeconds, setLiveElapsedSeconds] = useState(0);

  const mountedRef = useRef(true);
  const loopActiveRef = useRef(false);
  const snapshotTimeRef = useRef<{ baseElapsed: number; capturedAtMs: number }>({
    baseElapsed: 0,
    capturedAtMs: Date.now(),
  });

  const onCompleteRef = useRef(options.onScanComplete);
  const onErrorRef = useRef(options.onScanError);
  onCompleteRef.current = options.onScanComplete;
  onErrorRef.current = options.onScanError;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      loopActiveRef.current = false;
    };
  }, []);

  const syncProgressSnapshot = useCallback((next: BehavioralScanProgress | null) => {
    setScanProgress(next);
    if (!next) {
      return;
    }
    const baseElapsed = Math.max(0, Number(next.elapsed_seconds ?? 0));
    snapshotTimeRef.current = {
      baseElapsed,
      capturedAtMs: Date.now(),
    };
    setLiveElapsedSeconds(baseElapsed);
    if (next.status === 'running' && !next.is_stale) {
      setScanning(true);
    } else {
      setScanning(false);
    }
  }, []);

  // Client 1s live elapsed ticker synchronized against the latest backend snapshot
  useEffect(() => {
    if (!scanning) {
      return;
    }
    const tick = setInterval(() => {
      if (!mountedRef.current) return;
      if (typeof document !== 'undefined' && document.hidden) return;
      const deltaSec = (Date.now() - snapshotTimeRef.current.capturedAtMs) / 1000;
      setLiveElapsedSeconds(Math.max(0, snapshotTimeRef.current.baseElapsed + deltaSec));
    }, 1000);
    return () => clearInterval(tick);
  }, [scanning]);

  // Sequential awaited batch processor while scanning === true
  useEffect(() => {
    if (!scanning || isInitializing || loopActiveRef.current) {
      return;
    }

    let cancelled = false;
    loopActiveRef.current = true;

    const runLoop = async () => {
      while (!cancelled && mountedRef.current) {
        try {
          const res: BehavioralScanProgress = await apiRequest({
            path: '/custom-rules/scan/batch',
            method: 'POST',
            data: { batch_size: 400 },
          });

          if (cancelled || !mountedRef.current) {
            break;
          }

          if (!res) {
            break;
          }

          if (res.success === false) {
            setScanError(res.message || 'Scan session interrupted.');
            setScanning(false);
            if (onErrorRef.current && res.message) {
              onErrorRef.current(res.message);
            }
            break;
          }

          setScanError(null);
          syncProgressSnapshot(res);

          if (res.status === 'completed' || res.is_completed) {
            setScanning(false);
            setScanError(null);
            if (onCompleteRef.current) {
              await onCompleteRef.current(res);
            }
            break;
          }

          // Brief yield between batches so UI paints smoothly without hammering PHP workers
          await new Promise((resolve) => setTimeout(resolve, 140));
        } catch (err: any) {
          if (cancelled || !mountedRef.current) {
            break;
          }
          const msg = err?.message || 'Batch scan request failed.';
          setScanError(msg);
          setScanning(false);
          if (onErrorRef.current) {
            onErrorRef.current(msg);
          }
          break;
        }
      }
      loopActiveRef.current = false;
    };

    runLoop();

    return () => {
      cancelled = true;
      loopActiveRef.current = false;
    };
  }, [scanning, isInitializing, syncProgressSnapshot]);

  const startScan = useCallback(async (): Promise<BehavioralScanProgress | null> => {
    setScanError(null);
    setIsInitializing(true);
    snapshotTimeRef.current = { baseElapsed: 0, capturedAtMs: Date.now() };
    setLiveElapsedSeconds(0);

    try {
      const res: BehavioralScanProgress = await apiRequest({
        path: '/custom-rules/scan/start',
        method: 'POST',
        data: { force_rescan: true },
      });

      if (res && res.success) {
        setScanError(null);
        syncProgressSnapshot(res);
        setScanning(true);
        return res;
      }

      const msg = res?.message || 'Failed to initialize behavioral AST scan.';
      setScanError(msg);
      setScanning(false);
      if (onErrorRef.current) {
        onErrorRef.current(msg);
      }
      return null;
    } catch (err: any) {
      const msg = err?.message || 'Failed to initialize behavioral AST scan.';
      setScanError(msg);
      setScanning(false);
      if (onErrorRef.current) {
        onErrorRef.current(msg);
      }
      return null;
    } finally {
      setIsInitializing(false);
    }
  }, [syncProgressSnapshot]);

  const pauseScan = useCallback(async (): Promise<BehavioralScanProgress | null> => {
    setScanning(false);
    try {
      const res: BehavioralScanProgress = await apiRequest({
        path: '/custom-rules/scan/pause',
        method: 'POST',
      });
      if (res && res.success) {
        syncProgressSnapshot(res);
      }
      return res || null;
    } catch (err) {
      console.error('Failed to pause scan:', err);
      return null;
    }
  }, [syncProgressSnapshot]);

  const resumeScan = useCallback(async (): Promise<BehavioralScanProgress | null> => {
    setScanError(null);
    try {
      const res: BehavioralScanProgress = await apiRequest({
        path: '/custom-rules/scan/resume',
        method: 'POST',
      });
      if (res && res.success) {
        syncProgressSnapshot({ ...res, is_stale: false, status: 'running' });
        setScanning(true);
        return res;
      }
      return null;
    } catch (err: any) {
      const msg = err?.message || 'Failed to resume behavioral AST scan.';
      setScanError(msg);
      if (onErrorRef.current) onErrorRef.current(msg);
      return null;
    }
  }, [syncProgressSnapshot]);

  const cancelScan = useCallback(async (): Promise<BehavioralScanProgress | null> => {
    setScanning(false);
    setScanError(null);
    try {
      const res: BehavioralScanProgress = await apiRequest({
        path: '/custom-rules/scan/cancel',
        method: 'POST',
      });
      if (res && res.success) {
        syncProgressSnapshot(res);
      }
      return res || null;
    } catch (err) {
      console.error('Failed to cancel scan:', err);
      return null;
    }
  }, [syncProgressSnapshot]);

  const isPaused = Boolean(
    !scanning &&
      scanProgress &&
      (scanProgress.status === 'paused' || (scanProgress.status === 'running' && scanProgress.is_stale))
  );

  return {
    scanning: scanning || isInitializing,
    isPaused,
    setScanning,
    scanProgress,
    syncProgressSnapshot,
    liveElapsedSeconds,
    scanError,
    startScan,
    pauseScan,
    resumeScan,
    cancelScan,
  };
}
