import { useEffect, useRef } from '@wordpress/element';

/**
 * useVisibilityPolling
 *
 * Runs an asynchronous polling callback on an interval, automatically pausing
 * ticks when the document is hidden (`document.hidden === true`), and immediately
 * executing a catch-up poll when the user focuses or switches back to the tab.
 *
 * Hardened with Promise rejection handling and an in-flight overlap guard so
 * rapid visibility toggles or slow network responses never fire overlapping requests.
 *
 * @param callback Async function or function to execute on each tick
 * @param intervalMs Interval in milliseconds (pass null or 0 to disable)
 * @param enabled Whether polling is active
 */
export function useVisibilityPolling(
  callback: (signal?: AbortSignal) => void | Promise<void>,
  intervalMs: number | null | undefined,
  enabled: boolean = true
): void {
  const savedCallback = useRef(callback);
  savedCallback.current = callback;
  const inFlightPromiseRef = useRef<Promise<void> | null>(null);
  const activeControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!enabled || !intervalMs || intervalMs <= 0) {
      return;
    }

    let isEffectActive = true;

    const executeTick = () => {
      if (typeof document !== 'undefined' && document.hidden) {
        return;
      }
      // If a request is already executing, wait for it rather than starting a concurrent execution
      if (inFlightPromiseRef.current !== null) {
        return;
      }

      // Abort previous controller if any was dangling
      if (activeControllerRef.current) {
        try {
          activeControllerRef.current.abort();
        } catch (_) {}
      }

      const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      activeControllerRef.current = controller;
      const signal = controller ? controller.signal : undefined;

      const currentExecution = Promise.resolve()
        .then(() => savedCallback.current(signal))
        .catch((err) => {
          if (err && (err.name === 'AbortError' || err.code === 20)) {
            return;
          }
          if (process.env.NODE_ENV !== 'production') {
            console.warn('[WebCare] Visibility polling callback failed:', err);
          }
        })
        .finally(() => {
          // Release execution ownership strictly for THIS execution promise
          if (inFlightPromiseRef.current === currentExecution) {
            inFlightPromiseRef.current = null;
          }
          if (activeControllerRef.current === controller) {
            activeControllerRef.current = null;
          }
        });

      inFlightPromiseRef.current = currentExecution;
    };

    const intervalId = setInterval(executeTick, intervalMs);

    const handleVisibilityChange = () => {
      if (typeof document !== 'undefined' && !document.hidden && isEffectActive) {
        executeTick();
      }
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    return () => {
      isEffectActive = false;
      // Abort in-flight network request on cleanup
      if (activeControllerRef.current) {
        try {
          activeControllerRef.current.abort();
        } catch (_) {}
      }
      // Note: inFlightPromiseRef remains non-null until currentExecution's finally resolves,
      // guaranteeing that an asynchronous callback still executing across effect cleanup/re-render
      // cannot overlap with a new effect tick.
      clearInterval(intervalId);
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', handleVisibilityChange);
      }
    };
  }, [intervalMs, enabled]);
}

/**
 * isDocumentVisible
 * Helper function to check if the current document is visible.
 */
export function isDocumentVisible(): boolean {
  return typeof document === 'undefined' || !document.hidden;
}

