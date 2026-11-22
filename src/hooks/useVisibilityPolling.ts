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
  const inFlightRef = useRef<boolean>(false);
  const generationRef = useRef<number>(0);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!enabled || !intervalMs || intervalMs <= 0) {
      return;
    }

    let isMounted = true;

    const executeTick = () => {
      if (typeof document !== 'undefined' && document.hidden) {
        return;
      }
      if (inFlightRef.current) {
        return;
      }

      inFlightRef.current = true;
      const currentGen = ++generationRef.current;
      
      // Abort any prior in-flight controller and instantiate new AbortController
      if (abortControllerRef.current) {
        try {
          abortControllerRef.current.abort();
        } catch (_) {}
      }
      abortControllerRef.current = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const signal = abortControllerRef.current ? abortControllerRef.current.signal : undefined;

      Promise.resolve()
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
          if (currentGen === generationRef.current) {
            inFlightRef.current = false;
            abortControllerRef.current = null;
          }
        });
    };

    const intervalId = setInterval(executeTick, intervalMs);

    const handleVisibilityChange = () => {
      if (typeof document !== 'undefined' && !document.hidden && isMounted) {
        // Trigger immediate catch-up tick on tab return if not already in-flight
        executeTick();
      }
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    return () => {
      isMounted = false;
      // Invalidate the generation so any in-flight promise from this cycle cannot reset state
      generationRef.current++;
      // Actively cancel and abort any active network request on unmount / re-render
      if (abortControllerRef.current) {
        try {
          abortControllerRef.current.abort();
        } catch (_) {}
        abortControllerRef.current = null;
      }
      // Keep inFlightRef true until async finally resolves, preventing overlapping requests on remount
      // while an asynchronous callback is still executing
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

