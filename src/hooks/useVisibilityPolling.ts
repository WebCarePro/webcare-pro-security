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
  const activeTokenRef = useRef<symbol | null>(null);
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
      const requestToken = Symbol('polling_request');
      activeTokenRef.current = requestToken;
      
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
          // If this request is still the active token, clear inFlight and controller
          if (activeTokenRef.current === requestToken) {
            inFlightRef.current = false;
            activeTokenRef.current = null;
            abortControllerRef.current = null;
          } else if (activeTokenRef.current === null) {
            // If the effect was cleaned up (which nulled activeTokenRef), always release inFlight ownership
            // so subsequent effects or remounts are never permanently locked
            inFlightRef.current = false;
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
      // Invalidate active token and cancel active network request
      activeTokenRef.current = null;
      if (abortControllerRef.current) {
        try {
          abortControllerRef.current.abort();
        } catch (_) {}
        abortControllerRef.current = null;
      }
      // Release inFlightRef immediately on cleanup if no request is active,
      // or the async finally block will release it when the pending aborted promise resolves.
      if (!abortControllerRef.current) {
        inFlightRef.current = false;
      }
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

