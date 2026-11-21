import { useEffect, useRef } from '@wordpress/element';

/**
 * useVisibilityPolling
 *
 * Runs an asynchronous polling callback on an interval, automatically pausing
 * ticks when the document is hidden (`document.hidden === true`), and immediately
 * executing a catch-up poll when the user focuses or switches back to the tab.
 *
 * @param callback Async function or function to execute on each tick
 * @param intervalMs Interval in milliseconds (pass null or 0 to disable)
 * @param enabled Whether polling is active
 */
export function useVisibilityPolling(
  callback: () => void | Promise<void>,
  intervalMs: number | null | undefined,
  enabled: boolean = true
): void {
  const savedCallback = useRef(callback);
  savedCallback.current = callback;

  useEffect(() => {
    if (!enabled || !intervalMs || intervalMs <= 0) {
      return;
    }

    let isMounted = true;

    const executeTick = () => {
      if (typeof document !== 'undefined' && document.hidden) {
        return;
      }
      try {
        savedCallback.current();
      } catch (err) {
        console.warn('Visibility polling error:', err);
      }
    };

    const intervalId = setInterval(executeTick, intervalMs);

    const handleVisibilityChange = () => {
      if (typeof document !== 'undefined' && !document.hidden && isMounted) {
        // Trigger immediate catch-up tick on tab return
        executeTick();
      }
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    return () => {
      isMounted = false;
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
