<?php
namespace WebCareProScanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class ScanLock {

    const LOCK_OPTION          = 'webcareproscan_active_scan_lock';
    const ADVISORY_LOCK_NAME   = 'webcareproscan_scan_mutex';
    const LOCK_TIMEOUT_SECONDS = 300; // 5 minutes timeout for auto recovery

    /**
     * Attempt to acquire a scan lock atomically.
     * Combines MySQL advisory lock (GET_LOCK) with option-based state tracking.
     *
     * @param int $scan_id
     * @return bool True if acquired, false if another scan is actively locked.
     */
    public static function acquire($scan_id): bool {
        global $wpdb;
        $scan_id = (int) $scan_id;

        // 1. Attempt MySQL advisory lock if database connection is available
        $has_advisory_lock = false;
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $lock_res = $wpdb->get_var($wpdb->prepare("SELECT GET_LOCK(%s, %d)", self::ADVISORY_LOCK_NAME, 0));
            if ($lock_res !== null) {
                // 1 = successfully acquired, 0 = locked by another thread
                if ((int) $lock_res !== 1) {
                    return false;
                }
                $has_advisory_lock = true;
            }
        }

        // 2. Check option-based tracking for active scan timeout and scan ID match
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing)) {
            $locked_time = (int) ($existing['time'] ?? 0);
            $locked_scan = (int) ($existing['scan_id'] ?? 0);

            // If lock is active and hasn't timed out, reject concurrent scan
            if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS && $locked_scan !== $scan_id) {
                if ($has_advisory_lock && $wpdb instanceof \wpdb) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::ADVISORY_LOCK_NAME));
                }
                return false;
            }
        }

        update_option(self::LOCK_OPTION, [
            'scan_id' => $scan_id,
            'time'    => time(),
        ], false);

        return true;
    }

    /**
     * Refresh the lock heartbeat to indicate the scan is still actively processing.
     *
     * @param int $scan_id
     */
    public static function heartbeat($scan_id): void {
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing) && (int) ($existing['scan_id'] ?? 0) === (int) $scan_id) {
            update_option(self::LOCK_OPTION, [
                'scan_id' => (int) $scan_id,
                'time'    => time(),
            ], false);
        }
    }

    /**
     * Release the scan lock (both MySQL advisory mutex and option state).
     *
     * @param int|null $scan_id
     */
    public static function release($scan_id = null): void {
        global $wpdb;
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::ADVISORY_LOCK_NAME));
        }

        if ($scan_id === null) {
            delete_option(self::LOCK_OPTION);
            return;
        }

        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing) && (int) ($existing['scan_id'] ?? 0) === (int) $scan_id) {
            delete_option(self::LOCK_OPTION);
        }
    }

    /**
     * Check if a scan is currently running and locked.
     *
     * @return int|null Scan ID if locked, or null.
     */
    public static function get_locked_scan_id(): ?int {
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing)) {
            $locked_time = (int) ($existing['time'] ?? 0);
            if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS) {
                return (int) $existing['scan_id'];
            }
        }
        return null;
    }

    /**
     * Check whether any scan lock is currently active.
     *
     * @return bool
     */
    public static function is_locked(): bool {
        return self::get_locked_scan_id() !== null;
    }

    /**
     * Check whether MySQL advisory lock is currently held by any session.
     *
     * @return bool
     */
    public static function is_advisory_lock_held(): bool {
        global $wpdb;
        if (!($wpdb instanceof \wpdb)) {
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $holder = $wpdb->get_var($wpdb->prepare("SELECT IS_USED_LOCK(%s)", self::ADVISORY_LOCK_NAME));
        return !empty($holder);
    }
}
