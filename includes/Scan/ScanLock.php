<?php
namespace WebCareProScanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class ScanLock {

    const LOCK_OPTION          = 'webcareproscan_active_scan_lock';
    const ADVISORY_LOCK_NAME   = 'webcareproscan_scan_mutex';
    const BATCH_LOCK_NAME      = 'webcareproscan_scan_batch_mutex';
    const LOCK_TIMEOUT_SECONDS = 300; // 5 minutes timeout for auto recovery

    /**
     * Attempt to acquire a scan lock atomically.
     * Combines MySQL advisory lock (GET_LOCK) with option-based state tracking.
     *
     * @param int $scan_id
     * @return bool True if acquired, false if another scan is actively locked or advisory lock fails.
     */
    public static function acquire($scan_id): bool {
        global $wpdb;
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0) {
            return false;
        }

        // 1. Attempt MySQL advisory lock if database connection is available
        // Note: GET_LOCK() returns 1 (success), 0 (locked by another thread), or NULL (database lock error)
        // Must fail-closed if lock is not definitively granted.
        $has_advisory_lock = false;
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $lock_res = $wpdb->get_var($wpdb->prepare("SELECT GET_LOCK(%s, %d)", self::ADVISORY_LOCK_NAME, 0));
            if ($lock_res === null || (int) $lock_res !== 1) {
                return false;
            }
            $has_advisory_lock = true;
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

        // 3. Atomically persist lease option
        $lease_payload = [
            'scan_id'     => $scan_id,
            'time'        => time(),
            'lease_token' => wp_generate_password(24, false),
        ];

        // If lock did not exist, add_option is atomic in MySQL via unique key
        $added = add_option(self::LOCK_OPTION, $lease_payload, '', false);
        if (!$added) {
            update_option(self::LOCK_OPTION, $lease_payload, false);
        }

        return true;
    }

    /**
     * Acquire a per-batch execution lock and verify active scan lease.
     * Prevents overlapping batch execution across concurrent AJAX/REST requests.
     *
     * @param int $scan_id
     * @return bool True if batch lock acquired and scan lease is valid.
     */
    public static function acquire_batch_lock($scan_id): bool {
        global $wpdb;
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0) {
            return false;
        }

        // 1. Verify scan lease validity and ownership
        if (!self::verify_and_renew_lease($scan_id)) {
            return false;
        }

        // 2. Acquire per-batch advisory mutex to serialize concurrent batch requests
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $batch_res = $wpdb->get_var($wpdb->prepare("SELECT GET_LOCK(%s, %d)", self::BATCH_LOCK_NAME, 0));
            if ($batch_res === null || (int) $batch_res !== 1) {
                return false;
            }
        }

        return true;
    }

    /**
     * Release per-batch execution lock after batch processing finishes.
     */
    public static function release_batch_lock(): void {
        global $wpdb;
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::BATCH_LOCK_NAME));
        }
    }

    /**
     * Verify that this scan_id currently owns the active lock and refresh its heartbeat.
     *
     * @param int $scan_id
     * @return bool True if owner lease verified and refreshed.
     */
    public static function verify_and_renew_lease($scan_id): bool {
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0) {
            return false;
        }

        $existing = get_option(self::LOCK_OPTION);
        if (!$existing || !is_array($existing)) {
            return false;
        }

        $locked_scan = (int) ($existing['scan_id'] ?? 0);
        $locked_time = (int) ($existing['time'] ?? 0);

        if ($locked_scan !== $scan_id) {
            return false;
        }

        if ((time() - $locked_time) >= self::LOCK_TIMEOUT_SECONDS) {
            return false;
        }

        update_option(self::LOCK_OPTION, [
            'scan_id'     => $scan_id,
            'time'        => time(),
            'lease_token' => $existing['lease_token'] ?? wp_generate_password(24, false),
        ], false);

        return true;
    }

    /**
     * Refresh the lock heartbeat to indicate the scan is still actively processing.
     *
     * @param int $scan_id
     */
    public static function heartbeat($scan_id): void {
        self::verify_and_renew_lease($scan_id);
    }

    /**
     * Release the scan lock (both MySQL advisory mutex and option state).
     * Strictly verifies ownership before clearing options.
     *
     * @param int|null $scan_id
     */
    public static function release($scan_id = null): void {
        global $wpdb;
        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::ADVISORY_LOCK_NAME));
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::BATCH_LOCK_NAME));
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
