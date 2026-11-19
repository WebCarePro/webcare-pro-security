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
     * Execute a critical lease-mutation callback while holding the MySQL advisory mutex.
     * Guarantees that read-validate-write and read-validate-delete sequences against
     * the shared lease option are strictly serialized across concurrent PHP/HTTP requests.
     *
     * @param callable $callback
     * @return mixed Return value of callback, or false on lock acquisition failure.
     */
    private static function execute_with_mutation_mutex(callable $callback) {
        global $wpdb;
        if (!($wpdb instanceof \wpdb)) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $lock_res = $wpdb->get_var($wpdb->prepare("SELECT GET_LOCK(%s, %d)", self::ADVISORY_LOCK_NAME, 5));
        if ($lock_res === null || (int) $lock_res !== 1) {
            return false;
        }

        try {
            return $callback();
        } finally {
            if ($wpdb instanceof \wpdb) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::ADVISORY_LOCK_NAME));
            }
        }
    }

    /**
     * Attempt to acquire a scan lock atomically.
     * Combines MySQL advisory lock (GET_LOCK) with serialized option-based state tracking.
     *
     * @param int $scan_id
     * @return bool True if acquired, false if another scan is actively locked or advisory lock fails.
     */
    public static function acquire($scan_id): bool {
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0) {
            return false;
        }

        return (bool) self::execute_with_mutation_mutex(static function () use ($scan_id) {
            // Check option-based tracking for active scan timeout and scan ID match
            $existing = get_option(self::LOCK_OPTION);
            if ($existing && is_array($existing)) {
                $locked_time = (int) ($existing['time'] ?? 0);
                $locked_scan = (int) ($existing['scan_id'] ?? 0);

                // If lock is active and hasn't timed out, reject concurrent scan
                if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS && $locked_scan !== $scan_id) {
                    return false;
                }
            }

            // Atomically persist lease option
            $lease_token = (!empty($existing['lease_token']) && is_array($existing) && (int) ($existing['scan_id'] ?? 0) === $scan_id)
                ? (string) $existing['lease_token']
                : wp_generate_password(24, false);

            $lease_payload = [
                'scan_id'     => $scan_id,
                'time'        => time(),
                'lease_token' => $lease_token,
            ];

            // If lock did not exist, add_option is atomic in MySQL via unique key
            $added = add_option(self::LOCK_OPTION, $lease_payload, '', false);
            if (!$added) {
                update_option(self::LOCK_OPTION, $lease_payload, false);
            }

            // Verify that the persisted lease was written and matches scan_id and lease_token
            $persisted = get_option(self::LOCK_OPTION);
            if (
                !is_array($persisted)
                || (int) ($persisted['scan_id'] ?? 0) !== $scan_id
                || empty($persisted['lease_token'])
                || !hash_equals((string) $persisted['lease_token'], $lease_token)
            ) {
                return false;
            }

            return true;
        });
    }

    /**
     * Acquire a per-batch execution lock and verify active scan lease.
     * Prevents overlapping batch execution across concurrent AJAX/REST requests.
     *
     * @param int    $scan_id
     * @param string $lease_token Mandatory cryptographic token verifying scan lease ownership.
     * @return bool True if batch lock acquired and scan lease is valid.
     */
    public static function acquire_batch_lock(int $scan_id, string $lease_token): bool {
        global $wpdb;
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0 || empty($lease_token) || !($wpdb instanceof \wpdb)) {
            return false;
        }

        // 1. Verify scan lease validity and ownership
        if (!self::verify_and_renew_lease($scan_id, $lease_token)) {
            return false;
        }

        // 2. Acquire per-batch advisory mutex to serialize concurrent batch requests
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $batch_res = $wpdb->get_var($wpdb->prepare("SELECT GET_LOCK(%s, %d)", self::BATCH_LOCK_NAME, 0));
        if ($batch_res === null || (int) $batch_res !== 1) {
            return false;
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
     * Verify that this scan_id currently owns the active lock with the matching lease token
     * and refresh its heartbeat. Checks both in-memory and persisted storage.
     *
     * @param int    $scan_id
     * @param string $lease_token Mandatory cryptographic token verifying scan lease ownership.
     * @return bool True if owner lease verified and refreshed.
     */
    public static function verify_and_renew_lease(int $scan_id, string $lease_token): bool {
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0 || empty($lease_token)) {
            return false;
        }

        return (bool) self::execute_with_mutation_mutex(static function () use ($scan_id, $lease_token) {
            $existing = get_option(self::LOCK_OPTION);
            if (!$existing || !is_array($existing)) {
                return false;
            }

            $locked_scan  = (int) ($existing['scan_id'] ?? 0);
            $locked_time  = (int) ($existing['time'] ?? 0);
            $stored_token = (string) ($existing['lease_token'] ?? '');

            if ($locked_scan !== $scan_id) {
                return false;
            }

            if (empty($stored_token) || !hash_equals($stored_token, $lease_token)) {
                return false;
            }

            if ((time() - $locked_time) >= self::LOCK_TIMEOUT_SECONDS) {
                return false;
            }

            $updated_payload = [
                'scan_id'     => $scan_id,
                'time'        => time(),
                'lease_token' => $stored_token,
            ];
            update_option(self::LOCK_OPTION, $updated_payload, false);

            // Verify heartbeat write persistence in storage
            $persisted = get_option(self::LOCK_OPTION);
            if (
                !is_array($persisted)
                || (int) ($persisted['scan_id'] ?? 0) !== $scan_id
                || empty($persisted['lease_token'])
                || !hash_equals((string) $persisted['lease_token'], $lease_token)
            ) {
                return false;
            }

            return true;
        });
    }

    /**
     * Refresh the lock heartbeat to indicate the scan is still actively processing.
     *
     * @param int    $scan_id
     * @param string $lease_token Mandatory cryptographic lease token.
     * @return bool
     */
    public static function heartbeat(int $scan_id, string $lease_token): bool {
        return self::verify_and_renew_lease($scan_id, $lease_token);
    }

    /**
     * Release the scan lock (both MySQL advisory mutex and option state).
     * Strictly verifies lease token ownership before clearing options and advisory locks.
     * Serializes option inspection and deletion under MySQL advisory mutex.
     *
     * @param int    $scan_id
     * @param string $lease_token Mandatory cryptographic lease token.
     * @return bool True if verified owner lease was successfully released.
     */
    public static function release(int $scan_id, string $lease_token): bool {
        global $wpdb;
        $scan_id = (int) $scan_id;
        if ($scan_id <= 0 || empty($lease_token)) {
            return false;
        }

        $released = (bool) self::execute_with_mutation_mutex(static function () use ($scan_id, $lease_token) {
            // 1. Verify lease ownership with strict timing and token check
            $existing = get_option(self::LOCK_OPTION);
            if (!$existing || !is_array($existing) || (int) ($existing['scan_id'] ?? 0) !== $scan_id) {
                // Mismatched scan ID or no active lease — fail safe and do NOT delete
                return false;
            }

            $stored_token = (string) ($existing['lease_token'] ?? '');
            if (empty($stored_token) || !hash_equals($stored_token, $lease_token)) {
                // Token mismatch — do NOT delete
                return false;
            }

            // 2. Delete lease option and verify deletion persistence
            delete_option(self::LOCK_OPTION);
            $persisted = get_option(self::LOCK_OPTION);
            if ($persisted !== false) {
                return false;
            }

            return true;
        });

        // Release batch advisory lock if held
        if ($released && $wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::BATCH_LOCK_NAME));
        }

        return $released;
    }

    /**
     * Explicit administrative or recovery operation to forcefully release all locks.
     * Reserved for emergency resets, aborts, and test teardowns, with audit logging.
     * Serializes option deletion under MySQL advisory mutex.
     *
     * @param int|null $scan_id Optional scan ID for audit context.
     * @return void
     */
    public static function force_release(?int $scan_id = null): void {
        global $wpdb;

        self::execute_with_mutation_mutex(static function () {
            delete_option(self::LOCK_OPTION);
            return true;
        });

        if ($wpdb instanceof \wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("SELECT RELEASE_LOCK(%s)", self::BATCH_LOCK_NAME));
        }

        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            \WebCareProScanner\System\AuditLogger::log(
                'scan_lock_force_released',
                sprintf('Scan lock forcefully cleared by administrative operation (Scan ID: %s).', $scan_id ? (string) $scan_id : 'any'),
                'warning'
            );
        }
    }

    /**
     * Check if a scan is currently running and locked.
     *
     * @return int|null Scan ID if locked, or null.
     */
    public static function get_locked_scan_id(): ?int {
        global $wpdb;
        if (!($wpdb instanceof \wpdb)) {
            return null;
        }
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
     * Retrieve the cryptographic lease token for the active scan.
     * When $scan_id is supplied, verifies that the stored lease belongs to that exact scan.
     *
     * @param int|null $scan_id Optional scan ID to verify exact ownership.
     * @return string|null
     */
    public static function get_active_lease_token(?int $scan_id = null): ?string {
        global $wpdb;
        if (!($wpdb instanceof \wpdb)) {
            return null;
        }
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing)) {
            $locked_time = (int) ($existing['time'] ?? 0);
            $locked_scan = (int) ($existing['scan_id'] ?? 0);
            if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS && !empty($existing['lease_token'])) {
                if ($scan_id !== null && (int) $scan_id !== $locked_scan) {
                    return null;
                }
                return (string) $existing['lease_token'];
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
