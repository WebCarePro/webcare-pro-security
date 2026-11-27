<?php
namespace WebCareProScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class SettingsManager {
    const OPTION_KEY = 'webcareproscan_settings';
    const OPTION_NAME = self::OPTION_KEY;
    const OPTION_SNAPSHOTS_KEY = 'webcareproscan_settings_snapshots';
    const OPTION_SNAPSHOTS = self::OPTION_SNAPSHOTS_KEY;
    const OPTION_MUTATION_LOCK = 'webcareproscan_settings_mutex';
    const OPTION_REVISION_KEY = 'webcareproscan_settings_revision';
    const CRON_HOOK = 'webcareproscan_scheduled_scan_event';
    const MAX_SNAPSHOTS = 10;
    public const MUTATION_LOCK_TTL = 60;

    /**
     * Tracks whether SecretVault persistence failed while sanitizing targeted allowlist rules.
     */
    private static bool $last_webhook_secret_store_failed = false;

    /**
     * Table-scoped cache of InnoDB storage-engine verification results keyed by
     * "<dbname>|<table_name>" so multisite blog switches re-verify the active options table.
     *
     * @var array<string, bool>
     */
    private static array $options_table_innodb_cache = [];

    /**
     * Per-request memoized decrypted settings cache keyed by "<blog_id>:<md5_of_raw_options>".
     *
     * @var array<string, mixed>|null
     */
    private static ?array $request_settings_cache = null;
    private static ?string $request_settings_cache_key = null;

    /**
     * Tracks option writes staged inside the currently open fenced transaction for post-commit notifications.
     *
     * @var array<string, array{existed: bool, old_value: mixed, new_value: mixed}>|null
     */
    private static ?array $active_tx_writes = null;

    /**
     * Reset per-request memoized decrypted settings cache.
     */
    public static function reset_settings_cache(): void {
        self::$request_settings_cache = null;
        self::$request_settings_cache_key = null;
    }

    /**
     * Reset cached storage-engine verification state (used for deterministic test isolation).
     */
    public static function reset_storage_engine_cache(): void {
        self::$options_table_innodb_cache = [];
        self::reset_settings_cache();
    }

    /**
     * Strip matching outer SQL backtick quoting without altering case or whitespace.
     */
    private static function unquote_sql_identifier(string $identifier): ?string {
        $len = strlen($identifier);
        if ($len >= 2 && $identifier[0] === '`' && $identifier[$len - 1] === '`') {
            $identifier = substr($identifier, 1, -1);
        }
        if ($identifier === '' || str_contains($identifier, '`') || str_contains($identifier, "\0") || preg_match('/\s/', $identifier) === 1) {
            return null;
        }
        return $identifier;
    }

    /**
     * Resolve a case-preserving, normalized identity key for the active $wpdb->options table,
     * or return null if the identifier is missing, contains whitespace, or is ambiguous.
     *
     * @return array{cache_key: string, table_name: string, schema_name: string|null}|null
     */
    private static function resolve_options_table_identity(): ?array {
        global $wpdb;
        if (!($wpdb instanceof \wpdb) || !isset($wpdb->options) || !is_string($wpdb->options)) {
            return null;
        }

        $raw_table = $wpdb->options;
        if ($raw_table === '' || str_contains($raw_table, "\0") || preg_match('/\s/', $raw_table) === 1) {
            return null;
        }

        $schema_name = null;
        $table_name = $raw_table;
        if (str_contains($raw_table, '.')) {
            $parts = explode('.', $raw_table, 2);
            $s_part = self::unquote_sql_identifier((string) ($parts[0] ?? ''));
            $t_part = self::unquote_sql_identifier((string) ($parts[1] ?? ''));
            if ($s_part === null || $t_part === null || str_contains($t_part, '.')) {
                return null;
            }
            $schema_name = $s_part;
            $table_name = $t_part;
        } else {
            $unquoted_table = self::unquote_sql_identifier($raw_table);
            if ($unquoted_table === null) {
                return null;
            }
            $table_name = $unquoted_table;
        }

        $db_id = $schema_name;
        if ($db_id === null) {
            $raw_dbname = $wpdb->dbname ?? '';
            if (!is_string($raw_dbname)) {
                return null;
            }
            if ($raw_dbname === '') {
                $db_id = '__default__';
            } else {
                $unquoted_db = self::unquote_sql_identifier($raw_dbname);
                if ($unquoted_db === null) {
                    return null;
                }
                $db_id = $unquoted_db;
            }
        }

        return [
            'cache_key'   => strlen($db_id) . ':' . $db_id . '|' . $table_name,
            'table_name'  => $table_name,
            'schema_name' => $schema_name,
        ];
    }

    /**
     * Verify that the currently active $wpdb->options table uses the InnoDB storage engine before
     * relying on transactional SELECT ... FOR UPDATE row locking and ROLLBACK semantics.
     * Cache is strictly scoped per table identity so multisite blog switches always re-check new tables.
     * Fails closed (returns false) if table identity is missing/ambiguous or engine is non-InnoDB/inconclusive.
     */
    public static function is_options_table_innodb(): bool {
        $identity = self::resolve_options_table_identity();
        if ($identity === null) {
            return false;
        }

        $cache_key = $identity['cache_key'];
        if (array_key_exists($cache_key, self::$options_table_innodb_cache)) {
            return self::$options_table_innodb_cache[$cache_key];
        }

        global $wpdb;
        if ($identity['schema_name'] !== null) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $engine = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT ENGINE
                     FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = %s
                       AND TABLE_NAME = %s
                     LIMIT 1",
                    $identity['schema_name'],
                    $identity['table_name']
                )
            );
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $engine = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT ENGINE
                     FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = DATABASE()
                       AND TABLE_NAME = %s
                     LIMIT 1",
                    $identity['table_name']
                )
            );
        }

        $is_innodb = is_string($engine) && strcasecmp(trim($engine), 'InnoDB') === 0;
        self::$options_table_innodb_cache[$cache_key] = $is_innodb;
        return $is_innodb;
    }

    /**
     * Optional test seam invoked immediately after acquire_mutation_lock() observes an expired lock
     * and right before compare_and_delete_mutation_lock() runs, to test two-contender stale-lock races.
     *
     * @var callable|null
     */
    public static $stale_lock_observed_hook = null;

    /**
     * Optional test seam invoked inside save_settings_locked() after sanitization completes and right
     * before lease renewal/fencing and database persistence begin, to test long-running mutations.
     *
     * @var callable|null
     */
    public static $before_persist_settings_hook = null;

    /**
     * Optional test seam invoked AFTER renew_mutation_lock() succeeds and immediately BEFORE
     * the transactional database write begins (testing P1 post-renewal suspension/expiry).
     *
     * @var callable|null
     */
    public static $after_renewal_before_write_hook = null;

    /**
     * Optional test seam invoked INSIDE execute_fenced_transaction() AFTER uncommitted SQL upserts
     * run and immediately BEFORE pre-COMMIT lease validation and COMMIT (testing mid-tx expiry rollback).
     *
     * @var callable|null
     */
    public static $inside_tx_before_commit_hook = null;

    /**
     * Optional test seam invoked immediately before undo_last_settings() pops OPTION_SNAPSHOTS_KEY
     * to deterministically test concurrent administrative interleavings.
     *
     * @var callable|null
     */
    public static $interleave_before_undo_pop_hook = null;

    /**
     * Read the raw uncached mutation lock payload ('<owner_token>|<expires_at>') directly from storage.
     */
    private static function read_raw_mutation_lock(): string {
        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $val = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
                    self::OPTION_MUTATION_LOCK
                )
            );
            return is_string($val) ? $val : '';
        }

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete(self::OPTION_MUTATION_LOCK, 'options');
        }
        $existing = get_option(self::OPTION_MUTATION_LOCK, '');
        return is_string($existing) ? $existing : '';
    }

    /**
     * Atomically delete OPTION_MUTATION_LOCK ONLY if its stored value still equals $expected_payload
     * (and, when $must_be_expired_before is provided, ONLY if its SQL-parsed expiry is strictly < $must_be_expired_before).
     * Prevents concurrent stale-lock contenders or expired former owners from deleting a newer owner's lock.
     */
    public static function compare_and_delete_mutation_lock(string $expected_payload, ?int $must_be_expired_before = null): bool {
        if ($expected_payload === '') {
            return false;
        }

        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            if ($must_be_expired_before !== null) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $deleted = $wpdb->query(
                    $wpdb->prepare(
                        "DELETE FROM {$wpdb->options}
                         WHERE option_name = %s
                           AND option_value = %s
                           AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) > 0
                           AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) < %d",
                        self::OPTION_MUTATION_LOCK,
                        $expected_payload,
                        $must_be_expired_before
                    )
                );
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $deleted = $wpdb->query(
                    $wpdb->prepare(
                        "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
                        self::OPTION_MUTATION_LOCK,
                        $expected_payload
                    )
                );
            }
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete(self::OPTION_MUTATION_LOCK, 'options');
            }
            return ($deleted === 1);
        }

        $current = self::read_raw_mutation_lock();
        if ($current !== $expected_payload) {
            return false;
        }
        if ($must_be_expired_before !== null) {
            $parts = explode('|', $current, 2);
            $exp = (int) ($parts[1] ?? 0);
            if ($exp <= 0 || $exp >= $must_be_expired_before) {
                return false;
            }
        }
        return delete_option(self::OPTION_MUTATION_LOCK);
    }

    /**
     * Verify that $token still actively owns an unexpired mutation lock.
     */
    public static function verify_mutation_lock_owner(string $token): bool {
        if ($token === '') {
            return false;
        }
        $now = time();

        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            $like_prefix = $wpdb->esc_like($token . '|') . '%';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $matched = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT option_value
                     FROM {$wpdb->options}
                     WHERE option_name = %s
                       AND option_value LIKE %s
                       AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= %d
                     LIMIT 1",
                    self::OPTION_MUTATION_LOCK,
                    $like_prefix,
                    $now
                )
            );
            return is_string($matched) && str_starts_with($matched, $token . '|');
        }

        $existing = self::read_raw_mutation_lock();
        if ($existing === '' || !str_starts_with($existing, $token . '|')) {
            return false;
        }
        $expires_at = (int) substr($existing, strlen($token) + 1);
        return $expires_at >= $now;
    }

    /**
     * Safely renew an active, unexpired mutation lock owned by $token via atomic SQL compare-and-swap
     * with database-level expiry enforcement. Refuses renewal if already expired or owned by another token.
     */
    public static function renew_mutation_lock(string $token, int $ttl = self::MUTATION_LOCK_TTL): bool {
        if ($token === '' || $ttl <= 0) {
            return false;
        }
        $ttl = max(5, min(300, $ttl));
        $now = time();
        $existing = self::read_raw_mutation_lock();
        if ($existing === '' || !str_starts_with($existing, $token . '|')) {
            return false;
        }

        $expires_at = (int) substr($existing, strlen($token) + 1);
        if ($expires_at < $now) {
            return false;
        }

        $new_payload = $token . '|' . ($now + $ttl);

        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            if ($new_payload === $existing) {
                return self::verify_mutation_lock_owner($token);
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $updated = $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->options}
                     SET option_value = %s
                     WHERE option_name = %s
                       AND option_value = %s
                       AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= %d",
                    $new_payload,
                    self::OPTION_MUTATION_LOCK,
                    $existing,
                    $now
                )
            );
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete(self::OPTION_MUTATION_LOCK, 'options');
            }
            return ($updated === 1);
        }

        if ($new_payload === $existing) {
            return self::verify_mutation_lock_owner($token);
        }
        if (self::read_raw_mutation_lock() !== $existing) {
            return false;
        }
        return update_option(self::OPTION_MUTATION_LOCK, $new_payload, false);
    }

    /**
     * Insert a fresh lock row atomically without stale object-cache interference.
     */
    private static function try_insert_mutation_lock(string $lock_payload): bool {
        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $inserted = $wpdb->query(
                $wpdb->prepare(
                    "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload)
                     VALUES (%s, %s, 'no')",
                    self::OPTION_MUTATION_LOCK,
                    $lock_payload
                )
            );
            if ($inserted === 1) {
                if (function_exists('wp_cache_delete')) {
                    wp_cache_delete(self::OPTION_MUTATION_LOCK, 'options');
                }
                return true;
            }
            return false;
        }

        return add_option(self::OPTION_MUTATION_LOCK, $lock_payload, '', 'no');
    }

    /**
     * Acquire shared atomic settings mutation lock to serialize concurrent save_settings(), undo_last_settings(), and reset_defaults().
     */
    public static function acquire_mutation_lock(int $ttl = self::MUTATION_LOCK_TTL): ?string {
        $ttl = max(5, min(300, $ttl));
        $token = bin2hex(random_bytes(16));

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $now = time();
            $lock_payload = $token . '|' . ($now + $ttl);
            if (self::try_insert_mutation_lock($lock_payload)) {
                return $token;
            }

            $existing = self::read_raw_mutation_lock();
            if ($existing === '') {
                continue;
            }

            if (str_contains($existing, '|')) {
                $parts = explode('|', $existing, 2);
                $expires_at = (int) ($parts[1] ?? 0);
                if ($expires_at > 0 && $expires_at < $now) {
                    if (is_callable(self::$stale_lock_observed_hook)) {
                        (self::$stale_lock_observed_hook)($existing);
                    }
                    if (self::compare_and_delete_mutation_lock($existing, $now)) {
                        $reclaim_payload = $token . '|' . (time() + $ttl);
                        if (self::try_insert_mutation_lock($reclaim_payload)) {
                            return $token;
                        }
                        continue;
                    }
                }
            }

            if (!defined('WEBCAREPROSCAN_TESTING') || !WEBCAREPROSCAN_TESTING) {
                usleep(25000);
            }
        }

        return null;
    }

    /**
     * Release shared atomic settings mutation lock ONLY if still owned by $token via compare-and-delete.
     */
    public static function release_mutation_lock(?string $token): void {
        if ($token === null || $token === '') {
            return;
        }
        $existing = self::read_raw_mutation_lock();
        if ($existing !== '' && str_starts_with($existing, $token . '|')) {
            self::compare_and_delete_mutation_lock($existing);
        }
    }

    /**
     * Read and lock an option row inside an active InnoDB transaction using SELECT ... FOR UPDATE.
     */
    private static function transactional_read_option_for_update(string $option, mixed $default = null): mixed {
        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $raw = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1 FOR UPDATE",
                    $option
                )
            );
            if ($raw === null) {
                return $default;
            }
            return maybe_unserialize($raw);
        }

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete($option, 'options');
        }
        return get_option($option, $default);
    }

    /**
     * Upsert an option row directly inside an active InnoDB transaction without prematurely mutating wp_cache.
     * Records pre-commit state into $active_tx_writes so standard WordPress option hooks can fire safely post-COMMIT.
     */
    private static function transactional_upsert_option(string $option, mixed $value, string $autoload = 'no'): bool {
        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            if (is_array(self::$active_tx_writes) && !array_key_exists($option, self::$active_tx_writes)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $prior_raw = $wpdb->get_var(
                    $wpdb->prepare(
                        "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
                        $option
                    )
                );
                self::$active_tx_writes[$option] = [
                    'existed'   => ($prior_raw !== null),
                    'old_value' => ($prior_raw !== null) ? maybe_unserialize($prior_raw) : null,
                    'new_value' => $value,
                ];
            } elseif (is_array(self::$active_tx_writes)) {
                self::$active_tx_writes[$option]['new_value'] = $value;
            }

            $serialized = (string) maybe_serialize($value);
            $autoload_val = ($autoload === 'yes' || $autoload === true) ? 'yes' : 'no';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $res = $wpdb->query(
                $wpdb->prepare(
                    "INSERT INTO {$wpdb->options} (option_name, option_value, autoload)
                     VALUES (%s, %s, %s)
                     ON DUPLICATE KEY UPDATE
                       option_value = %s,
                       autoload = %s",
                    $option,
                    $serialized,
                    $autoload_val,
                    $serialized,
                    $autoload_val
                )
            );
            return ($res !== false);
        }

        $sentinel = '__webcare_tx_unset__';
        $existing = get_option($option, $sentinel);
        $existed = ($existing !== $sentinel);
        if (is_array(self::$active_tx_writes)) {
            if (!array_key_exists($option, self::$active_tx_writes)) {
                self::$active_tx_writes[$option] = [
                    'existed'   => $existed,
                    'old_value' => $existed ? $existing : null,
                    'new_value' => $value,
                ];
            } else {
                self::$active_tx_writes[$option]['new_value'] = $value;
            }
        }
        if ($existed && $existing === $value && empty($GLOBALS['wp_mock_update_option_failures'][$option])) {
            return true;
        }
        return update_option($option, $value, ($autoload === 'yes' || $autoload === true));
    }

    /**
     * Dispatch controlled post-commit WordPress option lifecycle hooks without allowing
     * listener exceptions to turn an already-committed transaction into a false failure.
     *
     * @param array<string, array{existed: bool, old_value: mixed, new_value: mixed}> $committed_writes
     */
    private static function dispatch_post_commit_option_notifications(array $committed_writes): void {
        if (empty($committed_writes) || !function_exists('do_action')) {
            return;
        }

        foreach ($committed_writes as $option => $meta) {
            $existed   = !empty($meta['existed']);
            $old_value = $meta['old_value'] ?? null;
            $new_value = $meta['new_value'] ?? null;

            if (!$existed) {
                try {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress option lifecycle hook dispatched strictly post-COMMIT
                    do_action("add_option_{$option}", $option, $new_value);
                } catch (\Throwable $e) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                    @error_log('[WebCare SettingsManager] Post-commit add_option_' . $option . ' listener error: ' . $e->getMessage());
                }
                try {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress option lifecycle hook dispatched strictly post-COMMIT
                    do_action('added_option', $option, $new_value);
                } catch (\Throwable $e) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                    @error_log('[WebCare SettingsManager] Post-commit added_option listener error: ' . $e->getMessage());
                }
            } elseif ($old_value !== $new_value) {
                try {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress option lifecycle hook dispatched strictly post-COMMIT
                    do_action("update_option_{$option}", $old_value, $new_value, $option);
                } catch (\Throwable $e) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                    @error_log('[WebCare SettingsManager] Post-commit update_option_' . $option . ' listener error: ' . $e->getMessage());
                }
                try {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress option lifecycle hook dispatched strictly post-COMMIT
                    do_action('updated_option', $option, $old_value, $new_value);
                } catch (\Throwable $e) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                    @error_log('[WebCare SettingsManager] Post-commit updated_option listener error: ' . $e->getMessage());
                }
            }
        }
    }

    /**
     * Flush WordPress option and notoptions caches after a committed database transaction.
     *
     * @param array<int, string> $option_keys
     */
    private static function flush_committed_option_caches(array $option_keys): void {
        if (!function_exists('wp_cache_delete')) {
            return;
        }

        if (function_exists('wp_cache_get') && function_exists('wp_cache_set')) {
            $notoptions = wp_cache_get('notoptions', 'options');
            if (is_array($notoptions)) {
                $changed = false;
                foreach ($option_keys as $k) {
                    if (isset($notoptions[$k])) {
                        unset($notoptions[$k]);
                        $changed = true;
                    }
                }
                if ($changed) {
                    wp_cache_set('notoptions', $notoptions, 'options');
                }
            }
        }

        foreach ($option_keys as $k) {
            wp_cache_delete($k, 'options');
        }
        wp_cache_delete('alloptions', 'options');
        self::reset_settings_cache();
    }

    /**
     * Execute protected settings/revision/snapshot writes inside an InnoDB transaction that locks
     * OPTION_MUTATION_LOCK with SELECT ... FOR UPDATE, enforces owner + lease expiry in SQL both at
     * transaction entry and immediately before COMMIT, optionally verifies $expected_revision FOR UPDATE,
     * and rolls back all writes atomically if ownership or lease validity is lost at any point.
     *
     * @param string             $lock_token
     * @param int|null           $expected_revision
     * @param callable           $operation         function(): bool
     * @param array<int, string> $touched_options
     */
    private static function execute_fenced_transaction(
        string $lock_token,
        ?int $expected_revision,
        callable $operation,
        array $touched_options = []
    ): bool {
        if ($lock_token === '') {
            return false;
        }

        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            // Fail closed if $wpdb->options is not verified InnoDB (never silently fall back to non-transactional writes)
            if (!self::is_options_table_innodb()) {
                return false;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ($wpdb->query('START TRANSACTION') === false) {
                return false;
            }

            $committed = false;
            $committed_writes = [];
            self::$active_tx_writes = [];
            try {
                $now = time();
                $like_prefix = $wpdb->esc_like($lock_token . '|') . '%';

                // 1. Lock the mutex row exclusively (FOR UPDATE) and enforce BOTH token ownership AND unexpired lease in SQL
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $locked_mutex = $wpdb->get_var(
                    $wpdb->prepare(
                        "SELECT option_value
                         FROM {$wpdb->options}
                         WHERE option_name = %s
                           AND option_value LIKE %s
                           AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= %d
                         LIMIT 1
                         FOR UPDATE",
                        self::OPTION_MUTATION_LOCK,
                        $like_prefix,
                        $now
                    )
                );

                if (!is_string($locked_mutex) || !str_starts_with($locked_mutex, $lock_token . '|')) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->query('ROLLBACK');
                    return false;
                }

                // 2. Lock and verify expected monotonic settings revision inside the transaction when requested
                if ($expected_revision !== null) {
                    $db_rev_raw = self::transactional_read_option_for_update(self::OPTION_REVISION_KEY, 0);
                    if (max(0, (int) $db_rev_raw) !== $expected_revision) {
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                        $wpdb->query('ROLLBACK');
                        return false;
                    }
                }

                // 3. Perform all protected option upserts inside the active transaction
                if ($operation() !== true) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->query('ROLLBACK');
                    return false;
                }

                if (is_callable(self::$inside_tx_before_commit_hook)) {
                    (self::$inside_tx_before_commit_hook)($lock_token);
                }

                // 4. Pre-COMMIT database fence: verify the locked mutex row is STILL owned & unexpired in SQL
                //    and refresh its lease atomically within the same transaction before committing.
                $commit_now = time();
                $refreshed_mutex = $lock_token . '|' . ($commit_now + self::MUTATION_LOCK_TTL);
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $still_valid = $wpdb->get_var(
                    $wpdb->prepare(
                        "SELECT option_value
                         FROM {$wpdb->options}
                         WHERE option_name = %s
                           AND option_value = %s
                           AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= %d
                         LIMIT 1
                         FOR UPDATE",
                        self::OPTION_MUTATION_LOCK,
                        $locked_mutex,
                        $commit_now
                    )
                );

                if (!is_string($still_valid) || $still_valid !== $locked_mutex) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->query('ROLLBACK');
                    return false;
                }

                if ($refreshed_mutex !== $locked_mutex) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $lease_updated = $wpdb->query(
                        $wpdb->prepare(
                            "UPDATE {$wpdb->options}
                             SET option_value = %s
                             WHERE option_name = %s
                               AND option_value = %s
                               AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= %d",
                            $refreshed_mutex,
                            self::OPTION_MUTATION_LOCK,
                            $locked_mutex,
                            $commit_now
                        )
                    );
                    if ($lease_updated !== 1) {
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                        $wpdb->query('ROLLBACK');
                        return false;
                    }
                }

                // 5. Commit all protected writes + refreshed lease atomically
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                if ($wpdb->query('COMMIT') === false) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->query('ROLLBACK');
                    return false;
                }
                $committed = true;
                $committed_writes = is_array(self::$active_tx_writes) ? self::$active_tx_writes : [];
            } finally {
                self::$active_tx_writes = null;
                if (!$committed) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    @$wpdb->query('ROLLBACK');
                }
            }

            $all_keys = array_values(array_unique(array_merge([self::OPTION_MUTATION_LOCK], $touched_options)));
            self::flush_committed_option_caches($all_keys);
            self::dispatch_post_commit_option_notifications($committed_writes);
            return true;
        }

        // Minimal non-wpdb unit-test fallback with in-memory undo log rollback
        if (!self::verify_mutation_lock_owner($lock_token)) {
            return false;
        }
        if ($expected_revision !== null && self::get_settings_revision() !== $expected_revision) {
            return false;
        }

        $sentinel = '__webcare_tx_backup_unset__';
        $backup = [];
        foreach ($touched_options as $tk) {
            $prior_val = get_option($tk, $sentinel);
            $backup[$tk] = [
                'existed' => ($prior_val !== $sentinel),
                'value'   => ($prior_val !== $sentinel) ? $prior_val : null,
            ];
        }

        self::$active_tx_writes = [];
        try {
            $ok = ($operation() === true);
            if ($ok && is_callable(self::$inside_tx_before_commit_hook)) {
                (self::$inside_tx_before_commit_hook)($lock_token);
            }
            if (!$ok || !self::renew_mutation_lock($lock_token)) {
                foreach ($backup as $tk => $entry) {
                    if ($entry['existed']) {
                        update_option($tk, $entry['value'], false);
                    } else {
                        delete_option($tk);
                    }
                }
                return false;
            }
            $committed_writes = is_array(self::$active_tx_writes) ? self::$active_tx_writes : [];
        } finally {
            self::$active_tx_writes = null;
        }

        self::reset_settings_cache();
        self::dispatch_post_commit_option_notifications($committed_writes);
        return true;
    }

    /**
     * Read current monotonic settings revision counter directly from storage without stale cache.
     */
    private static function read_raw_revision(): int {
        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $raw = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
                    self::OPTION_REVISION_KEY
                )
            );
            return $raw !== null ? max(0, (int) $raw) : 0;
        }

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete(self::OPTION_REVISION_KEY, 'options');
        }
        return max(0, (int) get_option(self::OPTION_REVISION_KEY, 0));
    }

    /**
     * Return current monotonic settings revision counter.
     */
    public static function get_settings_revision(): int {
        return self::read_raw_revision();
    }

    /**
     * Non-secret boolean/policy setting keys whose names include words like 'password' or 'secrets'
     * and must NEVER be stripped from settings snapshots.
     */
    private const NON_SECRET_POLICY_KEYS = [
        'waf_enforce_strong_passwords',
        'waf_strong_passwords_roles',
        'waf_check_pwned_passwords',
        'scan_password_strength',
        'auth_admin_password_reset',
        'auth_application_password_created',
        'vault_secrets_rotated',
    ];

    /**
     * Secret keys that MUST NEVER be included in settings snapshots, export files, or undo history.
     */
    public const SECRET_KEYS = [
        'openai_api_key',
        'gemini_api_key',
        'claude_api_key',
        'deepseek_api_key',
        'openrouter_api_key',
        'ai_api_key',
        'virus_total_api_key',
        'wpscan_api_key',
        'cloudflare_api_token',
        'cloudflare_zone_id',
        'waf_cloudflare_origin_secret',
        'mcp_token',
        'slack_webhook_url',
        'discord_webhook_url',
        'clickup_webhook_url',
        'asana_webhook_url',
        'generic_webhook_url',
    ];

    /**
     * Suppression flag for noisy secondary firewall_ruleset_modified logs during dedicated IP actions.
     */
    public static bool $suppress_firewall_ruleset_log = false;

    /**
     * Default configuration options
     */
    public static function get_defaults(): array {
        $defaults = [
            // 1. Schedule Scan Settings
            'schedule_enabled'         => false,
            'schedule_frequency'       => 'daily', // hourly, twicedaily, daily, weekly
            'schedule_time'            => '02:00', // 24hr HH:MM server time
            'schedule_scan_type'       => 'plugins_themes', // plugins_themes, full, core_integrity, suspicious_uploads

            // 2. Email Notifications
            'email_alerts_enabled'     => false,
            'alert_emails'             => get_option('admin_email', ''),
            'alert_min_severity'       => 'high', // critical, high, medium, all
            'email_digest_enabled'     => false,
            'email_on_scan_completed'  => false,
            'notify_on_cve_detected'   => true,
            'email_report_items_limit' => 20, // Maximum threat items in scan email report (1 to 25, default 20)

            // 3. AI Threat & Code Analysis Integration
            'ai_enabled'               => false,
            'ai_provider'              => 'gemini', // gemini, openai, claude, deepseek, openrouter, wp_ai_connect
            'gemini_api_key'           => '',
            'gemini_model'             => 'gemini-3.5-flash-lite',
            'openai_api_key'           => '',
            'openai_model'             => 'gpt-6.1-sol',
            'claude_api_key'           => '',
            'claude_model'             => 'claude-sonnet-5-5',
            'deepseek_api_key'         => '',
            'deepseek_model'           => 'deepseek-chat',
            'openrouter_api_key'       => '',
            'openrouter_model'         => 'auto',
            'ai_temperature'           => 0.2,
            'ai_auto_analyze_critical' => false,

            // 4. Scanner Engine Performance & Throttle
            'scan_batch_size'                => 50, // 25, 50, 100, 200
            'scan_memory_safety_envelope'    => 'balanced', // strict (60%), balanced (70%), performance (80%)
            'scan_adaptive_throttling'       => true, // Dynamically throttle batch size and pace micro-sleeps for visitors
            'scan_batch_delay_ms'            => 0, // 0, 50, 100, 200, 500ms delay between REST batches
            'scan_execution_strategy'        => 'ajax_client', // 'ajax_client' | 'wp_cli_cron' | 'background_worker'
            'scan_uploads_mode'              => 'deep_raster', // 'smart_executable' | 'deep_raster'
            'scan_symlink_policy'            => 'ignore', // 'ignore' | 'follow_intree' | 'follow_all'
            'scan_skip_vcs'                  => true, // Skip .git, .svn, .hg
            'scan_skip_vendor'               => true, // Skip node_modules, third-party vendor dirs
            'scan_skip_cache'                => false, // Skip wp-content/cache, elementor/css, etc.
            'scan_ignore_cache_folder'       => false, // Default off - toggleable in scan options
            'scan_db_batch_size'             => 500, // 100, 250, 500, 1000 rows
            'scan_excluded_tables'           => '', // Custom DB tables to skip
            'scan_profiling_enabled'         => false, // Benchmarking & millisecond per-engine profiling
            'scan_dry_run_mode'              => false, // Dry-run mode without saving risk scores
            'memory_limit_override'          => '512M',
            'max_file_size_kb'               => 2024, // Skip files larger than ~2MB from heuristic scanning
            'auto_quarantine_critical'       => false, // Safeguard off by default

            // 5. Exclusions & Ignore Rules
            'excluded_paths'           => ".git/*\n.svn/*\n.hg/*\n.vault/*\n.backups/*\n.logs/*\n*.log\n*.tar.gz\n*.zip",
            'custom_extensions'        => 'php, phtml, phps, inc, tpl',

            // 6. Developer & Admin Security Tweaks & HTTP Headers
            'disable_file_editing'     => false,
            'hide_wp_version'          => false,
            'block_sensitive_files'    => false, // .env, .git, etc.
            'block_user_enumeration'   => true,  // Block ?author=1 and REST API user discovery

            // HTTP Security Headers
            'header_hsts'                      => true,
            'header_hsts_preload'              => false,
            'header_x_frame_options'           => true,
            'header_x_frame_options_mode'      => 'SAMEORIGIN', // SAMEORIGIN or DENY
            'header_nosniff'                   => true,
            'header_referrer_policy'           => true,
            'header_referrer_policy_value'     => 'strict-origin-when-cross-origin',
            'header_permissions_policy'        => true,
            'header_permissions_policy_value'  => 'geolocation=(), camera=(), microphone=(), payment=()',
            'header_xss_protection'            => true,
            'header_csp_enabled'               => false,
            'header_csp_custom'                => '',

            // 7. Cleanup & Data Privacy on Plugin Uninstall (Disabled by default to protect quarantine vault and configuration)
            'delete_data_on_uninstall'          => false,
            'uninstall_drop_tables'             => true,
            'uninstall_delete_options'          => true,
            'uninstall_delete_crons'            => true,
            'uninstall_delete_uploads'          => true,

            // 8. Web Application Firewall (WAF) Lite
            'waf_enabled'              => true,
            'waf_mode'                 => 'enabled', // 'enabled' | 'learning' | 'disabled'
            'waf_complementary_mode'   => true, // Auto-negotiate if Wordfence/Cloudflare active
            'waf_block_sqli'           => true,
            'waf_block_xss'            => true,
            'waf_block_traversal'      => true,
            'waf_block_php_injection'  => true,
            'waf_disable_xmlrpc'       => true,
            'waf_allow_jetpack_xmlrpc' => false, // Allow verified Automattic Jetpack sync via xmlrpc.php if Jetpack is used
            'waf_login_rate_limit'     => true,
            'waf_whitelisted_ips'      => '',
            'waf_whitelist_require_admin' => true, // Tiered Whitelist: Unauthenticated IPs can only bypass operational rules; require active Admin session for complete bypass
            'waf_whitelist_log_telemetry' => true, // 100% WAF Telemetry: Always log forensic incident when whitelisted IP triggers/bypasses a rule
            'waf_blocked_ips'          => '',
            'waf_block_fake_bots'      => true,
            'waf_block_ai_scrapers'    => false,
            'waf_ai_allow_search_citations'     => true,  // Allow verified search/citation assistants (OAI-SearchBot, PerplexityBot, Claude-SearchBot)
            'waf_ai_throttle_training_scrapers' => true,  // Rate-limit bulk training harvesters (GPTBot, CCBot, Bytespider, ClaudeBot)
            'waf_ai_challenge_stealth_agents'   => true,  // Challenge stealth headless AI agents with invisible WebCrypto PoW
            'waf_dynamic_robots_ai'    => false,
            'waf_block_404_scanners'   => true, // Smart 404 scanner rate limiter
            'waf_404_threshold'        => 10,   // Max 404s before temporary ban (e.g. 10)
            'waf_404_window_seconds'   => 60,   // Rolling time window in seconds (default 60s)
            'waf_404_lockout_duration' => 30,   // Lockout duration in minutes (default 30 mins)
            'waf_allow_uptime_monitors'        => false, // Allow verified Uptime Monitoring services (UptimeRobot, Pingdom, StatusCake, BetterUptime)
            'waf_allow_central_management'     => false, // Allow central WordPress management workers (ManageWP, MainWP, InfiniteWP) via cryptographic handshake
            'caf_threat_score_enabled'         => false, // Differential Threat Score & Behavioral Pre-Flight Sentinel (CAF Phase 3)

            // Enhanced Perimeter & Identity Protection Rules
            'waf_forms_safe_mode'               => true,
            'form_spam_protection_enabled'     => true,
            'form_block_headless_browsers'     => true,
            'form_honeypot_enabled'             => true,
            'form_speed_gate_enabled'           => true,
            'form_min_interaction_seconds'      => 2,
            'form_flood_limit_enabled'          => true,
            'form_max_submits_per_window'       => 5,
            'form_flood_window_minutes'         => 10,
            'form_content_filtering'            => true,
            'form_max_urls_allowed'             => 2,  // Smart Form Plugin Shield & False-Positive Immunity (CF7, WPForms, Gravity, Fluent Forms, etc.)
            'waf_ecommerce_safe_mode'           => false, // E-Commerce & Membership Smart Shield (off by default, recommended when shop/membership active)
            'waf_woo_carding_protection'        => true,  // WooCommerce Carding Attack & Checkout Velocity Shield (Rule #38)
            'waf_woo_checkout_max_attempts'     => 3,     // Max failed checkout attempts before lockout
            'waf_woo_carding_lockout_duration'  => 30,    // Lockout duration in minutes
            'waf_woo_coupon_protection'         => true,  // WooCommerce Coupon Enumeration & Brute-Force Shield (Rule #39)
            'waf_woo_coupon_max_failures'       => 8,     // Max failed coupon attempts before lockout (tuned for real shoppers)
            'waf_woo_coupon_lockout_duration'   => 15,    // Lockout duration in minutes (15 mins)
            'waf_woo_registration_protection'   => true,  // WooCommerce Customer Registration & Bot Shield (Rule #40)
            'waf_woo_reg_max_per_ip'            => 3,     // Max customer registrations per IP per window
            'waf_woo_reg_window_hours'          => 1,     // Registration rate limit window in hours (1 hour)
            'waf_woo_reg_block_disposable_emails' => true, // Block temporary / throwaway / disposable email domains
            'waf_woo_cart_flood_protection'     => true,  // WooCommerce Cart Flooding & Denial of Inventory Defense (Rule #41)
            'waf_woo_max_cart_items'            => 50,    // Maximum total item quantity in cart per session
            'waf_woo_add_to_cart_rate_limit'    => 15,    // Max add-to-cart operations per minute per IP
            'waf_woo_scraping_protection'       => true,  // WooCommerce Catalog & Price Scraping Mitigation (Rule #42)
            'waf_woo_scraping_max_requests'     => 60,    // Max catalog/product requests per minute per IP
            'waf_woo_scraping_lockout_duration' => 15,    // Lockout duration in minutes (15 mins)
            'waf_affiliate_shield_enabled'      => false, // Affiliate Ecosystem Shield & Anti-Fraud Armor (Rule #43, off by default, smart-activated when affiliate suite detected)
            'waf_affiliate_max_clicks_min'      => 10,    // Max referral clicks per minute per IP before suppression (default 10)
            'waf_affiliate_anti_injection'      => true,  // Referral Parameter Anti-Injection & Sanitization Armor
            'waf_affiliate_reg_spam_protection' => true,  // Affiliate Registration Anti-Spam Gate & Disposable Email Shield
            'waf_affiliate_direct_link_armor'   => true,  // Direct Link Tracking & Referer Integrity Verification
            'waf_allow_page_builders'           => false, // Visual Page Builder & Editor Smart Pass (off by default, recommended when Elementor/Divi active)
            'waf_block_empty_post_ua_referer'   => true, // Block IPs who send POST requests with blank User-Agent and Referer
            'waf_block_empty_user_agent'        => true, // Block unauthenticated requests with blank or missing User-Agent (Rule WAF-EMPTY-USER-AGENT)
            'waf_enable_progressive_warnings'   => true, // Progressive Warning Mode: Display amber warning checkpoint with support redirect for low-tier violations
            'waf_contact_support_url'           => '',   // Dedicated Support / Contact Page URL (e.g. /contact/ or https://example.com/support)
            'waf_whitelisted_urls'              => '',   // Allowlisted URLs / URI paths (one per line)
            'waf_targeted_allowlist_rules'      => '[]', // Granular User-Agent, Endpoint & IP allowlist rules (JSON string)
            'waf_block_forbidden_usernames'     => true, // Immediately block IP trying to sign in as forbidden honeypot usernames
            'waf_forbidden_usernames_list'      => "admin\nadministrator\nroot", // Forbidden/honeypot username list
            'waf_prevent_admin_registration'    => true, // Prevent users from registering 'admin' username
            'waf_mask_login_errors'             => true, // Don't let WordPress reveal valid users in login errors
            'waf_enforce_strong_passwords'      => true, // Enforce strong passwords for specific roles
            'waf_strong_passwords_roles'        => 'administrator, editor', // Roles subject to strong password policy
            'waf_check_pwned_passwords'         => true, // Prevent use of passwords leaked in data breaches (HIBP API)
            'waf_block_malicious_uploads'       => true, // Intercept & prevent malicious file uploads (executables, double ext, polyglots, SVG XSS)
            'waf_block_unsafe_http_methods'     => true, // Block TRACE, TRACK, CONNECT, DEBUG HTTP methods
            'waf_block_null_byte_attacks'       => true, // Block null byte (%00) poison attacks in URI & inputs
            'waf_block_sensitive_file_probes'   => true, // Block instant .env, .git, .sql, and backup file reconnaissance
            'waf_block_uploads_php_exec'        => true, // Deny direct execution requests to php files in wp-content/uploads/
            'waf_block_external_cron'           => false, // Block external HTTP hits to wp-cron.php (exempt loopback/cli)
            'waf_block_open_redirects'          => true, // Block open redirects targeting external phishing destinations
            'waf_block_ssrf_metadata'           => true, // Block SSRF probes targeting 169.254.169.254 cloud metadata
            'waf_block_install_php'             => true, // Lockdown install.php and upgrade.php on installed sites

            // Specialized Armor: phpMyAdmin & File Manager Restrictions
            'waf_disallow_phpmyadmin_plugins'   => true, // Disallow installation of phpMyAdmin & database manager plugins
            'waf_disallow_filemanager_plugins'  => true, // Disallow installation of File Manager plugins
            'waf_disallow_phpmyadmin_uploads'   => true, // Block uploads of phpMyAdmin / Adminer / standalone database scripts
            'waf_disallow_filemanager_uploads'  => true, // Block uploads of standalone File Manager / Webshell explorer scripts

            // Phase 2: Enumeration Suppression & Abuse / Rate Guards (Rules #29 - #34)
            'waf_block_rest_user_enum'          => true, // Rule #29: Block unauthenticated REST API user enumeration (/wp/v2/users)
            'waf_block_author_scan'             => true, // Rule #30: Suppress author ID permalink query scans (?author=N)
            'waf_limit_lostpassword'            => true, // Rule #31: Rate-limit lost-password reset attempts (3 / 15 min per IP & identity)
            'waf_enforce_host_allowlist'        => true, // Rule #32: Strict Host header allowlist against cache & reset poisoning
            'waf_allowed_host_aliases'          => '',   // Extra allowed host aliases/domains (one per line)
            'waf_limit_admin_ajax'              => true, // Rule #33: admin-ajax.php unauthenticated request burst rate limiter
            'waf_admin_ajax_limit_per_min'      => 60,   // Max unauthenticated admin-ajax requests per minute per IP
            'waf_block_oversized_requests'      => true, // Rule #34: Oversized request URI, query string, & parameter count guard
            'waf_block_ai_prompt_injection'     => true, // Rule #35: AI Prompt Injection & Agent Poisoning Shield
            'waf_cloudflare_proxy_trust_mode'   => 'disabled', // 'disabled' | 'auto_detected' | 'enabled'
            'waf_cloudflare_origin_secret'      => '', // Optional origin pull secret for strict CF proxy validation
            'waf_rewrite_server_remote_addr'    => false, // Opt-in rewrite of $_SERVER['REMOTE_ADDR']
            'waf_max_inspected_body_bytes'      => 4194304, // Deep request body inspection ceiling in bytes (default 4 MB, min 1 MB, max 64 MB)
            'waf_guest_ajax_policy'             => 'monitor', // Rule #36: Guest admin-ajax.php & admin-post.php Action Matrix ('monitor' | 'block' | 'off')
            'waf_guest_ajax_custom_allowlist'   => '',        // Newline-separated custom allowed action names
            'waf_guest_rest_policy'             => 'block',   // Rule #37: Guest REST API Mutation Guard ('block' | 'monitor' | 'off')
            'waf_guest_rest_custom_allowlist'   => '',        // Rule #37: Newline-separated custom allowed public REST route prefixes
            'waf_runtime_rasp_privilege_guard'  => true,      // Rule #44: Runtime Privilege Escalation Guard (In-Memory RASP Hook Firewall)
            'waf_upload_deep_mime_sanitizer'    => true,      // Rule #47: Deep MIME & Zip-Slip Polyglot Upload Armor
            'waf_log_retention_days'            => 60,   // WAF incident JSON log retention on filesystem in days (default 60 days)

            // 9. Cloud Threat Intelligence & Community Blacklists (Opt-in required for automated feed sync)
            'threat_intel_enabled'               => false,
            'threat_intel_block_blacklisted_ips' => false,
            'threat_intel_cisa_kev_enabled'        => true,
            'threat_intel_nvd_cve_enabled'         => true,
            'threat_intel_wpvulnerability_enabled' => true,
            'threat_intel_public_cidr_enabled'     => true,
            'waf_auto_enforce_virtual_patches'   => true, // Automatically enforce vendor-verified high-confidence virtual patches

            // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
            'auth_2fa_enabled'                   => true,
            'auth_2fa_algorithm'                 => 'sha1', // 'sha1' (6 digits) | 'sha512' (8 digits)
            'auth_2fa_digits'                    => 6,      // 6 | 8
            'auth_2fa_remember_device'           => true,
            'auth_2fa_remember_days'             => 7, // Days to remember trusted device (default 7 days)
            'auth_2fa_enforce_admins'            => false, // Force all administrator accounts to enable 2FA
            'auth_2fa_policy_mode'               => 'remind_login', // 'immediate' | 'grace_period' | 'remind_login'
            'auth_2fa_grace_days'                => 30, // Grace period in days (default 30 days when remind_login is active)
            'auth_2fa_enforce_since'             => 0, // Timestamp when enforcement policy was activated
            'login_hardening_enabled'            => true,
            'login_max_retries'                  => 5,
            'login_lockout_duration'             => 15,
            'session_sentinel_enabled'           => true,
            'session_block_concurrent'           => false,
            'webauthn_remember_session'          => false, // Remember WebAuthn passkey session via secure persistent auth cookie

            // 11. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n)
            'slack_enabled'                      => false,
            'slack_webhook_url'                  => '',
            'discord_enabled'                    => false,
            'discord_webhook_url'                => '',
            'clickup_enabled'                    => false,
            'clickup_webhook_url'                => '',
            'asana_enabled'                      => false,
            'asana_webhook_url'                  => '',
            'generic_webhook_enabled'            => false,
            'generic_webhook_url'                => '',
            'webhook_notify_on_critical'         => true,
            'webhook_notify_on_fim'              => true,
            'webhook_notify_on_waf_block'        => false,
            'webhook_notify_on_scan_finish'      => true,

            // 12. Cloudflare Edge Defense Integration
            'cloudflare_enabled'                 => false,
            'cloudflare_api_token'               => '',
            'cloudflare_zone_id'                 => '',
            'cloudflare_auto_sync_bans'          => true,

            // 13. False-Positive Tuning & Confidence Thresholds
            'confidence_threshold_filesystem'    => 50,
            'confidence_threshold_lotl'          => 60,
            'confidence_threshold_ai'            => 70,
            'confidence_threshold_db'            => 50,
            'auto_suppress_whitelisted'          => true,

            // 14. Model Context Protocol (MCP) Agent Service Surface
            'mcp_enabled'                        => true,
            'mcp_token'                          => '',
            'mcp_token_created_at'               => 0,
            'mcp_token_ttl_days'                 => 0,
            'mcp_allowed_cidrs'                  => '',
            'mcp_permission_scope'               => 'read_only',
            'mcp_persona_preset'                 => 'guided',
            'mcp_rate_limit_per_min'             => 60,
            'mcp_tool_matrix'                    => self::get_default_mcp_tool_matrix(),

            // 15. Custom Scan Engine Options (Wordfence-style scan customization)
            'custom_scan_options'                => self::get_default_custom_scan_options(),

            // 16. Plugin Self-Defense & Anti-Tamper Attestation
            'self_defense_watchdog_enabled'      => true,
            'self_defense_notify_email'          => true,

            // 17. Granular Event Notifications Matrix
            'notification_master_enabled'        => true,
            'notification_events'                => self::get_default_notification_events(),

            // 18. Centralized Cron & Task Automation Control
            'cron_waf_log_prune_enabled'         => true,
            'cron_cve_audit_enabled'             => true,
            'cron_domain_reputation_enabled'     => false, // Opt-in required for automated DNSBL & SSL reputation audits
            'cron_redirect_canary_enabled'       => true,
            'cron_reinfection_watchdog_enabled'  => true,
            'cron_custom_rules_autopilot_enabled'     => true,
            'cron_custom_rules_ast_bg_enabled'        => true,
            'cron_scan_bg_enabled'               => true,
            'cron_backup_bg_enabled'             => true,
            'cron_task_schedules'                => [],
            'cron_log_retention_days'            => 30,
        ];

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            $defaults = array_merge($defaults, \WebCareProScanner\Core\ModuleRegistry::get_settings_defaults());
        }

        return $defaults;
    }

    /**
     * Default states for all granular notification events
     */
    public static function get_default_notification_events(): array {
        return [
            // Core Scans & Threats
            'scan_scheduled_complete'   => ['email' => false, 'webhook' => false],
            'scan_manual_complete'      => ['email' => false, 'webhook' => false],
            'scan_targeted_complete'    => ['email' => false, 'webhook' => false],
            'scan_threats_found'        => ['email' => true,  'webhook' => true],
            'scan_auto_quarantine'      => ['email' => false, 'webhook' => false],
            'scan_aborted_timeout'      => ['email' => false, 'webhook' => false],

            // Plugin Self-Defense
            'plugin_file_tampered'      => ['email' => false, 'webhook' => false],
            'plugin_file_missing'       => ['email' => false, 'webhook' => false],

            // Cloudflare & WAF
            'cf_firewall_updated'       => ['email' => false, 'webhook' => false],
            'cf_firewall_rule_deleted'  => ['email' => false, 'webhook' => false],
            'waf_block_surge'           => ['email' => false, 'webhook' => false],
            'waf_virtual_patch_hit'     => ['email' => false, 'webhook' => false],
            'waf_server_rules_updated'  => ['email' => false, 'webhook' => false],
            'redirect_hack_detected'    => ['email' => true,  'webhook' => true],
            'redirect_hack_auto_healed' => ['email' => true,  'webhook' => false],

            // Authentication & 2FA
            'auth_admin_login'                  => ['email' => true,  'webhook' => false],
            'auth_admin_password_reset'         => ['email' => true,  'webhook' => false],
            'auth_application_password_created' => ['email' => true,  'webhook' => false],
            'auth_2fa_enabled'                  => ['email' => false, 'webhook' => false],
            'auth_2fa_disabled'                 => ['email' => false, 'webhook' => false],
            'auth_bruteforce_lockout'   => ['email' => false, 'webhook' => false],
            'auth_cf_edge_ban_synced'   => ['email' => false, 'webhook' => false],
            'auth_session_hijack_flag'  => ['email' => false, 'webhook' => false],
            'auth_rogue_admin_created'  => ['email' => false, 'webhook' => false],

            // File Integrity Monitoring (FIM)
            'fim_core_file_modified'    => ['email' => false, 'webhook' => false],
            'fim_plugin_theme_modified' => ['email' => false, 'webhook' => false],
            'fim_suspicious_php_found'  => ['email' => false, 'webhook' => false],
            'fim_auto_cure_applied'     => ['email' => false, 'webhook' => false],
            'fim_baseline_refreshed'    => ['email' => false, 'webhook' => false],

            // Vulnerabilities & Updates (CVE)
            'vuln_core_cve_detected'    => ['email' => false, 'webhook' => false],
            'vuln_plugin_theme_cve'     => ['email' => false, 'webhook' => false],
            'vuln_abandoned_extension'  => ['email' => false, 'webhook' => false],
            'vuln_feed_synced'          => ['email' => false, 'webhook' => false],

            // Database Backups & Vault
            'backup_db_completed'       => ['email' => false, 'webhook' => false],
            'backup_db_failed'          => ['email' => false, 'webhook' => false],
            'backup_db_restored'        => ['email' => false, 'webhook' => false],
            'vault_quarantine_restored' => ['email' => false, 'webhook' => false],
            'vault_quarantine_deleted'  => ['email' => false, 'webhook' => false],

            // DevSecOps Webhooks & AI Forensics
            'webhook_status_toggled'    => ['email' => false, 'webhook' => false],
            'ai_forensics_toggled'      => ['email' => false, 'webhook' => false],
            'mcp_service_toggled'       => ['email' => false, 'webhook' => false],

            // Supply-Chain Defense & SBOM
            'supply_chain_anchor_tampered'      => ['email' => false, 'webhook' => false],
            'supply_chain_gatekeeper_blocked'   => ['email' => false, 'webhook' => true],
            'supply_chain_gatekeeper_rollback'  => ['email' => false, 'webhook' => false],
            'supply_chain_risk_advisor_alert'   => ['email' => false, 'webhook' => false],
            'supply_chain_lockfile_cve'         => ['email' => false, 'webhook' => false],
            'supply_chain_script_drift'         => ['email' => false, 'webhook' => false],

            // Behavioral WAF & Active Traps
            'behavioral_bot_trap_triggered'     => ['email' => false, 'webhook' => false],
            'behavioral_rate_limit_exceeded'    => ['email' => false, 'webhook' => false],
            'ai_defense_prompt_injection'       => ['email' => false, 'webhook' => true],
            'attack_drill_completed'            => ['email' => false, 'webhook' => false],

            // Zero-Trust Identity & Session Forensics
            'auth_passkey_registered'           => ['email' => false, 'webhook' => false],
            'auth_passkey_revoked'              => ['email' => false, 'webhook' => false],
            'auth_impossible_travel_flag'       => ['email' => true,  'webhook' => true],

            // Advanced Forensics, Vault & Quarantine
            'forensics_reinfection_resurrection'=> ['email' => false, 'webhook' => true],
            'vault_secrets_rotated'             => ['email' => false, 'webhook' => false],
            'remediation_transaction_rollback'  => ['email' => false, 'webhook' => false],

            // Emergency Containment Protocol
            'containment_mode_activated'        => ['email' => true,  'webhook' => true],
            'containment_mode_deactivated'      => ['email' => true,  'webhook' => true],

            // Executive Reports & Non-Technical Digests
            'weekly_peace_of_mind_digest'       => ['email' => false, 'webhook' => false],
        ];
    }

    /**
     * Default state for customizable scan engine options
     */
    public static function get_default_custom_scan_options(): array {
        return [
            // Reputation Checks (Free On-Premise DNSBL & Spam Feeds)
            'check_domain_blocklist'     => true,
            'check_spamvertised'         => true,
            'check_spam_ip'              => true,

            // General & Deep Detection Engines
            'scan_ip_detection'          => true,
            'scan_public_config'         => true,
            'scan_public_quarantine'     => true,
            'scan_core_integrity'        => true,
            'scan_theme_integrity'       => true,
            'scan_plugin_integrity'      => true,
            'scan_cve_vulnerabilities'   => true,
            'scan_unbundled_files'       => true,
            'scan_known_malware'         => true,
            'scan_backdoors_heuristics'  => true,
            'scan_malicious_urls'        => true,
            'scan_posts_content'         => true,
            'scan_comments_content'      => true,
            'scan_options_content'       => true,
            'scan_vulnerable_software'   => true,
            'scan_rogue_admins'          => true,
            'scan_password_strength'     => false, // Disabled by default matching screenshot
            'monitor_disk_space'         => true,
            'monitor_firewall_status'    => true,
            'scan_outside_root'          => false, // Opt-in so default scans never crawl sibling vhosts
            'scan_images_executable'     => true,
        ];
    }

    /**
     * Sanitize custom scan engine options
     */
    public static function sanitize_custom_scan_options(array $opts): array {
        $defaults = self::get_default_custom_scan_options();
        $clean = [];
        foreach ($defaults as $key => $default_val) {
            $clean[$key] = array_key_exists($key, $opts) ? !empty($opts[$key]) : $default_val;
        }
        return $clean;
    }

    /**
     * Sanitize granular notification events dictionary
     */
    /**
     * Sanitize and validate targeted allowlist rules.
     * Ensures rules with no network/endpoint/hostname/asn constraints are rejected.
     *
     * @param mixed $rules
     * @return array
     */
    public static function sanitize_targeted_allowlist_rules(mixed $rules): array {
        if (is_string($rules)) {
            $parsed = json_decode($rules, true);
        } elseif (is_array($rules)) {
            $parsed = $rules;
        } else {
            $parsed = [];
        }

        if (!is_array($parsed)) {
            return [];
        }

        $clean_targeted = [];
        foreach ($parsed as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            $rule_id = !empty($rule['id']) ? sanitize_key($rule['id']) : 'rule_' . substr(md5(uniqid((string) wp_rand(), true)), 0, 8);
            $raw_endpoints = is_array($rule['endpoints'] ?? null)
                ? array_values(array_filter(array_map('sanitize_text_field', $rule['endpoints'])))
                : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['endpoints'] ?? ''))))));

            $clean_endpoints = [];
            foreach ($raw_endpoints as $ep) {
                $ep = trim((string) $ep);
                if ($ep === '') {
                    continue;
                }
                // Reject universal wildcards
                if ($ep === '*' || $ep === '/*' || $ep === '/**') {
                    continue;
                }
                // Reject dot segments
                if (str_contains($ep, '..')) {
                    continue;
                }
                // Ensure starts with '/'
                if (!str_starts_with($ep, '/')) {
                    $ep = '/' . $ep;
                }
                // Canonicalize multiple consecutive slashes
                $ep = (string) preg_replace('#/{2,}#', '/', $ep);
                if ($ep === '/' || $ep === '/*') {
                    continue;
                }
                $clean_endpoints[] = $ep;
            }
            $clean_endpoints = array_values(array_unique($clean_endpoints));

            $raw_wh_provider = sanitize_key((string) ($rule['webhook_hmac_provider'] ?? $rule['webhook_provider'] ?? 'none'));
            if ($raw_wh_provider === '' || $raw_wh_provider === 'none') {
                $wh_provider = 'none';
            } elseif (
                class_exists(\WebCareProScanner\Firewall\Core\AllowlistManager::class)
                && in_array($raw_wh_provider, \WebCareProScanner\Firewall\Core\AllowlistManager::get_supported_hmac_providers(), true)
            ) {
                $wh_provider = $raw_wh_provider;
            } else {
                continue; // Reject unsupported webhook HMAC provider
            }

            $clean_rule = [
                'id'           => $rule_id,
                'name'         => sanitize_text_field($rule['name'] ?? 'Custom Allowlist Rule'),
                'enabled'      => isset($rule['enabled']) ? (bool) $rule['enabled'] : true,
                'user_agents'  => is_array($rule['user_agents'] ?? null) 
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['user_agents'])))
                    : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['user_agents'] ?? '')))))),
                'endpoints'    => $clean_endpoints,
                'ip_addresses'     => is_array($rule['ip_addresses'] ?? null)
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['ip_addresses'])))
                    : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['ip_addresses'] ?? '')))))),
                'hostnames'        => is_array($rule['hostnames'] ?? null)
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['hostnames'])))
                    : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['hostnames'] ?? '')))))),
                'asns'             => is_array($rule['asns'] ?? null)
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['asns'])))
                    : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['asns'] ?? '')))))),
                'required_headers' => is_array($rule['required_headers'] ?? null)
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['required_headers'])))
                    : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['required_headers'] ?? '')))))),
                'webhook_hmac_provider' => $wh_provider,
                'webhook_replay_window_sec' => max(30, min(900, (int) ($rule['webhook_replay_window_sec'] ?? 300))),
                'webhook_secret_ref' => sanitize_key((string) ($rule['webhook_secret_ref'] ?? '')),
                'replay_protection'  => class_exists(\WebCareProScanner\Firewall\Core\AllowlistManager::class)
                    ? \WebCareProScanner\Firewall\Core\AllowlistManager::get_provider_replay_capability($wh_provider)
                    : 'none',
                'allow_unpinned_headers' => !empty($rule['allow_unpinned_headers']),
                'methods'          => is_array($rule['methods'] ?? null)
                    ? array_values(array_filter(array_map('sanitize_text_field', $rule['methods'])))
                    : ['ALL'],
                'log_payload'      => isset($rule['log_payload']) ? (bool) $rule['log_payload'] : true,
                'description'      => sanitize_text_field($rule['description'] ?? ''),
            ];

            // S2 Finding 3 & v3.25.1: Reject empty targeted allowlist rules that lack any effective constraints.
            // An allowlist rule must contain at least one non-empty IP/CIDR, validated non-universal endpoint, verified hostname, or ASN.
            $has_ips       = !empty($clean_rule['ip_addresses']);
            $has_endpoints = !empty($clean_rule['endpoints']);
            $has_hosts     = !empty($clean_rule['hostnames']);
            $has_asns      = !empty($clean_rule['asns']);

            if (!$has_ips && !$has_endpoints && !$has_hosts && !$has_asns) {
                continue; // Skip invalid, match-all empty allowlist rule
            }

            // If plaintext secret is supplied, store encrypted in SecretVault and link via webhook_secret_ref.
            // Abort persisting the allowlist rule if SecretVault encryption or option write fails!
            $raw_secret = trim((string) ($rule['webhook_secret'] ?? ''));
            if ($raw_secret !== '') {
                $ref = $clean_rule['webhook_secret_ref'] !== '' ? $clean_rule['webhook_secret_ref'] : 'wcp_wh_sec_' . $clean_rule['id'];
                if (!\WebCareProScanner\Firewall\Core\AllowlistManager::store_webhook_secret($ref, $raw_secret)) {
                    self::$last_webhook_secret_store_failed = true;
                    continue;
                }
                $clean_rule['webhook_secret_ref'] = $ref;
            }

            // Fail closed at configuration save time: HMAC provider without secret_ref or secret_ref with 'none' provider is rejected
            if (($clean_rule['webhook_hmac_provider'] !== 'none' && $clean_rule['webhook_secret_ref'] === '')
                || ($clean_rule['webhook_hmac_provider'] === 'none' && $clean_rule['webhook_secret_ref'] !== '')
            ) {
                continue;
            }

            // Security Hardening: Header-only rules without endpoint/IP/host pinning or cryptographic secret require explicit acknowledgment
            $is_unpinned = empty($clean_rule['ip_addresses']) && empty($clean_rule['hostnames']) && empty($clean_rule['asns']);
            $has_secret = !empty($clean_rule['webhook_secret_ref']);
            $has_headers_only = !empty($clean_rule['required_headers']) && $is_unpinned && !$has_secret;
            if ($has_headers_only && empty($clean_rule['allow_unpinned_headers'])) {
                continue; // Reject unpinned header-only rule without explicit user acknowledgment
            }

            $clean_targeted[] = $clean_rule;
        }

        return $clean_targeted;
    }

    public static function sanitize_notification_events(array $events): array {
        $defaults = self::get_default_notification_events();
        $clean = [];
        foreach ($defaults as $key => $default_channels) {
            $incoming = isset($events[$key]) && is_array($events[$key]) ? $events[$key] : [];
            $clean[$key] = [
                'email'   => isset($incoming['email']) ? !empty($incoming['email']) : ($default_channels['email'] ?? false),
                'webhook' => isset($incoming['webhook']) ? !empty($incoming['webhook']) : ($default_channels['webhook'] ?? false),
            ];
        }
        return $clean;
    }

    /**
     * Default governance policy matrix for all MCP agent tools.
     */
    public static function get_default_mcp_tool_matrix(): array {
        $matrix = [
            // Existing Core Tools
            'webcareproscan_get_security_posture'           => 'allowed',
            'webcareproscan_list_findings'                  => 'allowed',
            'webcareproscan_audit_behavioral_baseline'      => 'allowed',
            'webcareproscan_get_containment_status'         => 'allowed',
            'webcareproscan_list_staged_actions'            => 'allowed',
            'webcareproscan_whitelist_finding'              => 'confirmation_required',
            'webcareproscan_rollback_remediation'           => 'confirmation_required',
            'webcareproscan_deploy_virtual_patch'           => 'confirmation_required',
            'webcareproscan_quarantine_file'                => 'confirmation_required',
            'webcareproscan_run_security_drill'             => 'allowed',
            'webcareproscan_set_containment_mode'           => 'confirmation_required',
            'webcareproscan_get_supply_chain_sbom'          => 'allowed',
            'webcareproscan_get_gatekeeper_history'         => 'allowed',
            'webcareproscan_recalibrate_sbom_baseline'      => 'confirmation_required',
            'webcareproscan_quarantine_supply_chain_anchor' => 'confirmation_required',
            'webcareproscan_get_behavioral_waf_status'      => 'allowed',
            'webcareproscan_set_route_learning_status'      => 'confirmation_required',
            'webcareproscan_get_identity_forensics'         => 'allowed',
            'webcareproscan_revoke_user_session'            => 'confirmation_required',
            'webcareproscan_grant_ephemeral_elevation'      => 'confirmation_required',
            'webcareproscan_revoke_ephemeral_elevation'     => 'confirmation_required',
            'webcareproscan_get_threat_intel_network'       => 'allowed',
            'webcareproscan_sync_threat_intel'              => 'allowed',
            'webcareproscan_synthesize_virtual_patch'       => 'confirmation_required',
            'webcareproscan_test_virtual_patch'             => 'allowed',
            'webcareproscan_deploy_synthesized_patch'       => 'confirmation_required',
            // Expanded Governed Full-Plugin Tools
            'webcareproscan_get_settings_catalog'           => 'allowed',
            'webcareproscan_update_plugin_settings'         => 'confirmation_required',
            'webcareproscan_get_server_hardening_status'    => 'allowed',
            'webcareproscan_apply_htaccess_hardening'       => 'confirmation_required',
            'webcareproscan_start_security_scan'            => 'confirmation_required',
            'webcareproscan_get_scan_status'                => 'allowed',
            'webcareproscan_explain_finding'                => 'allowed',
            'webcareproscan_manage_scan_exclusions'         => 'confirmation_required',
            'webcareproscan_export_security_report'         => 'allowed',
            'webcareproscan_list_quarantine_items'          => 'allowed',
            'webcareproscan_restore_quarantined_file'       => 'confirmation_required',
            'webcareproscan_delete_quarantined_file'        => 'confirmation_required',
            'webcareproscan_repair_official_file'           => 'confirmation_required',
            'webcareproscan_list_waf_incidents'             => 'allowed',
            'webcareproscan_manage_ip_access'               => 'confirmation_required',
            'webcareproscan_get_cloudflare_status'          => 'allowed',
            'webcareproscan_sync_cloudflare_ip_ban'         => 'confirmation_required',
            'webcareproscan_list_mcp_snapshots'             => 'allowed',
            'webcareproscan_undo_last_mcp_change'           => 'confirmation_required',
        ];

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            foreach (\WebCareProScanner\Core\ModuleRegistry::get_mcp_tools() as $mt) {
                $t_name = (string) ($mt['name'] ?? '');
                if ($t_name !== '' && !isset($matrix[$t_name])) {
                    $matrix[$t_name] = !empty($mt['isMutating']) ? 'confirmation_required' : 'allowed';
                }
            }
        }

        return $matrix;
    }

    /**
     * Sanitize MCP tool policy governance matrix.
     */
    public static function sanitize_mcp_tool_matrix(array $matrix): array {
        $valid_policies = ['allowed', 'confirmation_required', 'blocked'];
        $tier4_locked   = [
            'webcareproscan_delete_quarantined_file',
            'webcareproscan_set_containment_mode',
            'webcareproscan_grant_ephemeral_elevation',
            'webcareproscan_quarantine_supply_chain_anchor',
        ];
        $defaults = self::get_default_mcp_tool_matrix();
        $clean = [];
        foreach ($defaults as $tool => $def_policy) {
            $incoming = $matrix[$tool] ?? $def_policy;
            $policy   = in_array($incoming, $valid_policies, true) ? $incoming : $def_policy;
            if (in_array($tool, $tier4_locked, true) && $policy === 'allowed') {
                $policy = 'confirmation_required';
            }
            $clean[$tool] = $policy;
        }
        return $clean;
    }

    /**
     * Get a specific setting by key with decrypted value.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public static function get(string $key, $default = null) {
        $settings = self::get_settings();
        return array_key_exists($key, $settings) ? $settings[$key] : $default;
    }

    /**
     * Retrieve all settings merged with defaults and decrypted.
     */
    public static function get_settings(): array {
        $saved = get_option(self::OPTION_KEY, []);
        if (!is_array($saved)) {
            $saved = [];
        }

        $act_settings = get_option('webcareproscan_activity_log_settings', []);
        $act_settings = is_array($act_settings) ? $act_settings : [];

        $blog_id   = function_exists('get_current_blog_id') ? (int) get_current_blog_id() : 1;
        $cache_key = $blog_id . ':' . md5(serialize([$saved, $act_settings]));
        if (self::$request_settings_cache !== null && self::$request_settings_cache_key === $cache_key) {
            $merged = self::$request_settings_cache;
            if (function_exists('apply_filters')) {
                $merged = apply_filters('webcareproscan_settings', $merged);
            }
            return $merged;
        }

        $defaults = self::get_defaults();
        $merged = array_merge($defaults, $saved);

        // Transparently decrypt sensitive credentials if encrypted
        $sensitive_keys = [
            'cloudflare_api_token',
            'cloudflare_zone_id',
            'waf_cloudflare_origin_secret',
            'openai_api_key',
            'gemini_api_key',
            'claude_api_key',
            'deepseek_api_key',
            'openrouter_api_key',
            'slack_webhook_url',
            'discord_webhook_url',
            'clickup_webhook_url',
            'asana_webhook_url',
            'generic_webhook_url',
            'mcp_token',
        ];

        foreach ($sensitive_keys as $k) {
            if (!empty($merged[$k])) {
                $raw_val = (string) $merged[$k];
                if (\WebCareProScanner\Security\SecretVault::is_encrypted($raw_val)) {
                    $merged[$k] = \WebCareProScanner\Security\SecretVault::decrypt($raw_val);
                }
            }
        }

        // Boolean configuration flags for UI state without needing plaintext credentials
        $merged['has_openai_key']             = !empty($merged['openai_api_key']);
        $merged['has_gemini_key']             = !empty($merged['gemini_api_key']);
        $merged['has_claude_key']             = !empty($merged['claude_api_key']);
        $merged['has_deepseek_key']           = !empty($merged['deepseek_api_key']);
        $merged['has_openrouter_key']         = !empty($merged['openrouter_api_key']);
        $merged['has_cloudflare_key']         = !empty($merged['cloudflare_api_token']);
        $merged['has_cloudflare_zone_id']     = !empty($merged['cloudflare_zone_id']);
        $merged['has_cloudflare_origin_secret'] = !empty($merged['waf_cloudflare_origin_secret']);
        $merged['has_slack_webhook']          = !empty($merged['slack_webhook_url']);
        $merged['has_discord_webhook']        = !empty($merged['discord_webhook_url']);
        $merged['has_clickup_webhook']        = !empty($merged['clickup_webhook_url']);
        $merged['has_asana_webhook']          = !empty($merged['asana_webhook_url']);
        $merged['has_generic_webhook']        = !empty($merged['generic_webhook_url']);
        $merged['has_mcp_token']              = !empty($merged['mcp_token']);

        // Activity log options
        $merged['activity_log_settings']      = $act_settings;

        self::$request_settings_cache     = $merged;
        self::$request_settings_cache_key = $cache_key;

        // Apply developer and policy overrides via filter hook
        if (function_exists('apply_filters')) {
            $merged = apply_filters('webcareproscan_settings', $merged);
        }

        return $merged;
    }

    /**
     * Retrieve UI-safe settings with all SecretVault credentials replaced by masked sentinels
     * and accurate has_* presence booleans preserved for React forms.
     *
     * @param array<string, mixed>|null $settings Optional pre-loaded settings array
     * @return array<string, mixed>
     */
    public static function get_settings_for_ui(?array $settings = null): array {
        $ui = $settings ?? self::get_settings();

        $ui['has_openai_key']               = !empty($ui['openai_api_key']) || !empty($ui['has_openai_key']);
        $ui['has_gemini_key']               = !empty($ui['gemini_api_key']) || !empty($ui['has_gemini_key']);
        $ui['has_claude_key']               = !empty($ui['claude_api_key']) || !empty($ui['has_claude_key']);
        $ui['has_deepseek_key']             = !empty($ui['deepseek_api_key']) || !empty($ui['has_deepseek_key']);
        $ui['has_openrouter_key']           = !empty($ui['openrouter_api_key']) || !empty($ui['has_openrouter_key']);
        $ui['has_cloudflare_key']           = !empty($ui['cloudflare_api_token']) || !empty($ui['has_cloudflare_key']);
        $ui['has_cloudflare_zone_id']       = !empty($ui['cloudflare_zone_id']) || !empty($ui['has_cloudflare_zone_id']);
        $ui['has_cloudflare_origin_secret'] = !empty($ui['waf_cloudflare_origin_secret']) || !empty($ui['has_cloudflare_origin_secret']);
        $ui['has_slack_webhook']            = !empty($ui['slack_webhook_url']) || !empty($ui['has_slack_webhook']);
        $ui['has_discord_webhook']          = !empty($ui['discord_webhook_url']) || !empty($ui['has_discord_webhook']);
        $ui['has_clickup_webhook']          = !empty($ui['clickup_webhook_url']) || !empty($ui['has_clickup_webhook']);
        $ui['has_asana_webhook']            = !empty($ui['asana_webhook_url']) || !empty($ui['has_asana_webhook']);
        $ui['has_generic_webhook']          = !empty($ui['generic_webhook_url']) || !empty($ui['has_generic_webhook']);
        $ui['has_mcp_token']                = !empty($ui['mcp_token']) || !empty($ui['has_mcp_token']);

        foreach (self::SECRET_KEYS as $secret_key) {
            if (empty($ui[$secret_key])) {
                $ui[$secret_key] = '';
                continue;
            }
            $ui[$secret_key] = ($secret_key === 'mcp_token') ? 'wcp_mcp_••••••••' : '••••••••';
        }

        return $ui;
    }

    /**
     * Update a single setting key cleanly via save_settings().
     */
    public static function update_setting(string $key, mixed $value): bool {
        $res = self::save_settings([$key => $value]);
        return is_array($res);
    }

    /**
     * Save settings with sanitization and hook updates under an exclusive, lease-renewed mutation lock.
     * Returns false if lock acquisition, lock ownership verification, option persistence, or SecretVault storage fails.
     *
     * @param array<string, mixed> $input
     * @param bool                 $record_snapshot
     * @return array<string, mixed>|false
     */
    public static function save_settings(array $input, bool $record_snapshot = true): array|false {
        $lock_token = self::acquire_mutation_lock();
        if ($lock_token === null) {
            return false;
        }

        try {
            return self::save_settings_locked($input, $lock_token, $record_snapshot);
        } finally {
            self::release_mutation_lock($lock_token);
        }
    }

    /**
     * Internal lock-fenced settings persistence and snapshot recording implementation.
     * Verifies and renews ownership of $lock_token at every persistence boundary so a stalled
     * process whose lease expired can never overwrite settings, revisions, or snapshot history.
     *
     * @param array<string, mixed>      $input
     * @param string                    $lock_token
     * @param bool                      $record_snapshot
     * @param array<string, mixed>|null $out_clean
     * @return array<string, mixed>|false
     */
    private static function save_settings_locked(
        array $input,
        string $lock_token,
        bool $record_snapshot = true,
        ?array &$out_clean = null
    ): array|false {
        if (!self::renew_mutation_lock($lock_token)) {
            return false;
        }

        self::$last_webhook_secret_store_failed = false;

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete(self::OPTION_KEY, 'options');
            wp_cache_delete(self::OPTION_REVISION_KEY, 'options');
        }

        $baseline_revision = self::read_raw_revision();
        $raw_existing = get_option(self::OPTION_KEY, []);
        $current = is_array($raw_existing) ? $raw_existing : [];

        $defaults = self::get_defaults();
        // Merge defaults, current options, and input so partial saves (from individual rule toggles,
        // specific settings pages, or cloudflare verifications) NEVER inadvertently reset or uncheck omitted rules!
        $merged = array_merge($defaults, $current, $input);

        $clean = [];

        // 1. Schedule Scan Settings
        $clean['schedule_enabled']   = !empty($merged['schedule_enabled']);
        $valid_freq = ['hourly', 'twicedaily', 'daily', 'weekly'];
        $clean['schedule_frequency'] = in_array($merged['schedule_frequency'] ?? '', $valid_freq, true) 
            ? $merged['schedule_frequency'] 
            : 'daily';
        $clean['schedule_time']      = sanitize_text_field($merged['schedule_time'] ?? '02:00');
        $valid_targets = ['plugins_themes', 'full', 'core_integrity', 'suspicious_uploads', 'spam_content'];
        $clean['schedule_scan_type'] = in_array($merged['schedule_scan_type'] ?? '', $valid_targets, true)
            ? $merged['schedule_scan_type']
            : 'plugins_themes';

        // 2. Email Notifications
        $clean['email_alerts_enabled']    = !empty($merged['email_alerts_enabled']);
        $clean['alert_emails']            = sanitize_textarea_field($merged['alert_emails'] ?? '');
        $valid_sev = ['critical', 'high', 'medium', 'all'];
        $clean['alert_min_severity']      = in_array($merged['alert_min_severity'] ?? '', $valid_sev, true) 
            ? $merged['alert_min_severity'] 
            : 'high';
        $clean['email_digest_enabled']    = !empty($merged['email_digest_enabled']);
        $clean['email_on_scan_completed'] = !empty($merged['email_on_scan_completed']);
        $clean['notify_on_cve_detected']  = !empty($merged['notify_on_cve_detected']);
        $clean['email_report_items_limit'] = max(1, min(25, intval($merged['email_report_items_limit'] ?? 20)));

        // 3. AI Threat Integration
        $clean['ai_enabled']               = !empty($merged['ai_enabled']);
        $valid_ai = ['openai', 'gemini', 'claude', 'wp_ai_connect', 'deepseek', 'openrouter'];
        $clean['ai_provider']              = in_array($merged['ai_provider'] ?? '', $valid_ai, true) 
            ? $merged['ai_provider'] 
            : 'openai';

        // Preserve existing keys if incoming is masked or empty, and securely encrypt for database storage
        $in_openai = trim($input['openai_api_key'] ?? '');
        $old_openai_val = \WebCareProScanner\Security\SecretVault::decrypt($current['openai_api_key'] ?? '');
        $openai_val = ($in_openai === '' || str_contains($in_openai, '••'))
            ? $old_openai_val
            : sanitize_text_field($in_openai);
        $clean['openai_api_key'] = ($openai_val === $old_openai_val && !empty($current['openai_api_key']))
            ? $current['openai_api_key']
            : \WebCareProScanner\Security\SecretVault::encrypt($openai_val);
        $clean['openai_model'] = sanitize_text_field($merged['openai_model'] ?? 'gpt-6.1-sol');

        $in_gemini = trim($input['gemini_api_key'] ?? '');
        $old_gemini_val = \WebCareProScanner\Security\SecretVault::decrypt($current['gemini_api_key'] ?? '');
        $gemini_val = ($in_gemini === '' || str_contains($in_gemini, '••'))
            ? $old_gemini_val
            : sanitize_text_field($in_gemini);
        $clean['gemini_api_key'] = ($gemini_val === $old_gemini_val && !empty($current['gemini_api_key']))
            ? $current['gemini_api_key']
            : \WebCareProScanner\Security\SecretVault::encrypt($gemini_val);
        $clean['gemini_model'] = sanitize_text_field($merged['gemini_model'] ?? 'gemini-3.5-flash-lite');

        $in_claude = trim($input['claude_api_key'] ?? '');
        $old_claude_val = \WebCareProScanner\Security\SecretVault::decrypt($current['claude_api_key'] ?? '');
        $claude_val = ($in_claude === '' || str_contains($in_claude, '••'))
            ? $old_claude_val
            : sanitize_text_field($in_claude);
        $clean['claude_api_key'] = ($claude_val === $old_claude_val && !empty($current['claude_api_key']))
            ? $current['claude_api_key']
            : \WebCareProScanner\Security\SecretVault::encrypt($claude_val);
        $clean['claude_model'] = sanitize_text_field($merged['claude_model'] ?? 'claude-sonnet-5-5');

        $in_deepseek = trim($input['deepseek_api_key'] ?? '');
        $old_deepseek_val = \WebCareProScanner\Security\SecretVault::decrypt($current['deepseek_api_key'] ?? '');
        $deepseek_val = ($in_deepseek === '' || str_contains($in_deepseek, '••'))
            ? $old_deepseek_val
            : sanitize_text_field($in_deepseek);
        $clean['deepseek_api_key'] = ($deepseek_val === $old_deepseek_val && !empty($current['deepseek_api_key']))
            ? $current['deepseek_api_key']
            : \WebCareProScanner\Security\SecretVault::encrypt($deepseek_val);
        $clean['deepseek_model'] = sanitize_text_field($merged['deepseek_model'] ?? 'deepseek-chat');

        $in_openrouter = trim($input['openrouter_api_key'] ?? '');
        $old_openrouter_val = \WebCareProScanner\Security\SecretVault::decrypt($current['openrouter_api_key'] ?? '');
        $openrouter_val = ($in_openrouter === '' || str_contains($in_openrouter, '••'))
            ? $old_openrouter_val
            : sanitize_text_field($in_openrouter);
        $clean['openrouter_api_key'] = ($openrouter_val === $old_openrouter_val && !empty($current['openrouter_api_key']))
            ? $current['openrouter_api_key']
            : \WebCareProScanner\Security\SecretVault::encrypt($openrouter_val);
        $clean['openrouter_model'] = sanitize_text_field($merged['openrouter_model'] ?? 'auto');

        $clean['ai_temperature']           = max(0.0, min(1.0, floatval($merged['ai_temperature'] ?? 0.2)));
        $clean['ai_auto_analyze_critical'] = !empty($merged['ai_auto_analyze_critical']);

        // 4. Scanner Performance & Throttle
        $batch = intval($merged['scan_batch_size'] ?? 50);
        $clean['scan_batch_size']          = ($batch >= 10 && $batch <= 300) ? $batch : 50;
        $valid_envelopes                   = ['strict', 'balanced', 'performance'];
        $clean['scan_memory_safety_envelope'] = in_array($merged['scan_memory_safety_envelope'] ?? '', $valid_envelopes, true) ? $merged['scan_memory_safety_envelope'] : 'balanced';
        $clean['scan_adaptive_throttling'] = !empty($merged['scan_adaptive_throttling']);
        $delay = intval($merged['scan_batch_delay_ms'] ?? 0);
        $clean['scan_batch_delay_ms']      = ($delay >= 0 && $delay <= 2000) ? $delay : 0;
        $valid_strategies                  = ['ajax_client', 'wp_cli_cron', 'background_worker'];
        $clean['scan_execution_strategy']  = in_array($merged['scan_execution_strategy'] ?? '', $valid_strategies, true) ? $merged['scan_execution_strategy'] : 'ajax_client';
        $valid_uploads_mode                = ['smart_executable', 'deep_raster'];
        $clean['scan_uploads_mode']        = in_array($merged['scan_uploads_mode'] ?? '', $valid_uploads_mode, true) ? $merged['scan_uploads_mode'] : 'deep_raster';
        $valid_symlinks                    = ['ignore', 'follow_intree', 'follow_all'];
        $clean['scan_symlink_policy']      = in_array($merged['scan_symlink_policy'] ?? '', $valid_symlinks, true) ? $merged['scan_symlink_policy'] : 'ignore';
        $clean['scan_skip_vcs']            = isset($merged['scan_skip_vcs']) ? !empty($merged['scan_skip_vcs']) : true;
        $clean['scan_skip_vendor']         = isset($merged['scan_skip_vendor']) ? !empty($merged['scan_skip_vendor']) : true;
        $clean['scan_skip_cache']          = !empty($merged['scan_skip_cache']);
        $clean['scan_ignore_cache_folder'] = !empty($merged['scan_ignore_cache_folder']);
        $db_batch = intval($merged['scan_db_batch_size'] ?? 500);
        $clean['scan_db_batch_size']       = ($db_batch >= 50 && $db_batch <= 2000) ? $db_batch : 500;
        $clean['scan_excluded_tables']     = sanitize_textarea_field($merged['scan_excluded_tables'] ?? '');
        $clean['scan_profiling_enabled']   = !empty($merged['scan_profiling_enabled']);
        $clean['scan_dry_run_mode']        = !empty($merged['scan_dry_run_mode']);
        $clean['memory_limit_override']    = sanitize_text_field($merged['memory_limit_override'] ?? '512M');
        $clean['max_file_size_kb']         = max(100, intval($merged['max_file_size_kb'] ?? 2024));
        $clean['auto_quarantine_critical'] = !empty($merged['auto_quarantine_critical']);

        // 5. Exclusions & Ignore Rules
        $clean['excluded_paths']    = sanitize_textarea_field($merged['excluded_paths'] ?? $defaults['excluded_paths']);
        $clean['custom_extensions'] = sanitize_text_field($merged['custom_extensions'] ?? $defaults['custom_extensions']);

        // 6. Security Tweaks & HTTP Security Headers
        $clean['disable_file_editing']  = !empty($merged['disable_file_editing']);
        $clean['hide_wp_version']       = !empty($merged['hide_wp_version']);
        $clean['block_sensitive_files'] = !empty($merged['block_sensitive_files']);
        $clean['block_user_enumeration'] = !empty($merged['block_user_enumeration']);

        // HTTP Security Headers
        $clean['header_hsts']                 = !empty($merged['header_hsts']);
        $clean['header_hsts_preload']         = !empty($merged['header_hsts_preload']);
        $clean['header_x_frame_options']      = !empty($merged['header_x_frame_options']);
        $clean['header_x_frame_options_mode'] = in_array(strtoupper($merged['header_x_frame_options_mode'] ?? ''), ['DENY', 'SAMEORIGIN'], true) ? strtoupper($merged['header_x_frame_options_mode']) : 'SAMEORIGIN';
        $clean['header_nosniff']              = !empty($merged['header_nosniff']);
        $clean['header_referrer_policy']      = !empty($merged['header_referrer_policy']);
        $clean['header_referrer_policy_value'] = sanitize_text_field($merged['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin');
        $clean['header_permissions_policy']   = !empty($merged['header_permissions_policy']);
        $clean['header_permissions_policy_value'] = sanitize_text_field($merged['header_permissions_policy_value'] ?? 'geolocation=(), camera=(), microphone=(), payment=()');
        $clean['header_xss_protection']       = !empty($merged['header_xss_protection']);
        $clean['header_csp_enabled']          = !empty($merged['header_csp_enabled']);
        $clean['header_csp_custom']           = sanitize_text_field($merged['header_csp_custom'] ?? '');

        // 7. Cleanup & Data Privacy on Plugin Uninstall
        $clean['delete_data_on_uninstall'] = !empty($merged['delete_data_on_uninstall']);
        $clean['uninstall_drop_tables']    = isset($merged['uninstall_drop_tables']) ? !empty($merged['uninstall_drop_tables']) : true;
        $clean['uninstall_delete_options'] = isset($merged['uninstall_delete_options']) ? !empty($merged['uninstall_delete_options']) : true;
        $clean['uninstall_delete_crons']   = isset($merged['uninstall_delete_crons']) ? !empty($merged['uninstall_delete_crons']) : true;
        $clean['uninstall_delete_uploads'] = isset($merged['uninstall_delete_uploads']) ? !empty($merged['uninstall_delete_uploads']) : true;

        // 8. Web Application Firewall (WAF) Lite
        $clean['waf_enabled']             = !empty($merged['waf_enabled']);
        $valid_waf_modes                  = ['enabled', 'learning', 'disabled'];
        $clean['waf_mode']                = in_array($merged['waf_mode'] ?? '', $valid_waf_modes, true) ? $merged['waf_mode'] : 'enabled';
        $clean['waf_complementary_mode']  = !empty($merged['waf_complementary_mode']);
        $clean['waf_block_sqli']          = !empty($merged['waf_block_sqli']);
        $clean['waf_block_xss']           = !empty($merged['waf_block_xss']);
        $clean['waf_block_traversal']     = !empty($merged['waf_block_traversal']);
        $clean['waf_block_php_injection'] = !empty($merged['waf_block_php_injection']);
        $clean['waf_disable_xmlrpc']      = !empty($merged['waf_disable_xmlrpc']);
        $clean['waf_allow_jetpack_xmlrpc'] = !empty($merged['waf_allow_jetpack_xmlrpc']);
        $clean['waf_login_rate_limit']    = !empty($merged['waf_login_rate_limit']);
        $clean['waf_whitelisted_ips']     = sanitize_textarea_field($merged['waf_whitelisted_ips'] ?? '');
        $clean['waf_whitelist_require_admin'] = isset($merged['waf_whitelist_require_admin']) ? !empty($merged['waf_whitelist_require_admin']) : true;
        $clean['waf_whitelist_log_telemetry'] = isset($merged['waf_whitelist_log_telemetry']) ? !empty($merged['waf_whitelist_log_telemetry']) : true;
        $clean['waf_blocked_ips']         = sanitize_textarea_field($merged['waf_blocked_ips'] ?? '');
        $clean['waf_block_fake_bots']     = !empty($merged['waf_block_fake_bots']);
        $clean['waf_block_ai_scrapers']   = !empty($merged['waf_block_ai_scrapers']);
        $clean['waf_ai_allow_search_citations']     = isset($merged['waf_ai_allow_search_citations']) ? !empty($merged['waf_ai_allow_search_citations']) : true;
        $clean['waf_ai_throttle_training_scrapers'] = isset($merged['waf_ai_throttle_training_scrapers']) ? !empty($merged['waf_ai_throttle_training_scrapers']) : true;
        $clean['waf_ai_challenge_stealth_agents']   = isset($merged['waf_ai_challenge_stealth_agents']) ? !empty($merged['waf_ai_challenge_stealth_agents']) : true;
        $clean['waf_dynamic_robots_ai']   = !empty($merged['waf_dynamic_robots_ai']);
        $clean['waf_block_404_scanners']   = !empty($merged['waf_block_404_scanners']);
        $clean['waf_404_threshold']        = max(3, min(100, (int) ($merged['waf_404_threshold'] ?? 10)));
        $clean['waf_404_window_seconds']   = max(10, min(600, (int) ($merged['waf_404_window_seconds'] ?? 60)));
        $clean['waf_404_lockout_duration'] = max(1, min(1440, (int) ($merged['waf_404_lockout_duration'] ?? 30)));
        $clean['waf_allow_uptime_monitors']        = !empty($merged['waf_allow_uptime_monitors']);
        $clean['waf_allow_central_management']     = !empty($merged['waf_allow_central_management']);
        $clean['caf_threat_score_enabled']         = !empty($merged['caf_threat_score_enabled']);
        $clean['waf_allow_page_builders']          = !empty($merged['waf_allow_page_builders']);

        // Enhanced Perimeter & Identity Protection Rules
        $clean['waf_forms_safe_mode']             = !empty($merged['waf_forms_safe_mode']);
        $clean['form_spam_protection_enabled']     = !empty($merged['form_spam_protection_enabled']);
        $clean['form_block_headless_browsers']     = !empty($merged['form_block_headless_browsers']);
        $clean['form_honeypot_enabled']             = !empty($merged['form_honeypot_enabled']);
        $clean['form_speed_gate_enabled']           = !empty($merged['form_speed_gate_enabled']);
        $clean['form_min_interaction_seconds']      = max(1, min(10, (int) ($merged['form_min_interaction_seconds'] ?? 2)));
        $clean['form_flood_limit_enabled']          = !empty($merged['form_flood_limit_enabled']);
        $clean['form_max_submits_per_window']       = max(1, min(50, (int) ($merged['form_max_submits_per_window'] ?? 5)));
        $clean['form_flood_window_minutes']         = max(1, min(60, (int) ($merged['form_flood_window_minutes'] ?? 10)));
        $clean['form_content_filtering']            = !empty($merged['form_content_filtering']);
        $clean['form_max_urls_allowed']             = max(0, min(10, (int) ($merged['form_max_urls_allowed'] ?? 2)));
        $clean['waf_ecommerce_safe_mode']         = !empty($merged['waf_ecommerce_safe_mode']);
        $clean['waf_woo_carding_protection']       = !empty($merged['waf_woo_carding_protection']);
        $clean['waf_woo_checkout_max_attempts']    = max(2, min(20, (int) ($merged['waf_woo_checkout_max_attempts'] ?? 3)));
        $clean['waf_woo_carding_lockout_duration'] = max(5, min(1440, (int) ($merged['waf_woo_carding_lockout_duration'] ?? 30)));
        $clean['waf_woo_coupon_protection']        = !empty($merged['waf_woo_coupon_protection']);
        $clean['waf_woo_coupon_max_failures']      = max(2, min(30, (int) ($merged['waf_woo_coupon_max_failures'] ?? 8)));
        $clean['waf_woo_coupon_lockout_duration']  = max(5, min(1440, (int) ($merged['waf_woo_coupon_lockout_duration'] ?? 15)));
        $clean['waf_woo_registration_protection']  = !empty($merged['waf_woo_registration_protection']);
        $clean['waf_woo_reg_max_per_ip']           = max(1, min(20, (int) ($merged['waf_woo_reg_max_per_ip'] ?? 3)));
        $clean['waf_woo_reg_window_hours']         = max(1, min(24, (int) ($merged['waf_woo_reg_window_hours'] ?? 1)));
        $clean['waf_woo_reg_block_disposable_emails'] = !empty($merged['waf_woo_reg_block_disposable_emails']);
        $clean['waf_woo_cart_flood_protection']    = !empty($merged['waf_woo_cart_flood_protection']);
        $clean['waf_woo_max_cart_items']           = max(5, min(500, (int) ($merged['waf_woo_max_cart_items'] ?? 50)));
        $clean['waf_woo_add_to_cart_rate_limit']   = max(3, min(60, (int) ($merged['waf_woo_add_to_cart_rate_limit'] ?? 15)));
        $clean['waf_woo_scraping_protection']      = !empty($merged['waf_woo_scraping_protection']);
        $clean['waf_woo_scraping_max_requests']    = max(10, min(300, (int) ($merged['waf_woo_scraping_max_requests'] ?? 60)));
        $clean['waf_woo_scraping_lockout_duration'] = max(5, min(1440, (int) ($merged['waf_woo_scraping_lockout_duration'] ?? 15)));
        $clean['waf_affiliate_shield_enabled']      = !empty($merged['waf_affiliate_shield_enabled']);
        $clean['waf_affiliate_max_clicks_min']      = max(3, min(300, (int) ($merged['waf_affiliate_max_clicks_min'] ?? 10)));
        $clean['waf_affiliate_anti_injection']      = !empty($merged['waf_affiliate_anti_injection']);
        $clean['waf_affiliate_reg_spam_protection'] = !empty($merged['waf_affiliate_reg_spam_protection']);
        $clean['waf_affiliate_direct_link_armor']   = !empty($merged['waf_affiliate_direct_link_armor']);
        $clean['waf_block_empty_post_ua_referer'] = !empty($merged['waf_block_empty_post_ua_referer']);
        $clean['waf_block_empty_user_agent']        = !empty($merged['waf_block_empty_user_agent']);
        $clean['waf_enable_progressive_warnings']   = !empty($merged['waf_enable_progressive_warnings']);
        $clean['waf_contact_support_url']           = esc_url_raw(trim((string) ($merged['waf_contact_support_url'] ?? '')));
        $clean['waf_whitelisted_urls']            = sanitize_textarea_field($merged['waf_whitelisted_urls'] ?? '');

        // Targeted User-Agent, Endpoint & IP Allowlist Rules
        $raw_targeted = $merged['waf_targeted_allowlist_rules'] ?? '[]';
        $clean_targeted = self::sanitize_targeted_allowlist_rules($raw_targeted);
        $clean['waf_targeted_allowlist_rules']    = wp_json_encode($clean_targeted);

        $clean['waf_block_forbidden_usernames']   = !empty($merged['waf_block_forbidden_usernames']);
        $clean['waf_forbidden_usernames_list']    = sanitize_textarea_field($merged['waf_forbidden_usernames_list'] ?? "admin\nadministrator\nroot");
        $clean['waf_prevent_admin_registration']  = !empty($merged['waf_prevent_admin_registration']);
        $clean['waf_mask_login_errors']           = !empty($merged['waf_mask_login_errors']);
        $clean['waf_enforce_strong_passwords']    = !empty($merged['waf_enforce_strong_passwords']);
        $clean['waf_strong_passwords_roles']      = sanitize_text_field($merged['waf_strong_passwords_roles'] ?? 'administrator, editor');
        $clean['waf_check_pwned_passwords']       = !empty($merged['waf_check_pwned_passwords']);
        $clean['waf_block_malicious_uploads']     = !empty($merged['waf_block_malicious_uploads']);
        $clean['waf_block_unsafe_http_methods']   = !empty($merged['waf_block_unsafe_http_methods']);
        $clean['waf_block_null_byte_attacks']     = !empty($merged['waf_block_null_byte_attacks']);
        $clean['waf_block_sensitive_file_probes'] = !empty($merged['waf_block_sensitive_file_probes']);
        $clean['waf_block_uploads_php_exec']      = !empty($merged['waf_block_uploads_php_exec']);
        $clean['waf_block_external_cron']         = !empty($merged['waf_block_external_cron']);
        $clean['waf_block_open_redirects']        = !empty($merged['waf_block_open_redirects']);
        $clean['waf_block_ssrf_metadata']         = !empty($merged['waf_block_ssrf_metadata']);
        $clean['waf_block_install_php']           = !empty($merged['waf_block_install_php']);

        // Specialized Armor: phpMyAdmin & File Manager Restrictions
        $clean['waf_disallow_phpmyadmin_plugins']  = !empty($merged['waf_disallow_phpmyadmin_plugins']);
        $clean['waf_disallow_filemanager_plugins'] = !empty($merged['waf_disallow_filemanager_plugins']);
        $clean['waf_disallow_phpmyadmin_uploads']  = !empty($merged['waf_disallow_phpmyadmin_uploads']);
        $clean['waf_disallow_filemanager_uploads'] = !empty($merged['waf_disallow_filemanager_uploads']);

        // Phase 2: Enumeration Suppression & Abuse / Rate Guards (Rules #29 - #34)
        $clean['waf_block_rest_user_enum']     = !empty($merged['waf_block_rest_user_enum']);
        $clean['waf_block_author_scan']        = !empty($merged['waf_block_author_scan']);
        $clean['waf_limit_lostpassword']       = !empty($merged['waf_limit_lostpassword']);
        $clean['waf_enforce_host_allowlist']   = !empty($merged['waf_enforce_host_allowlist']);
        $clean['waf_allowed_host_aliases']     = sanitize_textarea_field($merged['waf_allowed_host_aliases'] ?? '');
        $clean['waf_limit_admin_ajax']         = !empty($merged['waf_limit_admin_ajax']);
        $clean['waf_admin_ajax_limit_per_min'] = max(10, min(300, (int) ($merged['waf_admin_ajax_limit_per_min'] ?? 60)));
        $clean['waf_block_oversized_requests'] = !empty($merged['waf_block_oversized_requests']);
        $clean['waf_block_ai_prompt_injection'] = !empty($merged['waf_block_ai_prompt_injection']);
        $cf_mode_in = sanitize_key($merged['waf_cloudflare_proxy_trust_mode'] ?? 'disabled');
        $clean['waf_cloudflare_proxy_trust_mode'] = in_array($cf_mode_in, ['disabled', 'auto_detected', 'enabled'], true) ? $cf_mode_in : 'disabled';
        if (array_key_exists('waf_cloudflare_origin_secret', $input)) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Origin pull secrets preserve percent/special characters; control chars are stripped prior to Vault encryption
            $raw_origin_secret = is_string($input['waf_cloudflare_origin_secret']) ? (string) wp_unslash($input['waf_cloudflare_origin_secret']) : '';
            $raw_origin_secret = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $raw_origin_secret);
            $raw_origin_secret = substr($raw_origin_secret, 0, 512);
            if ($raw_origin_secret === '') {
                $clean['waf_cloudflare_origin_secret'] = '';
            } elseif (str_contains($raw_origin_secret, '••')) {
                $clean['waf_cloudflare_origin_secret'] = (string) ($current['waf_cloudflare_origin_secret'] ?? '');
            } else {
                $old_origin_secret = \WebCareProScanner\Security\SecretVault::decrypt((string) ($current['waf_cloudflare_origin_secret'] ?? ''));
                $clean['waf_cloudflare_origin_secret'] = ($raw_origin_secret === $old_origin_secret && !empty($current['waf_cloudflare_origin_secret']))
                    ? (string) $current['waf_cloudflare_origin_secret']
                    : \WebCareProScanner\Security\SecretVault::encrypt($raw_origin_secret);
            }
        } else {
            $clean['waf_cloudflare_origin_secret'] = (string) ($current['waf_cloudflare_origin_secret'] ?? '');
        }
        $clean['waf_rewrite_server_remote_addr'] = !empty($merged['waf_rewrite_server_remote_addr']);
        $clean['waf_max_inspected_body_bytes']  = max(1048576, min(67108864, (int) ($merged['waf_max_inspected_body_bytes'] ?? 4194304)));

        // Rule #36 & #37: Guest admin-ajax.php / admin-post.php and REST Security Matrix
        $in_ajax_policy = sanitize_key($merged['waf_guest_ajax_policy'] ?? 'monitor');
        $clean['waf_guest_ajax_policy'] = in_array($in_ajax_policy, ['monitor', 'block', 'off'], true) ? $in_ajax_policy : 'monitor';
        $clean['waf_guest_ajax_custom_allowlist'] = sanitize_textarea_field($merged['waf_guest_ajax_custom_allowlist'] ?? '');
        $in_rest_policy = sanitize_key($merged['waf_guest_rest_policy'] ?? 'block');
        $clean['waf_guest_rest_policy'] = in_array($in_rest_policy, ['block', 'monitor', 'off'], true) ? $in_rest_policy : 'block';
        $clean['waf_guest_rest_custom_allowlist'] = sanitize_textarea_field($merged['waf_guest_rest_custom_allowlist'] ?? '');
        $clean['waf_runtime_rasp_privilege_guard'] = !empty($merged['waf_runtime_rasp_privilege_guard']);
        $clean['waf_upload_deep_mime_sanitizer']   = !empty($merged['waf_upload_deep_mime_sanitizer']);
        $valid_retention = [7, 14, 30, 60, 90, 180, 365, 0];
        $retention_val = (int) ($merged['waf_log_retention_days'] ?? 60);
        $clean['waf_log_retention_days'] = in_array($retention_val, $valid_retention, true) ? $retention_val : 60;

        // 9. Cloud Threat Intelligence & Community Blacklists
        $clean['threat_intel_enabled']               = !empty($merged['threat_intel_enabled']);
        $clean['threat_intel_block_blacklisted_ips'] = !empty($merged['threat_intel_block_blacklisted_ips']);
        $clean['threat_intel_cisa_kev_enabled']        = !isset($merged['threat_intel_cisa_kev_enabled']) || !empty($merged['threat_intel_cisa_kev_enabled']);
        $clean['threat_intel_nvd_cve_enabled']         = !isset($merged['threat_intel_nvd_cve_enabled']) || !empty($merged['threat_intel_nvd_cve_enabled']);
        $clean['threat_intel_wpvulnerability_enabled'] = !isset($merged['threat_intel_wpvulnerability_enabled']) || !empty($merged['threat_intel_wpvulnerability_enabled']);
        $clean['threat_intel_public_cidr_enabled']     = !isset($merged['threat_intel_public_cidr_enabled']) || !empty($merged['threat_intel_public_cidr_enabled']);

        // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
        $clean['auth_2fa_enabled']          = !empty($merged['auth_2fa_enabled']);
        $raw_2fa_algo                       = strtolower(sanitize_key($merged['auth_2fa_algorithm'] ?? 'sha1'));
        $clean['auth_2fa_algorithm']        = in_array($raw_2fa_algo, ['sha1', 'sha512'], true) ? $raw_2fa_algo : 'sha1';
        $clean['auth_2fa_digits']           = ((int) ($merged['auth_2fa_digits'] ?? 6) === 8 || $clean['auth_2fa_algorithm'] === 'sha512') ? 8 : 6;
        $clean['auth_2fa_remember_device']  = !empty($merged['auth_2fa_remember_device']);
        $clean['auth_2fa_remember_days']    = max(1, min(90, (int) ($merged['auth_2fa_remember_days'] ?? 7)));
        $clean['auth_2fa_enforce_admins']   = !empty($merged['auth_2fa_enforce_admins']);
        $raw_mode                           = sanitize_key($merged['auth_2fa_policy_mode'] ?? 'remind_login');
        $clean['auth_2fa_policy_mode']      = in_array($raw_mode, ['immediate', 'grace_period', 'remind_login'], true) ? $raw_mode : 'remind_login';
        $clean['auth_2fa_grace_days']       = max(0, min(90, (int) ($merged['auth_2fa_grace_days'] ?? 0)));
        // Record timestamp when enforcement is newly enabled
        $prev_enforce = !empty($current['auth_2fa_enforce_admins']);
        if ($clean['auth_2fa_enforce_admins'] && !$prev_enforce) {
            $clean['auth_2fa_enforce_since'] = time();
        } elseif (!$clean['auth_2fa_enforce_admins']) {
            $clean['auth_2fa_enforce_since'] = 0;
        } else {
            $clean['auth_2fa_enforce_since'] = (int) ($current['auth_2fa_enforce_since'] ?? time());
        }
        $clean['login_hardening_enabled']   = !empty($merged['login_hardening_enabled']);
        $clean['login_max_retries']         = max(1, min(20, (int) ($merged['login_max_retries'] ?? 5)));
        $clean['login_lockout_duration']    = max(1, min(1440, (int) ($merged['login_lockout_duration'] ?? 15)));
        $clean['session_sentinel_enabled']  = !empty($merged['session_sentinel_enabled']);
        $clean['session_block_concurrent']  = !empty($merged['session_block_concurrent']);
        $clean['webauthn_remember_session'] = !empty($merged['webauthn_remember_session']);


        // 11. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n - Encrypted with SecretVault)
        $clean['slack_enabled']                 = !empty($merged['slack_enabled']);
        $in_slack                               = isset($input['slack_webhook_url']) ? trim($input['slack_webhook_url']) : null;
        if ($in_slack === '') {
            $clean['slack_webhook_url'] = '';
        } elseif ($in_slack !== null) {
            $is_masked_slack = strpos($in_slack, '••') !== false;
            $old_slack_val   = \WebCareProScanner\Security\SecretVault::decrypt($current['slack_webhook_url'] ?? '');
            $slack_val       = $is_masked_slack ? $old_slack_val : esc_url_raw($in_slack);
            $clean['slack_webhook_url'] = (!empty($slack_val))
                ? (($slack_val === $old_slack_val && !empty($current['slack_webhook_url'])) ? $current['slack_webhook_url'] : \WebCareProScanner\Security\SecretVault::encrypt($slack_val))
                : '';
        } else {
            $clean['slack_webhook_url'] = $current['slack_webhook_url'] ?? '';
        }

        $clean['discord_enabled']               = !empty($merged['discord_enabled']);
        $in_discord                             = isset($input['discord_webhook_url']) ? trim($input['discord_webhook_url']) : null;
        if ($in_discord === '') {
            $clean['discord_webhook_url'] = '';
        } elseif ($in_discord !== null) {
            $is_masked_discord = strpos($in_discord, '••') !== false;
            $old_discord_val   = \WebCareProScanner\Security\SecretVault::decrypt($current['discord_webhook_url'] ?? '');
            $discord_val       = $is_masked_discord ? $old_discord_val : esc_url_raw($in_discord);
            $clean['discord_webhook_url'] = (!empty($discord_val))
                ? (($discord_val === $old_discord_val && !empty($current['discord_webhook_url'])) ? $current['discord_webhook_url'] : \WebCareProScanner\Security\SecretVault::encrypt($discord_val))
                : '';
        } else {
            $clean['discord_webhook_url'] = $current['discord_webhook_url'] ?? '';
        }

        $clean['clickup_enabled']               = !empty($merged['clickup_enabled']);
        $in_clickup                             = isset($input['clickup_webhook_url']) ? trim($input['clickup_webhook_url']) : null;
        if ($in_clickup === '') {
            $clean['clickup_webhook_url'] = '';
        } elseif ($in_clickup !== null) {
            $is_masked_clickup = strpos($in_clickup, '••') !== false;
            $old_clickup_val   = \WebCareProScanner\Security\SecretVault::decrypt($current['clickup_webhook_url'] ?? '');
            $clickup_val       = $is_masked_clickup ? $old_clickup_val : esc_url_raw($in_clickup);
            $clean['clickup_webhook_url'] = (!empty($clickup_val))
                ? (($clickup_val === $old_clickup_val && !empty($current['clickup_webhook_url'])) ? $current['clickup_webhook_url'] : \WebCareProScanner\Security\SecretVault::encrypt($clickup_val))
                : '';
        } else {
            $clean['clickup_webhook_url'] = $current['clickup_webhook_url'] ?? '';
        }

        $clean['asana_enabled']                 = !empty($merged['asana_enabled']);
        $in_asana                               = isset($input['asana_webhook_url']) ? trim($input['asana_webhook_url']) : null;
        if ($in_asana === '') {
            $clean['asana_webhook_url'] = '';
        } elseif ($in_asana !== null) {
            $is_masked_asana = strpos($in_asana, '••') !== false;
            $old_asana_val   = \WebCareProScanner\Security\SecretVault::decrypt($current['asana_webhook_url'] ?? '');
            $asana_val       = $is_masked_asana ? $old_asana_val : esc_url_raw($in_asana);
            $clean['asana_webhook_url'] = (!empty($asana_val))
                ? (($asana_val === $old_asana_val && !empty($current['asana_webhook_url'])) ? $current['asana_webhook_url'] : \WebCareProScanner\Security\SecretVault::encrypt($asana_val))
                : '';
        } else {
            $clean['asana_webhook_url'] = $current['asana_webhook_url'] ?? '';
        }

        $clean['generic_webhook_enabled']       = !empty($merged['generic_webhook_enabled']);
        $in_generic                             = isset($input['generic_webhook_url']) ? trim($input['generic_webhook_url']) : null;
        if ($in_generic === '') {
            $clean['generic_webhook_url'] = '';
        } elseif ($in_generic !== null) {
            $is_masked_generic = strpos($in_generic, '••') !== false;
            $old_generic_val   = \WebCareProScanner\Security\SecretVault::decrypt($current['generic_webhook_url'] ?? '');
            $generic_val       = $is_masked_generic ? $old_generic_val : esc_url_raw($in_generic);
            $clean['generic_webhook_url'] = (!empty($generic_val))
                ? (($generic_val === $old_generic_val && !empty($current['generic_webhook_url'])) ? $current['generic_webhook_url'] : \WebCareProScanner\Security\SecretVault::encrypt($generic_val))
                : '';
        } else {
            $clean['generic_webhook_url'] = $current['generic_webhook_url'] ?? '';
        }

        $clean['webhook_notify_on_critical']    = !empty($merged['webhook_notify_on_critical']);
        $clean['webhook_notify_on_fim']         = !empty($merged['webhook_notify_on_fim']);
        $clean['webhook_notify_on_waf_block']   = !empty($merged['webhook_notify_on_waf_block']);
        $clean['webhook_notify_on_scan_finish'] = !empty($merged['webhook_notify_on_scan_finish']);

        // 12. Cloudflare Edge Defense Integration (Encrypted with SecretVault)
        $clean['cloudflare_enabled']        = !empty($merged['cloudflare_enabled']);
        $in_cf_token                        = trim($input['cloudflare_api_token'] ?? '');
        $is_disconnect                      = !empty($input['cloudflare_disconnect']) || !empty($input['cloudflare_clear']) || (array_key_exists('cloudflare_api_token', $input) && $in_cf_token === '' && empty($clean['cloudflare_enabled']));

        if ($is_disconnect) {
            $clean['cloudflare_enabled']   = false;
            $clean['cloudflare_api_token'] = '';
            $clean['cloudflare_zone_id']   = '';
        } else {
            $is_masked_token                    = $in_cf_token === '' || strpos($in_cf_token, '••') !== false;
            $old_cf_token_val                   = \WebCareProScanner\Security\SecretVault::decrypt($current['cloudflare_api_token'] ?? '');
            $cf_token_val                       = $is_masked_token
                ? $old_cf_token_val
                : sanitize_text_field($in_cf_token);
            $clean['cloudflare_api_token']      = ($cf_token_val === $old_cf_token_val && !empty($current['cloudflare_api_token']))
                ? $current['cloudflare_api_token']
                : (!empty($cf_token_val) ? \WebCareProScanner\Security\SecretVault::encrypt($cf_token_val) : '');

            $in_zone_id                         = trim($input['cloudflare_zone_id'] ?? '');
            $is_masked_zone                     = $in_zone_id === '' || strpos($in_zone_id, '••') !== false;
            $old_zone_id_val                    = \WebCareProScanner\Security\SecretVault::decrypt($current['cloudflare_zone_id'] ?? '');
            $zone_id_val                        = $is_masked_zone
                ? $old_zone_id_val
                : sanitize_text_field($in_zone_id);
            $clean['cloudflare_zone_id']        = ($zone_id_val === $old_zone_id_val && !empty($current['cloudflare_zone_id']))
                ? $current['cloudflare_zone_id']
                : (!empty($zone_id_val) ? \WebCareProScanner\Security\SecretVault::encrypt($zone_id_val) : '');
        }

        if (!empty($clean['cloudflare_enabled'])) {
            if (isset($input['cloudflare_auto_sync_bans'])) {
                $clean['cloudflare_auto_sync_bans'] = !empty($input['cloudflare_auto_sync_bans']);
            } elseif (isset($merged['cloudflare_auto_sync_bans'])) {
                $clean['cloudflare_auto_sync_bans'] = !empty($merged['cloudflare_auto_sync_bans']);
            } else {
                $clean['cloudflare_auto_sync_bans'] = true;
            }
        } else {
            $clean['cloudflare_auto_sync_bans'] = false;
        }

        // 13. False-Positive Tuning & Confidence Thresholds
        $clean['confidence_threshold_filesystem'] = max(1, min(100, intval($merged['confidence_threshold_filesystem'] ?? 50)));
        $clean['confidence_threshold_lotl']       = max(1, min(100, intval($merged['confidence_threshold_lotl'] ?? 60)));
        $clean['confidence_threshold_ai']         = max(1, min(100, intval($merged['confidence_threshold_ai'] ?? 70)));
        $clean['confidence_threshold_db']         = max(1, min(100, intval($merged['confidence_threshold_db'] ?? 50)));
        $clean['auto_suppress_whitelisted']       = !empty($merged['auto_suppress_whitelisted']);

        // 14. Model Context Protocol (MCP) Agent Service Surface
        $clean['mcp_enabled'] = !empty($merged['mcp_enabled']);
        $mcp_tok = trim($input['mcp_token'] ?? '');
        $is_masked_mcp = (strpos($mcp_tok, '••••') !== false);
        $token_rotated = false;
        if ((empty($mcp_tok) || $is_masked_mcp) && !empty($current['mcp_token'])) {
            $raw_existing = $current['mcp_token'];
            $clean['mcp_token'] = \WebCareProScanner\Security\SecretVault::is_encrypted($raw_existing)
                ? $raw_existing
                : \WebCareProScanner\Security\SecretVault::encrypt($raw_existing);
        } elseif (!empty($mcp_tok) && !$is_masked_mcp) {
            $sanitized_tok = sanitize_text_field($mcp_tok);
            $clean['mcp_token'] = \WebCareProScanner\Security\SecretVault::encrypt($sanitized_tok);
            $token_rotated = true;
        } else {
            // Keep existing token if present in current settings
            if (!empty($current['mcp_token'])) {
                $clean['mcp_token'] = $current['mcp_token'];
            } else {
                $new_mcp_plain = 'webcareproscan_mcp_' . bin2hex(random_bytes(16));
                $clean['mcp_token'] = \WebCareProScanner\Security\SecretVault::encrypt($new_mcp_plain);
                $token_rotated = true;
            }
        }

        $clean['mcp_token_created_at'] = $token_rotated
            ? time()
            : max(0, intval($merged['mcp_token_created_at'] ?? ($current['mcp_token_created_at'] ?? 0)));
        $valid_ttls = [0, 7, 30, 90, 365];
        $ttl_cand   = intval($merged['mcp_token_ttl_days'] ?? ($current['mcp_token_ttl_days'] ?? 0));
        $clean['mcp_token_ttl_days'] = in_array($ttl_cand, $valid_ttls, true) ? $ttl_cand : max(0, min(365, $ttl_cand));
        $mcp_cidrs_input = (string) ($merged['mcp_allowed_cidrs'] ?? ($current['mcp_allowed_cidrs'] ?? ''));
        $clean['mcp_allowed_cidrs']  = ($mcp_cidrs_input !== '' && trim($mcp_cidrs_input) === '') ? $mcp_cidrs_input : sanitize_textarea_field($mcp_cidrs_input);

        $valid_personas = ['observer', 'guided', 'safe_operator'];
        $clean['mcp_persona_preset'] = in_array($merged['mcp_persona_preset'] ?? '', $valid_personas, true)
            ? $merged['mcp_persona_preset']
            : ($current['mcp_persona_preset'] ?? 'guided');

        $valid_scopes = ['read_only', 'safe_operator', 'staged_proposer', 'read_write'];
        $clean['mcp_permission_scope'] = in_array($merged['mcp_permission_scope'] ?? '', $valid_scopes, true)
            ? $merged['mcp_permission_scope']
            : ($current['mcp_permission_scope'] ?? 'read_only');

        $clean['mcp_rate_limit_per_min'] = max(10, min(600, intval($merged['mcp_rate_limit_per_min'] ?? ($current['mcp_rate_limit_per_min'] ?? 60))));

        if (isset($input['mcp_tool_matrix']) && is_array($input['mcp_tool_matrix'])) {
            $clean['mcp_tool_matrix'] = self::sanitize_mcp_tool_matrix($input['mcp_tool_matrix']);
        } elseif (isset($current['mcp_tool_matrix']) && is_array($current['mcp_tool_matrix'])) {
            $clean['mcp_tool_matrix'] = self::sanitize_mcp_tool_matrix($current['mcp_tool_matrix']);
        } else {
            $clean['mcp_tool_matrix'] = self::get_default_mcp_tool_matrix();
        }

        // 15. Custom Scan Engine Options
        if (isset($input['custom_scan_options']) && is_array($input['custom_scan_options'])) {
            $clean['custom_scan_options'] = self::sanitize_custom_scan_options($input['custom_scan_options']);
        } elseif (isset($merged['custom_scan_options']) && is_array($merged['custom_scan_options'])) {
            $clean['custom_scan_options'] = self::sanitize_custom_scan_options($merged['custom_scan_options']);
        } else {
            $clean['custom_scan_options'] = self::get_default_custom_scan_options();
        }

        // 16. Plugin Self-Defense
        $clean['self_defense_watchdog_enabled'] = !empty($merged['self_defense_watchdog_enabled']);
        $clean['self_defense_notify_email']     = !empty($merged['self_defense_notify_email']);

        // 17. Granular Event Notifications Matrix
        $clean['notification_master_enabled']   = !empty($merged['notification_master_enabled']);
        if (isset($input['notification_events']) && is_array($input['notification_events'])) {
            $clean['notification_events'] = self::sanitize_notification_events($input['notification_events']);
        } elseif (isset($current['notification_events']) && is_array($current['notification_events'])) {
            $clean['notification_events'] = self::sanitize_notification_events($current['notification_events']);
        } else {
            $clean['notification_events'] = self::get_default_notification_events();
        }

        // 18. Activity & Audit Logs Configuration (deferred until lock-fenced OPTION_KEY write succeeds)
        $pending_act_settings = null;
        if (isset($input['activity_log_settings']) && is_array($input['activity_log_settings'])) {
            $ret_days = isset($input['activity_log_settings']['retention_days']) ? (int) $input['activity_log_settings']['retention_days'] : 30;
            if ($ret_days !== 0 && $ret_days < 7) {
                $ret_days = 7; // Minimum 7-day forensic immutability
            }
            $pending_act_settings = [
                'retention_days'      => $ret_days,
                'tamper_webhook_url'  => isset($input['activity_log_settings']['tamper_webhook_url']) ? esc_url_raw($input['activity_log_settings']['tamper_webhook_url']) : '',
            ];
        }

        // 19. Centralized Cron & Task Automation Control
        $cron_bool_keys = [
            'cron_waf_log_prune_enabled',
            'cron_cve_audit_enabled',
            'cron_domain_reputation_enabled',
            'cron_redirect_canary_enabled',
            'cron_reinfection_watchdog_enabled',
            'cron_custom_rules_autopilot_enabled',
            'cron_custom_rules_ast_bg_enabled',
            'cron_scan_bg_enabled',
            'cron_backup_bg_enabled',
        ];
        foreach ($cron_bool_keys as $cron_k) {
            $clean[$cron_k] = array_key_exists($cron_k, $merged) ? !empty($merged[$cron_k]) : true;
        }

        $allowed_intervals = ['webcare_every_five_minutes', 'webcare_15min', 'webcare_30min', 'hourly', 'twicedaily', 'daily', 'weekly'];
        $clean_schedules   = [];
        $raw_schedules     = is_array($merged['cron_task_schedules'] ?? null) ? $merged['cron_task_schedules'] : [];
        foreach ($raw_schedules as $hk => $freq) {
            $clean_hk   = sanitize_key((string) $hk);
            $clean_freq = sanitize_key((string) $freq);
            if ($clean_hk !== '' && in_array($clean_freq, $allowed_intervals, true)) {
                $clean_schedules[$clean_hk] = $clean_freq;
            }
        }
        $clean['cron_task_schedules']     = $clean_schedules;
        $clean['cron_log_retention_days'] = max(7, min(365, intval($merged['cron_log_retention_days'] ?? 30)));

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            $clean = array_merge($clean, \WebCareProScanner\Core\ModuleRegistry::sanitize_module_settings($merged, $current, $input));
        }

        if (self::$last_webhook_secret_store_failed) {
            self::$last_webhook_secret_store_failed = false;
            return false;
        }

        if (is_callable(self::$before_persist_settings_hook)) {
            (self::$before_persist_settings_hook)($lock_token);
        }

        // Renew lease after sanitization if still valid & owned by $lock_token
        if (!self::renew_mutation_lock($lock_token)) {
            return false;
        }

        if (is_callable(self::$after_renewal_before_write_hook)) {
            (self::$after_renewal_before_write_hook)($lock_token);
        }

        $out_clean = $clean;

        // Compute settings diff before persisting
        $diff = self::compute_settings_diff($current, $clean);
        $next_revision = $baseline_revision + 1;
        $safe_snapshot_settings = ($record_snapshot && !empty($diff)) ? self::strip_secrets($current) : [];

        $touched_options = [
            self::OPTION_KEY,
            \WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION,
            self::OPTION_REVISION_KEY,
        ];
        if ($pending_act_settings !== null) {
            $touched_options[] = 'webcareproscan_activity_log_settings';
        }
        if ($record_snapshot && !empty($diff) && !empty($safe_snapshot_settings)) {
            $touched_options[] = self::OPTION_SNAPSHOTS_KEY;
        }

        // Commit settings, secondary options, monotonic revision, and snapshot history atomically
        // inside a single database-fenced InnoDB transaction holding SELECT ... FOR UPDATE on OPTION_MUTATION_LOCK.
        $committed = self::execute_fenced_transaction(
            $lock_token,
            $baseline_revision,
            static function () use ($clean, $pending_act_settings, $next_revision, $record_snapshot, $diff, $safe_snapshot_settings): bool {
                if (!self::transactional_upsert_option(self::OPTION_KEY, $clean, 'no')) {
                    return false;
                }
                if (!self::transactional_upsert_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION, $clean['waf_log_retention_days'], 'no')) {
                    return false;
                }
                if ($pending_act_settings !== null && !self::transactional_upsert_option('webcareproscan_activity_log_settings', $pending_act_settings, 'no')) {
                    return false;
                }
                if (!self::transactional_upsert_option(self::OPTION_REVISION_KEY, $next_revision, 'no')) {
                    return false;
                }

                if ($record_snapshot && !empty($diff) && !empty($safe_snapshot_settings)) {
                    $snapshots = self::transactional_read_option_for_update(self::OPTION_SNAPSHOTS_KEY, []);
                    if (!is_array($snapshots)) {
                        $snapshots = [];
                    }
                    array_unshift($snapshots, [
                        'id'        => 'snap_' . bin2hex(random_bytes(8)),
                        'revision'  => $next_revision,
                        'timestamp' => time(),
                        'user'      => function_exists('wp_get_current_user') ? (wp_get_current_user()->user_login ?? 'system') : 'system',
                        'settings'  => $safe_snapshot_settings,
                    ]);
                    if (count($snapshots) > self::MAX_SNAPSHOTS) {
                        $snapshots = array_slice($snapshots, 0, self::MAX_SNAPSHOTS);
                    }
                    if (!self::transactional_upsert_option(self::OPTION_SNAPSHOTS_KEY, $snapshots, 'no')) {
                        return false;
                    }
                }

                return true;
            },
            $touched_options
        );

        if (!$committed) {
            return false;
        }

        // Synchronize Cron Schedule
        self::sync_cron_schedule($clean);
        if (class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter') && !\WebCareProScanner\System\Cron\CronControlCenter::$syncing_from_cron_center) {
            \WebCareProScanner\System\Cron\CronControlCenter::sync_all_from_settings($clean);
        }

        // Audit Trail: Log settings change if diff is non-empty
        // Strictly record changes made by authorized administrators or explicit administrative processes
        if (!empty($diff)) {
            // Ignore internal machine tokens from admin activity diff
            unset($diff['mcp_token']);

            // Exclude automated bot-banned IP list updates from settings audit trail
            // (Automated bot traps belong in WAF logs, not admin configuration logs)
            if (isset($diff['waf_blocked_ips']) && !current_user_can('manage_options')) {
                unset($diff['waf_blocked_ips']);
            }

            // Exclude background/bot-triggered settings modifications when not executed by an administrator
            if (!current_user_can('manage_options') && !defined('WP_CLI')) {
                $diff = [];
            }

            // Suppress secondary generic firewall_ruleset_modified when an explicit IP action is logged or suppressed
            if (!empty($diff) && (self::$suppress_firewall_ruleset_log || (class_exists('\WebCareProScanner\System\WebCareActivityLogger') && \WebCareProScanner\System\WebCareActivityLogger::has_action_logged('firewall_ip_unblocked', 'firewall_ip_blocked', 'firewall_ip_whitelisted', 'firewall_ip_whitelist_removed')))) {
                $diff_keys_check = array_keys($diff);
                $substantive_keys = array_diff($diff_keys_check, ['waf_blocked_ips', 'waf_whitelisted_ips']);
                if (empty($substantive_keys)) {
                    $diff = [];
                }
            }

            if (!empty($diff)) {
                // Check if changes are firewall/WAF related
                $diff_keys = array_keys($diff);
                $waf_keys = array_filter($diff_keys, function($k) {
                    return strpos($k, 'waf_') === 0 || strpos($k, 'threat_intel_') === 0 || strpos($k, 'cloudflare_') === 0;
                });

                $is_firewall = !empty($waf_keys) && count($waf_keys) >= (count($diff_keys) / 2);

                if ($is_firewall) {
                    // Determine user-friendly description if single rule was toggled
                    $current_user = wp_get_current_user();
                    $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
                    $ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                        ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                        : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

                    $friendly_desc = sprintf('Firewall rule modification: updated %d security policy parameter(s) by %s from IP %s.', count($diff), $user_login, $ip);
                    if (count($diff) === 1) {
                        $single_key = array_key_first($diff);
                        $new_val = $diff[$single_key]['new'] ?? null;
                        $rule_name = self::get_rule_friendly_name($single_key);

                        if ($single_key === 'waf_blocked_ips') {
                            $friendly_desc = sprintf('Firewall Custom Blocked IP List updated by %s from IP %s.', $user_login, $ip);
                        } elseif ($single_key === 'waf_mode') {
                            $friendly_desc = sprintf('Firewall Operating Mode set to "%s" by %s from IP %s.', esc_html((string) $new_val), $user_login, $ip);
                        } else {
                            $state_text = ($new_val === true || $new_val === 'enabled' || $new_val === 1 || $new_val === '1') ? 'turned on' : 'turned off';
                            $friendly_desc = sprintf('%s is %s by %s with IP %s.', $rule_name, $state_text, $user_login, $ip);
                        }
                    }

                    \WebCareProScanner\System\WebCareActivityLogger::notice(
                        'firewall_ruleset_modified',
                        'firewall',
                        [
                            'changed_count' => count($diff),
                            'description'   => $friendly_desc,
                            'rules'         => array_values($waf_keys),
                            'diff'          => $diff,
                        ]
                    );
                } else {
                    \WebCareProScanner\System\WebCareActivityLogger::notice(
                        'settings_updated',
                        'settings',
                        [
                            'changed_count' => count($diff),
                            'description'   => sprintf('Updated %d plugin configuration setting(s).', count($diff)),
                            'diff'          => $diff,
                        ]
                    );
                }
            }

            // Recompile Preload Micro-WAF when whitelist, blocklist, or WAF operating mode changes
            $preload_sync_keys = [
                'waf_enabled',
                'waf_mode',
                'waf_whitelisted_ips',
                'waf_whitelisted_urls',
                'waf_whitelist_require_admin',
                'waf_blocked_ips',
                'waf_block_threat_intel_ips',
                'waf_trusted_proxies',
            ];
            if (
                !empty(array_intersect(array_keys($diff), $preload_sync_keys))
                && class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')
                && file_exists(\WebCareProScanner\Firewall\MicroWafCompiler::get_compiled_file_path())
            ) {
                \WebCareProScanner\Firewall\MicroWafCompiler::compile();
            }
            if (!empty(array_intersect(array_keys($diff), ['cloudflare_enabled', 'cloudflare_api_token', 'cloudflare_zone_id']))) {
                delete_transient('webcareproscan_cf_zone_meta_' . md5((string) ($current['cloudflare_zone_id'] ?? '')));
                delete_transient('webcareproscan_cf_zone_meta_' . md5((string) ($clean['cloudflare_zone_id'] ?? '')));
            }
        }

        return self::get_settings();
    }

    /**
     * Compute clean before/after diff of changed settings with redacted secrets.
     *
     * @param array $old_settings
     * @param array $new_settings
     * @return array
     */
    /**
     * Get a human-readable title for a firewall rule or setting key.
     *
     * @param string $key
     * @return string
     */
    public static function get_rule_friendly_name(string $key): string {
        $map = [
            'waf_block_sqli'                   => 'SQL Injection (SQLi) Defense',
            'waf_block_xss'                    => 'Cross-Site Scripting (XSS) Defense',
            'waf_block_traversal'              => 'Directory Traversal & LFI Defense',
            'waf_block_php_injection'          => 'Remote Code Execution & PHP Injection Defense',
            'waf_block_fake_bots'              => 'Fake Search Engine Bots Defense',
            'waf_block_ai_scrapers'            => 'AI Scrapers & LLM Crawler Blocker',
            'waf_ai_allow_search_citations'     => 'Allow AI Search Engine Citations (Perplexity, OAI-Search, Claude)',
            'waf_ai_throttle_training_scrapers' => 'Rate-Limit Bulk AI Training Harvesters (GPTBot, CCBot, Bytespider)',
            'waf_ai_challenge_stealth_agents'   => 'Challenge Stealth Headless AI Agents (WebCrypto PoW)',
            'waf_block_404_scanners'           => 'Aggressive 404 Scanner Protection',
            'waf_block_empty_post_ua_referer'  => 'Empty User-Agent / Referer POST Protection',
            'waf_block_empty_user_agent'       => 'Empty / Missing User-Agent Shield',
            'waf_enable_progressive_warnings'  => 'Progressive Enforcement Warnings (Soft Block)',
            'waf_contact_support_url'          => 'Support / Contact Page URL',
            'waf_block_forbidden_usernames'    => 'Forbidden Default Admin Usernames Shield',
            'waf_block_malicious_uploads'      => 'Malicious File Upload Inspection',
            'waf_block_unsafe_http_methods'    => 'Unsafe HTTP Methods Filter',
            'waf_block_null_byte_attacks'      => 'Null Byte Poisoning Defense',
            'waf_block_sensitive_file_probes'  => 'Sensitive System File Probes Shield',
            'waf_block_uploads_php_exec'       => 'Uploads PHP Execution Blocker',
            'waf_block_external_cron'          => 'External WP-Cron Protection',
            'waf_block_open_redirects'         => 'Open Redirect Defense',
            'waf_block_ssrf_metadata'          => 'SSRF & Cloud Metadata Protection',
            'waf_block_install_php'            => 'Direct install.php / setup-config.php Blocker',
            'waf_block_rest_user_enum'         => 'REST API User Enumeration Shield',
            'waf_block_author_scan'            => 'Author Query String User Enumeration Shield',
            'waf_block_oversized_requests'     => 'Oversized Request Payload Guard',
            'waf_block_ai_prompt_injection'    => 'AI Prompt Injection Defense',
            'waf_woo_carding_protection'        => 'WooCommerce Carding Attack & Checkout Velocity Shield',
            'waf_woo_coupon_protection'         => 'WooCommerce Coupon Enumeration & Brute-Force Shield',
            'waf_woo_registration_protection'   => 'WooCommerce Fake Customer Registration & Bot Shield',
            'waf_woo_cart_flood_protection'     => 'WooCommerce Cart Flooding & Denial of Inventory Defense',
            'waf_woo_scraping_protection'       => 'WooCommerce Catalog & Price Scraping Mitigation',
            'waf_affiliate_shield_enabled'      => 'Affiliate Ecosystem Shield & Click-Fraud Armor (Rule #43)',
            'waf_affiliate_max_clicks_min'      => 'Affiliate Referral Max Clicks Per Minute',
            'waf_affiliate_anti_injection'      => 'Affiliate Referral Parameter Anti-Injection Armor',
            'waf_affiliate_reg_spam_protection' => 'Affiliate Registration Anti-Spam Shield',
            'waf_affiliate_direct_link_armor'   => 'Affiliate Direct Link Tracking Armor',
            'waf_guest_ajax_policy'            => 'Guest admin-ajax.php / admin-post.php Action Matrix',
            'waf_guest_ajax_custom_allowlist'  => 'Guest AJAX Custom Allowlist',
            'waf_guest_rest_policy'            => 'Guest REST API Mutation Guard',
            'waf_guest_rest_custom_allowlist'  => 'Guest REST Custom Allowlist',
            'waf_runtime_rasp_privilege_guard' => 'Runtime Privilege Escalation Guard (In-Memory RASP Hook Firewall)',
            'waf_upload_deep_mime_sanitizer'   => 'Deep MIME & Zip-Slip Polyglot Upload Armor',
            'waf_disable_xmlrpc'               => 'Disable XML-RPC API',
            'waf_enabled'                      => 'Web Application Firewall (WAF) Master Switch',
            'waf_mode'                         => 'Web Application Firewall (WAF) Mode',
            'waf_blocked_ips'                  => 'Custom Blocked IP List',
        ];

        if (isset($map[$key])) {
            return $map[$key];
        }

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            $mod_labels = \WebCareProScanner\Core\ModuleRegistry::get_setting_labels();
            if (isset($mod_labels[$key])) {
                return $mod_labels[$key];
            }
        }

        $clean = str_replace(['waf_block_', 'waf_', 'threat_intel_', 'webcareproscan_'], '', $key);
        $clean = str_replace('xmlrpc', 'XML-RPC', $clean);
        return ucwords(str_replace('_', ' ', $clean));
    }

    /**
     * Compute clean before/after diff of changed settings with redacted secrets.
     *
     * @param array $old_settings
     * @param array $new_settings
     * @return array
     */
    public static function compute_settings_diff(array $old_settings, array $new_settings): array {
        $diff = [];
        $keys = array_unique(array_merge(array_keys($old_settings), array_keys($new_settings)));

        $vaulted_keys = [
            'openai_api_key',
            'gemini_api_key',
            'claude_api_key',
            'deepseek_api_key',
            'openrouter_api_key',
            'slack_webhook_url',
            'discord_webhook_url',
            'clickup_webhook_url',
            'asana_webhook_url',
            'generic_webhook_url',
            'cloudflare_api_token',
            'cloudflare_zone_id',
            'waf_cloudflare_origin_secret',
        ];

        foreach ($keys as $k) {
            $old_val = $old_settings[$k] ?? null;
            $new_val = $new_settings[$k] ?? null;

            // Treat null and empty string as equivalent for optional fields
            if ($old_val === null && $new_val === '') {
                continue;
            }

            // For encrypted/vaulted fields, compare decrypted plaintext values to prevent false diffs from randomized AES-GCM IVs
            if (in_array($k, $vaulted_keys, true)) {
                $dec_old = is_string($old_val) ? \WebCareProScanner\Security\SecretVault::decrypt($old_val) : $old_val;
                $dec_new = is_string($new_val) ? \WebCareProScanner\Security\SecretVault::decrypt($new_val) : $new_val;
                if ($dec_old === $dec_new) {
                    continue;
                }
            }

            if ($old_val !== $new_val) {
                $diff[$k] = [
                    'new' => \WebCareProScanner\System\ActivityLogs\ActivityRedactor::redact($new_val),
                    'old' => \WebCareProScanner\System\ActivityLogs\ActivityRedactor::redact($old_val),
                ];
            }
        }

        return $diff;
    }

    /**
     * Set a single setting by key and save.
     *
     * @param string $key
     * @param mixed $value
     * @return array
     */
    public static function set(string $key, $value) {
        $settings = self::get_settings();
        $settings[$key] = $value;
        return self::save_settings($settings);
    }

    /**
     * Synchronize WordPress Cron for scheduled scanning
     */
    public static function sync_cron_schedule(array $settings) {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);

        if (empty($settings['schedule_enabled'])) {
            if ($timestamp) {
                wp_unschedule_event($timestamp, self::CRON_HOOK);
            }
            return;
        }

        $frequency = $settings['schedule_frequency'] ?? 'daily';
        
        // If not scheduled or scheduled with different frequency, recreate schedule
        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }

        $now_utc = time();
        $time_str = !empty($settings['schedule_time']) ? $settings['schedule_time'] : '02:00';
        $parts = explode(':', $time_str);
        $target_hour = isset($parts[0]) ? (int) $parts[0] : 2;
        $target_minute = isset($parts[1]) ? (int) $parts[1] : 0;

        // Use WordPress site timezone for clean datetime arithmetic
        $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone(get_option('timezone_string') ?: 'UTC');
        $site_now = new \DateTimeImmutable('now', $tz);

        if ($frequency === 'hourly') {
            // Anchor to the specific minute of each hour (e.g. 11:59 -> :59 past the hour)
            $cand = $site_now->setTime((int) $site_now->format('H'), $target_minute, 0);
            if ($cand->getTimestamp() <= $now_utc) {
                $cand = $cand->modify('+1 hour');
            }
            $target_utc = $cand->getTimestamp();

            // Safety guard: guarantee target is in the future
            while ($target_utc <= $now_utc) {
                $target_utc += HOUR_IN_SECONDS;
            }
        } elseif ($frequency === 'twicedaily') {
            // Twice daily (every 12 hours) anchored to schedule_time
            $cand = $site_now->setTime($target_hour, $target_minute, 0);
            $anchor_utc = $cand->getTimestamp();

            // Find nearest upcoming occurrence (every 12 hours from anchor)
            $target_utc = $anchor_utc;
            while ($target_utc <= $now_utc) {
                $target_utc += (12 * HOUR_IN_SECONDS);
            }
            while (($target_utc - (12 * HOUR_IN_SECONDS)) > $now_utc) {
                $target_utc -= (12 * HOUR_IN_SECONDS);
            }
        } else {
            // Daily or Weekly at the configured schedule_time in site timezone
            $cand = $site_now->setTime($target_hour, $target_minute, 0);
            $target_utc = $cand->getTimestamp();

            if ($target_utc <= $now_utc) {
                $target_utc += DAY_IN_SECONDS;
            }
        }

        wp_schedule_event($target_utc, $frequency, self::CRON_HOOK);
    }

    /**
     * Export all settings as JSON payload
     */
    public static function export_settings(): array {
        $settings = get_option(self::OPTION_KEY, self::get_defaults());
        $safe_settings = self::strip_secrets(is_array($settings) ? $settings : []);
        return [
            'app'         => 'WebCare Pro Security & Firewall',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '1.3.0',
            'exported_at' => current_time('mysql'),
            'site_url'    => get_site_url(),
            'settings'    => $safe_settings,
        ];
    }

    /**
     * Import settings from JSON payload
     *
     * @return array<string, mixed>
     */
    public static function import_settings(array $payload): array {
        if (empty($payload['settings']) || !is_array($payload['settings'])) {
            throw new \Exception(esc_html__('Invalid settings backup file format.', 'webcare-pro-security'));
        }

        $saved = self::save_settings($payload['settings']);
        if ($saved === false || !is_array($saved)) {
            throw new \RuntimeException(esc_html__('Unable to apply imported settings due to concurrent lock contention or storage failure.', 'webcare-pro-security'));
        }
        return $saved;
    }

    /**
     * Reset settings to factory defaults inside a database-fenced InnoDB transaction under OPTION_MUTATION_LOCK.
     *
     * @return array<string, mixed>|false
     */
    public static function reset_defaults(): array|false {
        $lock_token = self::acquire_mutation_lock();
        if ($lock_token === null) {
            return false;
        }

        try {
            $baseline_revision = self::read_raw_revision();
            $current = get_option(self::OPTION_KEY, []);
            $current = is_array($current) ? $current : [];
            $defaults = self::get_defaults();
            $safe_snapshot_settings = !empty($current) ? self::strip_secrets($current) : [];

            if (!self::renew_mutation_lock($lock_token)) {
                return false;
            }

            if (is_callable(self::$after_renewal_before_write_hook)) {
                (self::$after_renewal_before_write_hook)($lock_token);
            }

            $next_revision = $baseline_revision + 1;
            $default_retention_days = (int) ($defaults['waf_log_retention_days'] ?? 60);
            $default_act_settings = [
                'retention_days'     => 7,
                'tamper_webhook_url' => '',
            ];
            $touched = [
                self::OPTION_KEY,
                \WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION,
                'webcareproscan_activity_log_settings',
                self::OPTION_REVISION_KEY,
            ];
            if (!empty($safe_snapshot_settings)) {
                $touched[] = self::OPTION_SNAPSHOTS_KEY;
            }

            $committed = self::execute_fenced_transaction(
                $lock_token,
                $baseline_revision,
                static function () use ($defaults, $default_retention_days, $default_act_settings, $next_revision, $safe_snapshot_settings): bool {
                    if (!self::transactional_upsert_option(self::OPTION_KEY, $defaults, 'no')) {
                        return false;
                    }
                    if (!self::transactional_upsert_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION, $default_retention_days, 'no')) {
                        return false;
                    }
                    if (!self::transactional_upsert_option('webcareproscan_activity_log_settings', $default_act_settings, 'no')) {
                        return false;
                    }
                    if (!self::transactional_upsert_option(self::OPTION_REVISION_KEY, $next_revision, 'no')) {
                        return false;
                    }
                    if (!empty($safe_snapshot_settings)) {
                        $snapshots = self::transactional_read_option_for_update(self::OPTION_SNAPSHOTS_KEY, []);
                        if (!is_array($snapshots)) {
                            $snapshots = [];
                        }
                        array_unshift($snapshots, [
                            'id'        => 'snap_' . bin2hex(random_bytes(8)),
                            'revision'  => $next_revision,
                            'timestamp' => time(),
                            'user'      => function_exists('wp_get_current_user') ? (wp_get_current_user()->user_login ?? 'system') : 'system',
                            'settings'  => $safe_snapshot_settings,
                        ]);
                        if (count($snapshots) > self::MAX_SNAPSHOTS) {
                            $snapshots = array_slice($snapshots, 0, self::MAX_SNAPSHOTS);
                        }
                        if (!self::transactional_upsert_option(self::OPTION_SNAPSHOTS_KEY, $snapshots, 'no')) {
                            return false;
                        }
                    }
                    return true;
                },
                $touched
            );

            if (!$committed) {
                return false;
            }

            self::sync_cron_schedule($defaults);
            if (class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter') && !\WebCareProScanner\System\Cron\CronControlCenter::$syncing_from_cron_center) {
                \WebCareProScanner\System\Cron\CronControlCenter::sync_all_from_settings($defaults);
            }
            return self::get_settings();
        } finally {
            self::release_mutation_lock($lock_token);
        }
    }

    /**
     * Recursively strip all secret and credential keys from a settings array or serialized JSON string.
     * Guarantees zero raw secrets persist at any nesting depth.
     *
     * @param array $settings
     * @return array
     */
    public static function strip_secrets(array $settings): array {
        return self::recursively_strip_secrets($settings);
    }

    /**
     * Helper for recursive secret stripping.
     *
     * @param array $data
     * @return array
     */
    private static function recursively_strip_secrets(array $data): array {
        $secret_regex = '/(?:secret|token|password|api_key|private_key|passphrase)/i';
        $safe_meta_regex = '/(?:_ref|_enabled|_mode|_window|_ttl|_created_at|_roles|_strength)$/i';

        $clean = [];
        foreach ($data as $key => $val) {
            $key_str = (string) $key;

            // Direct match against top-level SECRET_KEYS
            if (in_array($key_str, self::SECRET_KEYS, true)) {
                continue;
            }

            // Preserve non-secret boolean/policy configuration keys
            if (!in_array($key_str, self::NON_SECRET_POLICY_KEYS, true) && !is_bool($val)) {
                // Heuristic match for credential names, excluding safe metadata keys
                if (preg_match($secret_regex, $key_str) === 1 && preg_match($safe_meta_regex, $key_str) === 0) {
                    continue;
                }
            }

            if (is_array($val)) {
                $clean[$key] = self::recursively_strip_secrets($val);
            } elseif (is_string($val) && json_validate($val)) {
                // Native PHP 8.3 json_validate
                $decoded = json_decode($val, true);
                if (is_array($decoded)) {
                    $stripped_decoded = self::recursively_strip_secrets($decoded);
                    $clean[$key] = wp_json_encode($stripped_decoded);
                } else {
                    $clean[$key] = $val;
                }
            } else {
                $clean[$key] = $val;
            }
        }

        return $clean;
    }

    /**
     * Record a snapshot of the current settings (excluding secrets) for Undo capability.
     * Acquires the shared settings mutation lock when called standalone.
     * Capped at MAX_SNAPSHOTS (10).
     *
     * @param array $settings
     * @param int   $revision
     */
    public static function record_settings_snapshot(array $settings, int $revision = 0): void {
        $lock_token = self::acquire_mutation_lock();
        if ($lock_token === null) {
            return;
        }

        try {
            self::record_settings_snapshot_locked($settings, $revision, $lock_token);
        } finally {
            self::release_mutation_lock($lock_token);
        }
    }

    /**
     * Database-fenced internal implementation of record_settings_snapshot().
     * Executes inside execute_fenced_transaction() holding SELECT ... FOR UPDATE on OPTION_MUTATION_LOCK.
     */
    private static function record_settings_snapshot_locked(array $settings, int $revision, string $lock_token): bool {
        $safe_settings = self::strip_secrets($settings);
        if (empty($safe_settings)) {
            return true;
        }

        return self::execute_fenced_transaction(
            $lock_token,
            null,
            static function () use ($safe_settings, $revision): bool {
                $snapshots = self::transactional_read_option_for_update(self::OPTION_SNAPSHOTS_KEY, []);
                if (!is_array($snapshots)) {
                    $snapshots = [];
                }

                $eff_rev = $revision > 0 ? $revision : max(0, (int) self::transactional_read_option_for_update(self::OPTION_REVISION_KEY, 0));
                array_unshift($snapshots, [
                    'id'        => 'snap_' . bin2hex(random_bytes(8)),
                    'revision'  => $eff_rev,
                    'timestamp' => time(),
                    'user'      => function_exists('wp_get_current_user') ? (wp_get_current_user()->user_login ?? 'system') : 'system',
                    'settings'  => $safe_settings,
                ]);

                if (count($snapshots) > self::MAX_SNAPSHOTS) {
                    $snapshots = array_slice($snapshots, 0, self::MAX_SNAPSHOTS);
                }

                return self::transactional_upsert_option(self::OPTION_SNAPSHOTS_KEY, $snapshots, 'no');
            },
            [self::OPTION_SNAPSHOTS_KEY]
        );
    }

    /**
     * Compute a deterministic fingerprint of a snapshot entry for compare-and-swap head verification.
     *
     * @param array<string, mixed> $snapshot
     */
    private static function compute_snapshot_fingerprint(array $snapshot): string {
        $id = (string) ($snapshot['id'] ?? '');
        $rev = (int) ($snapshot['revision'] ?? 0);
        $ts = (int) ($snapshot['timestamp'] ?? 0);
        $settings = is_array($snapshot['settings'] ?? null) ? self::canonicalize_for_fingerprint($snapshot['settings']) : [];
        return hash('sha256', $id . '|' . $rev . '|' . $ts . '|' . wp_json_encode($settings));
    }

    /**
     * Normalize associative key ordering recursively for deterministic snapshot fingerprinting.
     *
     * @param array<mixed> $data
     * @return array<mixed>
     */
    private static function canonicalize_for_fingerprint(array $data): array {
        if (!array_is_list($data)) {
            ksort($data);
        }
        foreach ($data as $k => $v) {
            if (is_array($v)) {
                $data[$k] = self::canonicalize_for_fingerprint($v);
            }
        }
        return $data;
    }

    /**
     * Retrieve the list of recorded settings snapshots (without secrets).
     *
     * @return array
     */
    public static function get_settings_snapshots(): array {
        $snapshots = get_option(self::OPTION_SNAPSHOTS_KEY, []);
        return is_array($snapshots) ? $snapshots : [];
    }

    /**
     * Recursively compare two arrays for canonical equality, normalizing key order on associative arrays.
     *
     * @param array<mixed> $a
     * @param array<mixed> $b
     * @return bool
     */
    public static function arrays_canonical_equal(array $a, array $b): bool {
        if (count($a) !== count($b)) {
            return false;
        }

        $a_is_list = array_is_list($a);
        $b_is_list = array_is_list($b);
        if ($a_is_list !== $b_is_list) {
            return false;
        }

        if (!$a_is_list) {
            ksort($a);
            ksort($b);
            if (array_keys($a) !== array_keys($b)) {
                return false;
            }
        }

        foreach ($a as $k => $va) {
            if (!array_key_exists($k, $b)) {
                return false;
            }
            if (!self::values_canonical_equal($va, $b[$k])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Compare scalar, nested array, or JSON-encoded array values canonically.
     */
    private static function values_canonical_equal(mixed $va, mixed $vb): bool {
        if (is_array($va) || is_array($vb)) {
            if (!is_array($va) || !is_array($vb)) {
                return false;
            }
            return self::arrays_canonical_equal($va, $vb);
        }

        if (is_string($va) && is_string($vb) && $va !== '' && $vb !== '' && json_validate($va) && json_validate($vb)) {
            $da = json_decode($va, true);
            $db = json_decode($vb, true);
            if (is_array($da) && is_array($db)) {
                return self::arrays_canonical_equal($da, $db);
            }
        }

        if (is_bool($va) || is_bool($vb)) {
            return is_bool($va) && is_bool($vb) && $va === $vb;
        }

        if ((is_int($va) || is_float($va)) && (is_int($vb) || is_float($vb))) {
            if (is_int($va) && is_int($vb)) {
                return $va === $vb;
            }
            return abs((float) $va - (float) $vb) < 1e-9;
        }

        return $va === $vb;
    }

    /**
     * Undo the last settings change by popping the most recent snapshot and applying it.
     * Preserves all active secrets currently in the database so credentials are never lost.
     *
     * @return array<string, mixed>
     */
    public static function undo_last_settings(): array {
        $lock_token = self::acquire_mutation_lock();
        if ($lock_token === null) {
            return [
                'success'             => false,
                'code'                => 'lock_contention',
                'message'             => __('Another settings update is currently in progress. Please try again.', 'webcare-pro-security'),
                'settings'            => self::get_settings(),
                'snapshots_remaining' => count(self::get_settings_snapshots()),
            ];
        }

        try {
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete(self::OPTION_SNAPSHOTS_KEY, 'options');
                wp_cache_delete(self::OPTION_REVISION_KEY, 'options');
            }

            $snapshots = self::get_settings_snapshots();
            if (empty($snapshots)) {
                return [
                    'success'             => false,
                    'message'             => __('No previous settings snapshot available to undo.', 'webcare-pro-security'),
                    'settings'            => self::get_settings(),
                    'snapshots_remaining' => 0,
                ];
            }

            // Peek at the most recent snapshot without popping it yet (two-phase verified + fenced undo)
            $initial_snapshot_count = count($snapshots);
            $target_snapshot = is_array($snapshots[0]) ? $snapshots[0] : [];
            $expected_head_fp = self::compute_snapshot_fingerprint($target_snapshot);
            $restored_subset = $target_snapshot['settings'] ?? [];
            if (!is_array($restored_subset) || empty($restored_subset)) {
                // Discard corrupted top snapshot inside a database-fenced transaction verifying the head is unchanged
                $remaining_corrupted = $snapshots;
                $discarded = self::execute_fenced_transaction(
                    $lock_token,
                    null,
                    static function () use ($expected_head_fp, &$remaining_corrupted): bool {
                        $tx_snaps = self::transactional_read_option_for_update(self::OPTION_SNAPSHOTS_KEY, []);
                        if (!is_array($tx_snaps) || empty($tx_snaps) || !is_array($tx_snaps[0])) {
                            return false;
                        }
                        if (self::compute_snapshot_fingerprint($tx_snaps[0]) !== $expected_head_fp) {
                            return false;
                        }
                        array_shift($tx_snaps);
                        $remaining_corrupted = $tx_snaps;
                        return self::transactional_upsert_option(self::OPTION_SNAPSHOTS_KEY, $tx_snaps, 'no');
                    },
                    [self::OPTION_SNAPSHOTS_KEY]
                );

                if (!$discarded) {
                    return [
                        'success'             => false,
                        'code'                => 'lock_lost',
                        'message'             => __('Settings mutation lock expired or snapshot stack changed before corrupted snapshot could be removed.', 'webcare-pro-security'),
                        'settings'            => self::get_settings(),
                        'snapshots_remaining' => count(self::get_settings_snapshots()),
                    ];
                }

                return [
                    'success'             => false,
                    'message'             => __('Corrupted settings snapshot encountered.', 'webcare-pro-security'),
                    'settings'            => self::get_settings(),
                    'snapshots_remaining' => count($remaining_corrupted),
                ];
            }

            // Preserve current active secrets
            $current = get_option(self::OPTION_KEY, []);
            if (!is_array($current)) {
                $current = [];
            }

            $active_secrets = [];
            foreach (self::SECRET_KEYS as $secret_key) {
                if (isset($current[$secret_key])) {
                    $active_secrets[$secret_key] = $current[$secret_key];
                }
            }

            // Merge restored non-secret settings with active secrets
            $merged_restoration = array_merge($restored_subset, $active_secrets);

            // Phase 1: Apply restoration directly via private lock-aware save_settings_locked() without mutating snapshot history yet
            $expected_clean = null;
            $saved = self::save_settings_locked($merged_restoration, $lock_token, false, $expected_clean);
            if ($saved === false || (function_exists('is_wp_error') && is_wp_error($saved)) || !is_array($saved) || !is_array($expected_clean)) {
                return [
                    'success'             => false,
                    'message'             => __('Settings undo failed: unable to persist restored settings.', 'webcare-pro-security'),
                    'settings'            => self::get_settings(),
                    'snapshots_remaining' => count($snapshots),
                ];
            }

            $expected_undo_revision = self::get_settings_revision();

            // Phase 2: Clear options cache and read back persisted state via get_option() and get_settings()
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete(self::OPTION_KEY, 'options');
            }

            $raw_persisted = get_option(self::OPTION_KEY, []);
            $read_back = self::get_settings();
            if (!is_array($raw_persisted) || empty($raw_persisted) || !is_array($read_back) || empty($read_back)) {
                return [
                    'success'             => false,
                    'message'             => __('Settings undo verification failed: unable to read back restored state.', 'webcare-pro-security'),
                    'settings'            => is_array($read_back) ? $read_back : [],
                    'snapshots_remaining' => count($snapshots),
                ];
            }

            // Verify EVERY non-secret key in the expected sanitized restored payload (including nested arrays & missing keys)
            // and confirm live secrets remain intact in raw storage.
            $verification_failed = false;
            foreach ($expected_clean as $ek => $ev) {
                if (in_array($ek, self::SECRET_KEYS, true)) {
                    $expected_secret = $active_secrets[$ek] ?? $ev;
                    if (!array_key_exists($ek, $raw_persisted) || $raw_persisted[$ek] !== $expected_secret) {
                        $verification_failed = true;
                        break;
                    }
                    continue;
                }

                if (!array_key_exists($ek, $raw_persisted) || !array_key_exists($ek, $read_back)) {
                    $verification_failed = true;
                    break;
                }

                if (!self::values_canonical_equal($ev, $raw_persisted[$ek]) || !self::values_canonical_equal($ev, $read_back[$ek])) {
                    $verification_failed = true;
                    break;
                }
            }

            // Also ensure no non-secret key present in the snapshot's restored_subset is missing or mismatched
            if (!$verification_failed) {
                foreach ($restored_subset as $rk => $rv) {
                    $rk_str = (string) $rk;
                    if (in_array($rk_str, self::SECRET_KEYS, true) || str_starts_with($rk_str, 'has_') || $rk_str === 'activity_log_settings') {
                        continue;
                    }
                    if (!array_key_exists($rk_str, $raw_persisted) || !array_key_exists($rk_str, $read_back)) {
                        $verification_failed = true;
                        break;
                    }
                    if (!array_key_exists($rk_str, $expected_clean)) {
                        if (!self::values_canonical_equal($rv, $raw_persisted[$rk_str]) || !self::values_canonical_equal($rv, $read_back[$rk_str])) {
                            $verification_failed = true;
                            break;
                        }
                    }
                }
            }

            if ($verification_failed) {
                return [
                    'success'             => false,
                    'message'             => __('Settings undo verification failed: restored settings mismatch.', 'webcare-pro-security'),
                    'settings'            => $read_back,
                    'snapshots_remaining' => count($snapshots),
                ];
            }

            // Optional test hook to simulate concurrent interleaving right before popping snapshot history
            if (is_callable(self::$interleave_before_undo_pop_hook)) {
                (self::$interleave_before_undo_pop_hook)();
            }

            // Phase 3: Database-Fenced Transactional Snapshot Pop
            // Locks OPTION_MUTATION_LOCK, OPTION_REVISION_KEY, and OPTION_SNAPSHOTS_KEY with SELECT ... FOR UPDATE
            // and writes the popped snapshot stack inside the same transaction so post-renewal expiry cannot slip through.
            $pop_failure_reason = null;
            $remaining_snapshots = [];
            $popped_ok = self::execute_fenced_transaction(
                $lock_token,
                $expected_undo_revision,
                static function () use ($initial_snapshot_count, $expected_head_fp, &$remaining_snapshots, &$pop_failure_reason): bool {
                    $tx_snapshots = self::transactional_read_option_for_update(self::OPTION_SNAPSHOTS_KEY, []);
                    $tx_snapshots = is_array($tx_snapshots) ? $tx_snapshots : [];
                    $tx_head_intact = !empty($tx_snapshots)
                        && count($tx_snapshots) === $initial_snapshot_count
                        && is_array($tx_snapshots[0])
                        && self::compute_snapshot_fingerprint($tx_snapshots[0]) === $expected_head_fp;

                    if (!$tx_head_intact) {
                        $pop_failure_reason = 'concurrent_modification';
                        return false;
                    }

                    $next_stack = $tx_snapshots;
                    array_shift($next_stack);
                    if (!self::transactional_upsert_option(self::OPTION_SNAPSHOTS_KEY, $next_stack, 'no')) {
                        $pop_failure_reason = 'persist_failed';
                        return false;
                    }

                    $remaining_snapshots = $next_stack;
                    return true;
                },
                [self::OPTION_SNAPSHOTS_KEY]
            );

            if (!$popped_ok) {
                $live_snapshots = self::get_settings_snapshots();
                if ($pop_failure_reason === 'persist_failed') {
                    $warn_msg = __('Settings restored, but snapshot history could not be updated.', 'webcare-pro-security');
                    return [
                        'success'             => false,
                        'warning'             => $warn_msg,
                        'message'             => $warn_msg,
                        'settings'            => $read_back,
                        'snapshots_remaining' => count($live_snapshots),
                    ];
                }

                $live_revision = self::read_raw_revision();
                $head_still_same = !empty($live_snapshots)
                    && count($live_snapshots) === $initial_snapshot_count
                    && is_array($live_snapshots[0])
                    && self::compute_snapshot_fingerprint($live_snapshots[0]) === $expected_head_fp;

                $failure_code = ($pop_failure_reason === 'concurrent_modification' || $live_revision !== $expected_undo_revision || !$head_still_same)
                    ? 'concurrent_modification'
                    : 'lock_lost';

                return [
                    'success'             => false,
                    'code'                => $failure_code,
                    'message'             => __('Concurrent settings modification or lock expiration detected during undo; snapshot history was preserved.', 'webcare-pro-security'),
                    'settings'            => self::get_settings(),
                    'snapshots_remaining' => count($live_snapshots),
                ];
            }

            if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                $formatted_time = function_exists('date_i18n')
                    ? date_i18n('Y-m-d H:i:s', $target_snapshot['timestamp'] ?? time())
                    : gmdate('Y-m-d H:i:s', $target_snapshot['timestamp'] ?? time());
                \WebCareProScanner\System\WebCareActivityLogger::notice(
                    'settings_undo_applied',
                    'settings',
                    [
                        'description'         => sprintf('Reverted settings to snapshot from %s.', $formatted_time),
                        'snapshot_time'       => $target_snapshot['timestamp'] ?? time(),
                        'snapshots_remaining' => count($remaining_snapshots),
                    ]
                );
            }

            return [
                'success'             => true,
                'message'             => __('Settings successfully reverted to the previous snapshot.', 'webcare-pro-security'),
                'settings'            => $read_back,
                'snapshots_remaining' => count($remaining_snapshots),
            ];
        } finally {
            self::release_mutation_lock($lock_token);
        }
    }

    /**
     * Test if a database table matches user-configured excluded tables.
     *
     * @param string $table_name
     * @return bool
     */
    public static function is_table_excluded(string $table_name): bool {
        $raw = self::get('scan_excluded_tables');
        if (empty($raw)) {
            return false;
        }

        $lines = explode("\n", $raw);
        $clean_table = strtolower(trim($table_name));

        foreach ($lines as $line) {
            $pattern = strtolower(trim($line));
            if (empty($pattern) || strpos($pattern, '#') === 0) {
                continue;
            }
            if ($pattern === $clean_table || fnmatch($pattern, $clean_table) || fnmatch("*{$pattern}*", $clean_table)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Test if a file path matches user-configured excluded paths/patterns.
     *
     * @param string $file_path
     * @return bool
     */
    public static function is_path_excluded(string $file_path): bool {
        $raw = self::get('excluded_paths');
        if (empty($raw)) {
            return false;
        }

        $normalized = str_replace('\\', '/', $file_path);
        $filename   = basename($normalized);
        $lines      = explode("\n", $raw);

        foreach ($lines as $line) {
            $pattern = trim($line);
            if (empty($pattern) || strpos($pattern, '#') === 0) {
                continue;
            }
            $pattern = str_replace('\\', '/', $pattern);

            // 1. Filename / extension wildcard pattern (e.g. *.log, *.zip, *.tar.gz, *.bak)
            if (!str_contains($pattern, '/')) {
                if (fnmatch($pattern, $filename, FNM_CASEFOLD)) {
                    return true;
                }
                continue;
            }

            // 2. Directory or path pattern (e.g. vendor/*, wp-content/cache/*, node_modules/*, .git/*)
            $clean_pattern = trim($pattern, '/*');
            if ($clean_pattern === '') {
                continue;
            }

            // Directory boundary matching against absolute or relative path
            // Matches (start-of-path or '/') + clean_pattern + ('/' or end-of-path)
            if (preg_match('#(?:^|/)' . preg_quote($clean_pattern, '#') . '(?:/|$)#i', $normalized)) {
                return true;
            }

            // Also check if pattern has internal wildcards (e.g. wp-content/uploads/*/backup)
            if (str_contains($clean_pattern, '*')) {
                $regex_pattern = '#(?:^|/)' . str_replace('\*', '[^/]*', preg_quote($clean_pattern, '#')) . '(?:/|$)#i';
                if (preg_match($regex_pattern, $normalized)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Test if an index.php or index.html file is a harmless directory listing prevention placeholder.
     *
     * Handles:
     * 1. 0-byte or whitespace-only index files.
     * 2. Purely comment / docblock placeholders (e.g. WP Staging, Elementor, Wordfence directory protection notices).
     * 3. Standard WordPress "Silence is golden." placeholders.
     * 4. Harmless exit, die, 403 Forbidden header, or defined('ABSPATH') guard scripts.
     * 5. Static HTML directory disabled notices without embedded scripts.
     *
     * @param string $file_path
     * @return bool
     */
    public static function is_safe_directory_index(string $file_path): bool {
        if (!file_exists($file_path)) {
            return false;
        }

        $file_size = @filesize($file_path);
        // Harmless silence/protection files are compact (up to 8KB to accommodate multi-paragraph developer docblocks)
        if ($file_size === false || $file_size > 8192) {
            return false;
        }

        // 0-byte file is completely safe
        if ($file_size === 0) {
            return true;
        }

        $content = @file_get_contents($file_path, false, null, 0, 8192);
        if ($content === false) {
            return false;
        }

        $trimmed = trim($content);
        if ($trimmed === '' || $trimmed === '<?php' || $trimmed === '<?php ?>' || $trimmed === '<?php ?>\n') {
            return true;
        }

        // Normalize benign WPForms / plugin directory protection headers reading $_SERVER['SERVER_PROTOCOL'] solely for 403/404 status lines
        $normalized_content = preg_replace(
            '/\bheader\s*\(\s*\$_SERVER\s*\[\s*[\'"]SERVER_PROTOCOL[\'"]\s*\]\s*\.\s*[\'"]\s*(?:403\s+Forbidden|404\s+Not\s+Found)[\'"]\s*\)\s*;/i',
            "header('Status: 404 Not Found');",
            $content
        ) ?? $content;

        // Must NOT contain any dangerous execution functions, webshell signatures, superglobals, or backdoors
        $dangerous_pattern = '/(eval\s*\(|base64_decode\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|gzinflate\s*\(|gzuncompress\s*\(|create_function\s*\(|file_put_contents\s*\(|curl_exec\s*\(|include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\(|\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|\$_SERVER|\$GLOBALS)/i';
        if (preg_match($dangerous_pattern, $normalized_content)) {
            return false;
        }

        // Static HTML index files without script tags
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if (in_array($ext, ['html', 'htm'], true)) {
            if (stripos($normalized_content, '<?') === false && stripos($normalized_content, '<script') === false) {
                return true;
            }
            return false;
        }

        // Tokenize PHP to inspect actual AST tokens
        $tokens = @token_get_all($normalized_content);
        if (!is_array($tokens)) {
            return false;
        }

        $allowed_token_ids = [
            T_OPEN_TAG,
            T_CLOSE_TAG,
            T_WHITESPACE,
            T_COMMENT,
            T_DOC_COMMENT,
            T_INLINE_HTML,
            T_IF,
            T_ELSE,
            T_ELSEIF,
            T_RETURN,
            T_EXIT,
            T_STRING,
            T_NS_SEPARATOR,
            T_CONSTANT_ENCAPSED_STRING,
            T_LNUMBER,
            T_BOOLEAN_OR,
            T_BOOLEAN_AND,
            T_LOGICAL_OR,
            T_LOGICAL_AND,
            T_IS_IDENTICAL,
            T_IS_NOT_IDENTICAL,
            T_IS_EQUAL,
            T_IS_NOT_EQUAL,
        ];

        $allowed_chars = ['(', ')', ';', ',', '!', ':', '{', '}', '@'];
        $allowed_function_names = ['header', 'header_remove', 'http_response_code', 'status_header', 'defined', 'exit', 'die'];

        foreach ($tokens as $token) {
            if (is_array($token)) {
                $id = $token[0];
                $text = trim($token[1]);

                // Harmless structural, comment, and docblock tokens (WP Staging, Silence is Golden, etc.)
                if (in_array($id, [T_OPEN_TAG, T_CLOSE_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                // Inline HTML check
                if ($id === T_INLINE_HTML) {
                    if (stripos($text, '<?') !== false || stripos($text, '<script') !== false) {
                        return false;
                    }
                    continue;
                }

                if (!in_array($id, $allowed_token_ids, true)) {
                    return false;
                }

                // If identifier/string, verify it is only harmless exit/header/defined statements
                if ($id === T_STRING) {
                    $lower = strtolower($text);
                    if (!in_array($lower, $allowed_function_names, true) && !in_array($lower, ['true', 'false', 'null'], true) && !in_array($text, ['ABSPATH', 'WPINC'], true)) {
                        return false;
                    }
                }
            } else {
                if (!in_array($token, $allowed_chars, true)) {
                    return false;
                }
            }
        }

        // If file contains only comments, docblocks, whitespace, or safe guards, it is completely benign
        return true;
    }

    /**
     * Checks if a PHP file in the uploads directory is a benign, compiled cache file generated
     * by recognized legitimate WordPress plugins (such as MailPoet Twig template cache or W3TC cache),
     * while rigorously verifying it contains zero malware, webshells, or backdoor signatures.
     *
     * @param string $file_path
     * @return bool True if benign plugin cache file with zero malware indicators.
     */
    /**
     * Checks if an .htaccess file is a clean, benign protective access-control configuration
     * (e.g. SSL Let's Encrypt challenge isolation, ACME challenge, plugin uploads lockdown,
     * or standard 'Require all denied' / 'Deny from all' protection), free of malicious PHP handlers,
     * search engine cloaking redirects, or webshell execution overrides.
     *
     * @param string $file_path Absolute path to the .htaccess file.
     * @return bool True if benign protective .htaccess file.
     */
    public static function is_safe_protective_htaccess(string $file_path): bool {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        $size = @filesize($file_path);
        // Protective or challenge .htaccess files are rarely larger than 16KB
        if ($size === false || $size > 16384) {
            return false;
        }

        $content = @file_get_contents($file_path);
        if ($content === false) {
            return false;
        }

        // 1. Strict Malicious Directive Scan:
        // Must NOT contain PHP handler injections, auto_prepend / auto_append, engine enabling,
        // or search engine user-agent cloaking redirects.
        $malicious_directives = [
            '/(?:AddType|AddHandler|SetHandler)\s+application\/x-httpd-php/i',
            '/php_value\s+(?:auto_prepend_file|auto_append_file)/i',
            '/php_flag\s+engine\s+(?:on|1)/i',
            '/RewriteCond\s+%{HTTP_USER_AGENT}\s+.*(?:googlebot|bingbot|yahoo|baidu|slurp)/i',
            '/RewriteRule\s+.*https?:\/\//i',
            '/<FilesMatch\s+[^>]*\.(?:jpg|png|gif|ico|webp|svg|pdf)[^>]*>\s*SetHandler/i',
        ];

        foreach ($malicious_directives as $pattern) {
            if (preg_match($pattern, $content)) {
                return false; // Malicious rewrite/handler detected!
            }
        }

        $norm = str_replace('\\', '/', $file_path);

        // 2. SSL Let's Encrypt / ACME Challenge Verification:
        // /.well-known/acme-challenge/.htaccess commonly contains standard mod_auth / mod_rewrite directives
        if (strpos($norm, '/.well-known/acme-challenge/') !== false || strpos($norm, '/.well-known/pki-validation/') !== false) {
            return true;
        }

        // 3. Standard Protective Lockdown Directives
        // If it exclusively enforces access restrictions, directory browsing prevention, or script execution blocks
        $is_protective = (
            stripos($content, 'deny from all') !== false ||
            stripos($content, 'require all denied') !== false ||
            stripos($content, 'php_flag engine off') !== false ||
            stripos($content, 'Options -Indexes') !== false ||
            stripos($content, 'Options -ExecCGI') !== false ||
            stripos($content, 'RemoveHandler') !== false ||
            stripos($content, 'SetHandler default-handler') !== false ||
            stripos($content, 'ForceType text/plain') !== false ||
            trim($content) === ''
        );

        return $is_protective;
    }

    public static function is_legitimate_uploads_cache_file(string $file_path): bool {
        if (!file_exists($file_path)) {
            return false;
        }

        $norm = str_replace('\\', '/', $file_path);

        // 1. Must match a known legitimate plugin cache directory pattern within wp-content/uploads/
        $is_recognized_cache_dir = (
            preg_match('#/wp-content/uploads/mailpoet/cache/[a-f0-9]{2}/[a-f0-9]{64}\.php$#i', $norm) ||
            preg_match('#/wp-content/uploads/wpallimport/functions\.php$#i', $norm) ||
            preg_match('#/wp-content/uploads/w3tc-cache/#i', $norm) ||
            preg_match('#/wp-content/uploads/wp-optimize-cache/#i', $norm) ||
            preg_match('#/wp-content/uploads/elementor/css/#i', $norm)
        );

        if (!$is_recognized_cache_dir) {
            return false;
        }

        $size = @filesize($file_path);
        // An empty 0-byte file cannot execute malware
        if ($size === 0) {
            return true;
        }

        // Twig template caches can be 10KB - 500KB, but shouldn't exceed 2MB
        if ($size === false || $size > 2 * 1024 * 1024) {
            return false;
        }

        $content = @file_get_contents($file_path);
        if ($content === false) {
            return false;
        }

        if (strlen(trim($content)) < 15) {
            // Harmless stub or empty opening tag
            return (bool) preg_match('/^<\?php(?:\s*\/\/[^\r\n]*)?\s*$/i', trim($content));
        }

        // 2. Strict Zero-Tolerance Malware / Webshell Signature Scan
        // If it contains ANY dangerous webshell/backdoor patterns, it MUST NOT be ignored!
        $backdoor_patterns = [
            '/\b(eval|assert|passthru|shell_exec|exec|system|proc_open|popen|pcntl_exec)\s*\(/i',
            '/\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*["\']?[a-zA-Z0-9+\/]{40,}/i',
            '/\b(file_put_contents|fwrite|fputs)\s*\(\s*["\']?[^,\)]+\.(php|phtml|phar)/i',
            '/\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/i', // Dynamic execution: $_POST['x'](...)
            '/\$\w+\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',       // Dynamic variable execution: $cmd($_POST['a'])
            '/preg_replace\s*\(\s*["\']\/[^\/]*\/e["\']/i',      // preg_replace /e modifier code execution
            '/\b(c99shell|r57shell|b374k|wso_version|alfa_team|indosec|loggershell)\b/i',
            '/\b(chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}/i',           // Obfuscated string concatenation chains
        ];

        foreach ($backdoor_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return false; // Real malware detected! Do NOT ignore!
            }
        }

        // 3. For MailPoet Twig template cache: verify authentic MailPoet Twig template footprint
        if (strpos($norm, '/mailpoet/cache/') !== false) {
            $is_twig = (
                strpos($content, 'MailPoetVendor\Twig') !== false ||
                strpos($content, '__TwigTemplate_') !== false ||
                strpos($content, 'extends \MailPoetVendor\Twig\Template') !== false
            );
            return $is_twig;
        }

        return true;
    }
}
