<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare IP List Synchronizer (CAF Phase 2)
 *
 * Implements dual-engine bulk ban synchronization:
 * 1. Scope auto-discovery: Detects whether API token has Account Custom List or Zone Access Rules permissions.
 * 2. Subnet Aggregation: Consolidates >= 4 IPs in same /24 (IPv4) or /64 (IPv6) banned within 15 min into 1 CIDR.
 * 3. Asynchronous queue: Flushes queued bans via non-blocking WP-Cron hook (`webcare_cloudflare_ip_sync_cron`).
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareIpListSynchronizer {

    public const OPTION_BAN_QUEUE        = 'webcare_cf_pending_ban_queue';
    public const OPTION_TOKEN_SCOPE      = 'webcare_cf_token_scope';
    public const OPTION_ACCOUNT_LIST_ID  = 'webcare_cf_account_list_id';
    public const OPTION_RECONCILIATION_FLAG = 'webcare_cf_compensation_reconciliation_needed';
    public const OPTION_ACTIVE_EDGE_BANS = 'webcare_cf_active_edge_bans';
    public const OPTION_PENDING_OPERATIONS = 'webcare_cf_pending_operations';
    public const OPTION_IP_GENERATIONS   = 'webcare_cf_ip_generations';
    public const OPTION_SYNC_EVENTS      = 'webcare_cf_sync_events_log';
    public const LIST_NAME               = 'webcare_threat_blocklist';
    public const CRON_HOOK               = 'webcare_cloudflare_ip_sync_cron';

    /**
     * Increment monotonic per-IP generation token (preventing stale queued bans from applying after unban).
     *
     * Protected inside the atomic mutation boundary to eliminate race conditions.
     * Returns false if mutex acquisition fails or option persistence fails (never returns fabricated generation).
     *
     * @param string $ip
     * @return int|false New generation number on success, false on failure
     */
    public static function increment_ip_generation(string $ip): int|false {
        $ip = trim($ip);
        if ($ip === '') {
            return false;
        }

        $assigned_gen = null;
        $success = self::mutate_ban_queue(static function (array $queue) use ($ip, &$assigned_gen): ?array {
            $generations = get_option(self::OPTION_IP_GENERATIONS, []);
            $generations = is_array($generations) ? $generations : [];
            $current = (int) ($generations[$ip] ?? 0);
            $next_gen = $current + 1;
            $generations[$ip] = $next_gen;
            if (count($generations) > 2000) {
                $generations = array_slice($generations, -1000, null, true);
            }
            if (!self::save_verified_option(self::OPTION_IP_GENERATIONS, $generations)) {
                return null;
            }
            $assigned_gen = $next_gen;
            return $queue;
        });

        if (!$success || $assigned_gen === null) {
            return false;
        }

        return $assigned_gen;
    }

    /**
     * Safely persist an option and verify it actually exists and matches in database/storage.
     * Accounts for update_option returning false when value is identical/unchanged vs actual DB failure.
     *
     * @param string $option_name
     * @param mixed  $value
     * @return bool True if value is verified persisted in option store
     */
    public static function save_verified_option(string $option_name, mixed $value): bool {
        $res = update_option($option_name, $value, false);
        if ($res === true) {
            return true;
        }

        // update_option returns false if the stored value is already strictly equal to the new value.
        // Verify by reading back the option to distinguish between unchanged value vs storage failure.
        $stored = get_option($option_name, null);
        return ($stored === $value);
    }

    /**
     * Get current monotonic generation number for an IP.
     *
     * @param string $ip
     * @return int
     */
    public static function get_ip_generation(string $ip): int {
        $ip = trim($ip);
        if ($ip === '') {
            return 0;
        }
        $generations = get_option(self::OPTION_IP_GENERATIONS, []);
        if (!is_array($generations) || !isset($generations[$ip])) {
            return 0;
        }
        return (int) $generations[$ip];
    }

    /**
     * Append an immutable sync event to the forensic ledger.
     *
     * @param array $event
     * @return void
     */
    public static function log_sync_event(array $event): void {
        $events = get_option(self::OPTION_SYNC_EVENTS, []);
        $events = is_array($events) ? $events : [];
        $event['logged_at'] = time();
        $events[] = $event;
        if (count($events) > 500) {
            $events = array_slice($events, -300);
        }
        update_option(self::OPTION_SYNC_EVENTS, $events, false);
    }

    /**
     * In-memory queue of bans to push to Cloudflare at PHP shutdown (post-response).
     *
     * @var array<string, array>
     */
    private static array $shutdown_immediate_queue = [];

    /**
     * Whether register_shutdown_function has been registered for this request.
     *
     * @var bool
     */
    private static bool $shutdown_registered = false;

    /**
     * Test whether the configured Cloudflare API token has Account List permissions or Zone Access Rule permissions.
     * Caches the result in `webcare_cf_token_scope` for 6 hours.
     *
     * @param bool $force_refresh
     * @return string 'account' | 'zone' | 'none'
     */
    public function detect_api_scope(bool $force_refresh = false): string {
        if (!$force_refresh) {
            $cached = get_transient(self::OPTION_TOKEN_SCOPE);
            if (is_string($cached) && in_array($cached, ['account', 'zone', 'none'], true)) {
                return $cached;
            }
        }

        $settings = SettingsManager::get_settings();
        $token = $settings['cloudflare_api_token'] ?? '';
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($token)) {
            set_transient(self::OPTION_TOKEN_SCOPE, 'none', 3600);
            return 'none';
        }

        // Test 1: Probe Account List capability via /user/tokens/verify or by fetching accounts
        $accounts_res = CloudflareService::request('accounts');
        if (!empty($accounts_res['success']) && !empty($accounts_res['result'][0]['id'])) {
            $account_id = (string) $accounts_res['result'][0]['id'];
            // Check if lists endpoint is accessible
            $lists_res = CloudflareService::request("accounts/{$account_id}/rules/lists");
            if (!empty($lists_res['success'])) {
                set_transient(self::OPTION_TOKEN_SCOPE, 'account', 6 * 3600);
                return 'account';
            }
        }

        // Test 2: Fallback probe for Zone Access Rules
        if (!empty($zone_id)) {
            $zone_res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules?per_page=1");
            if (!empty($zone_res['success'])) {
                set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
                return 'zone';
            }
        }

        set_transient(self::OPTION_TOKEN_SCOPE, 'none', 1800);
        return 'none';
    }

    /**
     * Add a banned IP to the synchronization queue for background execution.
     *
     * Invariants:
     * - Advances the per-IP generation token AND persists the queue entry inside ONE shared mutex transaction.
     * - Checks the boolean result of mutate_ban_queue(); returns 'enqueue_failed' on failure without fabricating generation tokens.
     * - ZERO shutdown HTTP calls or inline requests to Cloudflare (processed strictly via background worker / WP-Cron).
     *
     * @param string $ip Client IPv4 or IPv6
     * @param string $reason Reason description
     * @param int $ttl Time to live in seconds (default 86400)
     * @return array{cf_sync_state: string, operation_id: ?string}
     */
    public static function queue_ip_ban(string $ip, string $reason = 'WebCare WAF Threat', int $ttl = 86400): array {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['cf_sync_state' => 'disabled', 'operation_id' => null];
        }

        // Never push private/loopback/reserved IPs to Cloudflare
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['cf_sync_state' => 'disabled', 'operation_id' => null];
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['cloudflare_enabled']) || empty($settings['cloudflare_api_token']) || empty($settings['cloudflare_zone_id'])) {
            return ['cf_sync_state' => 'disabled', 'operation_id' => null];
        }

        $operation_id = 'cfop_' . bin2hex(random_bytes(8));
        $assigned_generation = null;

        // Perform generation advancement AND queue insertion inside ONE shared mutex transaction with verified persistence & compensation
        $success = self::mutate_ban_queue(static function (array $queue) use ($ip, $reason, $ttl, $operation_id, &$assigned_generation): ?array {
            $prev_generations = get_option(self::OPTION_IP_GENERATIONS, []);
            $prev_generations = is_array($prev_generations) ? $prev_generations : [];

            $generations = $prev_generations;
            $current = (int) ($generations[$ip] ?? 0);
            $next_gen = $current + 1;
            $generations[$ip] = $next_gen;
            if (count($generations) > 2000) {
                $generations = array_slice($generations, -1000, null, true);
            }

            if (!self::save_verified_option(self::OPTION_IP_GENERATIONS, $generations)) {
                return null;
            }

            $queue[$ip] = [
                'ip'           => $ip,
                'reason'       => substr(sanitize_text_field($reason), 0, 240),
                'banned_at'    => time(),
                'expires_at'   => $ttl > 0 ? (time() + $ttl) : 0,
                'status'       => 'pending',
                'attempts'     => 0,
                'next_retry'   => 0,
                'last_error'   => '',
                'operation_id' => $operation_id,
                'generation'   => $next_gen,
            ];

            $assigned_generation = $next_gen;
            return $queue;
        });

        if (!$success || $assigned_generation === null) {
            return ['cf_sync_state' => 'enqueue_failed', 'operation_id' => null];
        }

        self::log_sync_event([
            'operation_id' => $operation_id,
            'ip'           => $ip,
            'type'         => 'ban_queued',
            'generation'   => $assigned_generation,
            'status'       => 'queued',
        ]);

        return ['cf_sync_state' => 'queued', 'operation_id' => $operation_id];
    }

    /**
     * Flush immediate bans after sending the HTTP 403 response to the client (0ms visitor latency).
     * Enforces atomic lock synchronization with queue processing (Finding 2.3).
     */
    public static function flush_immediate_shutdown_bans(): void {
        if (empty(self::$shutdown_immediate_queue)) {
            return;
        }

        // Flush HTTP response buffer to client first so connection closes immediately
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } elseif (function_exists('litespeed_finish_request')) {
            @litespeed_finish_request();
        }

        $lock_token = self::acquire_sync_lock(45);
        if ($lock_token === null) {
            // Another worker or cron is syncing; items are safely persisted in OPTION_BAN_QUEUE
            return;
        }

        try {
            $sync = new self();
            $items_to_sync = self::$shutdown_immediate_queue;
            self::$shutdown_immediate_queue = [];

            $targets = $sync->aggregate_subnets($items_to_sync);
            $scope = $sync->detect_api_scope();

            $result = ['synced_targets' => [], 'error' => ''];
            if ($scope === 'account') {
                $result = $sync->sync_via_account_list($targets, $items_to_sync);
            } elseif ($scope === 'zone') {
                $result = $sync->sync_via_zone_access_rules($targets, $items_to_sync);
            }

            // Determine which items were confirmed synced (CF-01)
            $confirmed_targets = $result['synced_targets'] ?? [];
            $confirmed_source_ips = [];
            foreach ($targets as $t) {
                if (in_array($t['target'], $confirmed_targets, true)) {
                    foreach (($t['source_ips'] ?? [$t['target']]) as $sip) {
                        $confirmed_source_ips[$sip] = true;
                    }
                }
            }

            // Remove confirmed items from OPTION_BAN_QUEUE and update unconfirmed items safely via mutate_ban_queue (Finding 1.2)
            self::mutate_ban_queue(static function (array $queue) use ($confirmed_source_ips, $items_to_sync, $result): array {
                if (!empty($confirmed_source_ips)) {
                    foreach (array_keys($confirmed_source_ips) as $cip) {
                        unset($queue[$cip]);
                    }
                }

                $now = time();
                foreach ($items_to_sync as $ip => $entry) {
                    if (empty($confirmed_source_ips[$ip])) {
                        $attempts = ((int) ($entry['attempts'] ?? 0)) + 1;
                        $entry['status']     = ($attempts >= 5) ? 'failed' : 'retry';
                        $entry['attempts']   = $attempts;
                        $entry['next_retry'] = $now + min(3600, 30 * (2 ** $attempts));
                        $entry['last_error'] = (string) ($result['error'] ?? 'Shutdown flush unconfirmed');
                        $queue[$ip] = $entry;
                    }
                }
                return $queue;
            });
        } finally {
            self::release_sync_lock($lock_token);
        }
    }

    /**
     * Trigger immediate non-blocking loopback request to flush bans without waiting for cron visitor.
     */
    public static function trigger_background_queue_flush(): void {
        $last_spawn = (int) get_transient('webcare_cf_queue_spawn_debounce');
        if (time() - $last_spawn < 60) {
            return; // Debounce to at most once per 60 seconds
        }
        set_transient('webcare_cf_queue_spawn_debounce', time(), 60);

        $now = time();
        $random_nonce = function_exists('wp_generate_password') ? wp_generate_password(16, false) : bin2hex(random_bytes(8));
        $salt = class_exists(\WebCareProScanner\Security\SecretVault::class)
            ? \WebCareProScanner\Security\SecretVault::get_key()
            : (function_exists('wp_salt') ? wp_salt('auth') : '');
        if ($salt === '') {
            return;
        }
        $signature = hash_hmac('sha256', "cf_flush|{$now}|{$random_nonce}", $salt);
        $token = "{$now}:{$random_nonce}:{$signature}";

        $ajax_url = admin_url('admin-ajax.php');
        wp_remote_post($ajax_url, [
            'timeout'   => 0.01,
            'blocking'  => false,
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Standard WordPress core filter for local loopback requests
            'sslverify' => apply_filters('https_local_ssl_verify', false),
            'body'      => [
                'action' => 'webcare_flush_cf_ban_queue',
                'token'  => $token,
            ],
        ]);
    }

    /**
     * Group IPv4 addresses by /24 prefix (and IPv6 by /64).
     * If enough distinct IPs in the same subnet were banned within 15 minutes (900s),
     * merges them into a single CIDR (e.g. xxx.xxx.xxx.0/24) to conserve rule quotas.
     *
     * Subnet aggregation is safe by default (CF-03): gated behind setting cloudflare_subnet_aggregation_enabled (default false).
     *
     * @param array $queue_entries Raw queue entries `[ip => ['ip' => ..., 'banned_at' => ...]]`
     * @return array Consolidated targets: `[['target' => string, 'type' => 'ip'|'ip_range', 'notes' => string, 'source_ips' => array]]`
     */
    public function aggregate_subnets(array $queue_entries): array {
        $settings = SettingsManager::get_settings();
        $aggregation_enabled = !empty($settings['cloudflare_subnet_aggregation_enabled']);

        // Safe Subnet Aggregation Defaults (CF-03): Default is disabled (individual IPs only)
        if (!$aggregation_enabled) {
            $singles = [];
            foreach ($queue_entries as $entry) {
                $ip = (string) ($entry['ip'] ?? '');
                if (!empty($ip)) {
                    $singles[] = [
                        'target'     => $ip,
                        'type'       => 'ip',
                        'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$ip],
                    ];
                }
            }
            return $singles;
        }

        $now = time();
        $subnets_v4 = []; // '192.0.2' => [entries]
        $subnets_v6 = []; // '2001:db8:1:1' => [entries]
        $singles = [];

        foreach ($queue_entries as $entry) {
            $ip = (string) ($entry['ip'] ?? '');
            $banned_at = (int) ($entry['banned_at'] ?? $now);

            // Only aggregate if banned within the last 15 minutes (900s)
            $is_recent = ($now - $banned_at) <= 900;

            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $octets = explode('.', $ip);
                if (count($octets) === 4) {
                    $prefix = "{$octets[0]}.{$octets[1]}.{$octets[2]}";
                    if ($is_recent) {
                        $subnets_v4[$prefix][] = $entry;
                    } else {
                        $singles[] = [
                            'target'     => $ip,
                            'type'       => 'ip',
                            'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                            'source_ips' => [$ip],
                        ];
                    }
                    continue;
                }
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $expanded = inet_pton($ip);
                if ($expanded !== false) {
                    $hex = bin2hex(substr($expanded, 0, 8)); // First 64 bits
                    $prefix = implode(':', str_split($hex, 4));
                    if ($is_recent) {
                        $subnets_v6[$prefix][] = $entry;
                    } else {
                        $singles[] = [
                            'target'     => $ip,
                            'type'       => 'ip',
                            'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                            'source_ips' => [$ip],
                        ];
                    }
                    continue;
                }
            }

            $singles[] = [
                'target'     => $ip,
                'type'       => 'ip',
                'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                'source_ips' => [$ip],
            ];
        }

        $results = [];

        // Check IPv4 clusters: Threshold defaults to 10 distinct IPs within 15 minutes (CF-03)
        $v4_threshold = (int) ($settings['cloudflare_subnet_v4_threshold'] ?? 10);
        if ($v4_threshold < 2) {
            $v4_threshold = 10;
        }

        foreach ($subnets_v4 as $prefix => $cluster) {
            $distinct_v4_ips = array_unique(array_column($cluster, 'ip'));
            if (count($distinct_v4_ips) >= $v4_threshold) {
                $results[] = [
                    'target'     => "{$prefix}.0/24",
                    'type'       => 'ip_range',
                    'notes'      => sprintf('WebCare Aggregated /24 (%d distinct IPs in 15m)', count($distinct_v4_ips)),
                    'source_ips' => array_values($distinct_v4_ips),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target'     => $c['ip'],
                        'type'       => 'ip',
                        'notes'      => $c['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$c['ip']],
                    ];
                }
            }
        }

        // Check IPv6 clusters: NEVER auto-aggregate unless explicitly enabled and >= 16 distinct IPs (CF-03)
        $v6_enabled = !empty($settings['cloudflare_subnet_v6_aggregation_enabled']);
        $v6_threshold = max(16, (int) ($settings['cloudflare_subnet_v6_threshold'] ?? 16));

        foreach ($subnets_v6 as $prefix => $cluster) {
            $distinct_v6_ips = array_unique(array_column($cluster, 'ip'));
            if ($v6_enabled && count($distinct_v6_ips) >= $v6_threshold) {
                $results[] = [
                    'target'     => "{$prefix}::/64",
                    'type'       => 'ip_range',
                    'notes'      => sprintf('WebCare Aggregated /64 (%d distinct IPs in 15m)', count($distinct_v6_ips)),
                    'source_ips' => array_values($distinct_v6_ips),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target'     => $c['ip'],
                        'type'       => 'ip',
                        'notes'      => $c['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$c['ip']],
                    ];
                }
            }
        }

        return array_merge($results, $singles);
    }

    /**
     * Mutate persistent ban queue under atomic database-level spinlock mutex (Finding 1.2).
     * Guarantees concurrent producers and consumers never drop newly added IP bans.
     *
     * @param callable $callback function(array $queue): array
     * @return bool
     */
    public static function mutate_ban_queue(callable $callback): bool {
        global $wpdb;
        $mutex_key = 'webcare_cf_queue_mutex';
        $acquired = false;
        $start = microtime(true);
        $token = bin2hex(random_bytes(16));

        // Spinlock with backoff (up to 2.5 seconds)
        while ((microtime(true) - $start) < 2.5) {
            $lock_val = $token . '|' . (time() + 5);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if (add_option($mutex_key, $lock_val, '', 'no')) {
                $acquired = true;
                break;
            }

            // Check if existing mutex is expired
            if ($wpdb && isset($wpdb->options)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $existing = (string) $wpdb->get_var($wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
                    $mutex_key
                ));
                if ($existing !== '') {
                    $parts = explode('|', $existing, 2);
                    $exp = (int) ($parts[1] ?? 0);
                    if ($exp > 0 && $exp < time()) {
                        // Expired: attempt atomic Compare-And-Swap takeover
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                        $swapped = $wpdb->query($wpdb->prepare(
                            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s",
                            $lock_val,
                            $mutex_key,
                            $existing
                        ));
                        if ($swapped === 1) {
                            $acquired = true;
                            break;
                        }
                    }
                }
            }

            usleep(10000); // 10ms
        }

        if (!$acquired) {
            // Finding 1.7 / Master Plan PR-A: Never mutate un-atomically when mutex acquisition fails
            return false;
        }

        try {
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete(self::OPTION_BAN_QUEUE, 'options');
            }
            $raw = null;
            if ($wpdb && isset($wpdb->options)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $raw = $wpdb->get_var($wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
                    self::OPTION_BAN_QUEUE
                ));
            }
            $queue = ($raw !== null && $raw !== '') ? maybe_unserialize($raw) : get_option(self::OPTION_BAN_QUEUE, []);
            $queue = is_array($queue) ? $queue : [];

            $prev_generations = get_option(self::OPTION_IP_GENERATIONS, []);
            $prev_queue = $queue;

            $queue = $callback($queue);
            if ($queue === null || !is_array($queue)) {
                return false;
            }

            if (empty($queue)) {
                delete_option(self::OPTION_BAN_QUEUE);
                $persisted = (get_option(self::OPTION_BAN_QUEUE, null) === null);
            } else {
                if (count($queue) > 500) {
                    $queue = array_slice($queue, -500, null, true);
                }
                $persisted = self::save_verified_option(self::OPTION_BAN_QUEUE, $queue);
            }

            if (!$persisted) {
                // Compensate/Rollback OPTION_IP_GENERATIONS to previous state if queue persistence failed
                $rolled_back = self::save_verified_option(self::OPTION_IP_GENERATIONS, $prev_generations);
                if (!$rolled_back) {
                    // Set and verify a durable persistent reconciliation-needed marker in database
                    $marker_persisted = self::save_verified_option(self::OPTION_RECONCILIATION_FLAG, time());
                    if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                        \WebCareProScanner\System\AuditLogger::log_operational('cf_queue_compensation_failed', [
                            'error'            => 'Failed to reconcile OPTION_IP_GENERATIONS after queue persistence failure',
                            'marker_persisted' => $marker_persisted,
                            'timestamp'        => time(),
                        ]);
                        if (!$marker_persisted) {
                            \WebCareProScanner\System\AuditLogger::log_operational('cf_reconciliation_marker_write_failed', [
                                'error'     => 'Failed to persist durable reconciliation marker to database',
                                'timestamp' => time(),
                            ]);
                        }
                    }
                }
                return false;
            }

            return true;
        } finally {
            if ($wpdb && isset($wpdb->options)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query($wpdb->prepare(
                    "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value LIKE %s",
                    $mutex_key,
                    $token . '|%'
                ));
            } else {
                delete_option($mutex_key);
            }
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete($mutex_key, 'options');
            }
        }
    }

    /**
     * Acquire atomic database-level synchronization lock using add_option and atomic DB CAS takeover (Finding 1.1).
     *
     * @param int $ttl Lock lifetime in seconds (default 60)
     * @return string|null Lock token if successfully acquired, null if already locked
     */
    public static function acquire_sync_lock(int $ttl = 60): ?string {
        global $wpdb;
        $now = time();
        $token = bin2hex(random_bytes(16)) . '|' . ($now + $ttl);
        $lock_key = 'webcare_cf_sync_atomic_lock';

        // 1. Fast-path: Atomic DB insertion via add_option (fails if option already exists)
        if (add_option($lock_key, $token, '', 'no')) {
            return $token;
        }

        // 2. Slow-path: Check if existing lock is expired and perform atomic Compare-And-Swap (CAS)
        if ($wpdb && isset($wpdb->options)) {
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete($lock_key, 'options');
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $existing = (string) $wpdb->get_var($wpdb->prepare(
                "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
                $lock_key
            ));
            if ($existing !== '') {
                $parts = explode('|', $existing, 2);
                $exp = (int) ($parts[1] ?? 0);
                if ($exp > 0 && $exp < $now) {
                    // Lock expired: atomic CAS update strictly verifying previous option_value
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $updated = $wpdb->query($wpdb->prepare(
                        "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s",
                        $token,
                        $lock_key,
                        $existing
                    ));
                    if ($updated === 1) {
                        if (function_exists('wp_cache_delete')) {
                            wp_cache_delete($lock_key, 'options');
                        }
                        return $token;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Release atomic synchronization lock only if held by current worker (Finding 1.1).
     *
     * @param string|null $token
     * @return void
     */
    public static function release_sync_lock(?string $token): void {
        if ($token === null || $token === '') {
            return;
        }
        global $wpdb;
        $lock_key = 'webcare_cf_sync_atomic_lock';

        if ($wpdb && isset($wpdb->options)) {
            // Atomic conditional deletion in single database query
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
                $lock_key,
                $token
            ));
        } else {
            $current = (string) get_option($lock_key, '');
            if ($current === $token) {
                delete_option($lock_key);
            }
        }
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete($lock_key, 'options');
        }
    }

    /**
     * Flush queued bans to Cloudflare Edge and prune expired temporary bans.
     * Enforces durable queue state machine, retry backoff and atomic mutex locking (CF-01, Finding 2.3).
     *
     * @return int Number of synchronized items
     */
    public function process_sync_queue(): int {
        // Atomic mutex lock (CF-01, Finding 2.3): atomic DB lock prevents race conditions
        $lock_token = self::acquire_sync_lock(60);
        if ($lock_token === null) {
            return 0;
        }

        try {
            // 0. Reconcile pending async bulk operations first
            $this->reconcile_pending_operations();

            // 1. Prune expired temporary edge bans (with acknowledgement check)
            $this->prune_expired_bans();

            $queue = get_option(self::OPTION_BAN_QUEUE, []);
            if (empty($queue) || !is_array($queue)) {
                return 0;
            }

            $now = time();
            $eligible_entries = [];
            $ineligible_entries = [];

            $stale_ips_to_evict = [];
            foreach ($queue as $ip => $entry) {
                if (!is_array($entry)) {
                    continue;
                }
                $entry['ip']         = (string) ($entry['ip'] ?? $ip);
                $entry['reason']     = (string) ($entry['reason'] ?? 'WebCare Threat Block');
                $entry['status']     = (string) ($entry['status'] ?? 'pending');
                $entry['attempts']   = (int) ($entry['attempts'] ?? 0);
                $entry['next_retry'] = (int) ($entry['next_retry'] ?? 0);
                $entry['last_error'] = (string) ($entry['last_error'] ?? '');

                // Generation Fencing: Verify queued operation generation matches current IP generation
                $current_gen = self::get_ip_generation($ip);
                $entry_gen   = (int) ($entry['generation'] ?? 0);
                if ($entry_gen > 0 && $entry_gen < $current_gen) {
                    // Stale generation: this IP was unbanned or re-evaluated since this ban was enqueued
                    $stale_ips_to_evict[] = $ip;
                    self::log_sync_event([
                        'operation_id' => $entry['operation_id'] ?? '',
                        'ip'           => $ip,
                        'type'         => 'ban_skipped_stale',
                        'generation'   => $entry_gen,
                        'current_gen'  => $current_gen,
                        'status'       => 'skipped',
                    ]);
                    continue;
                }

                // Skip items that exceeded maximum attempts (5) or are waiting for exponential backoff
                if ($entry['attempts'] >= 5) {
                    $entry['status'] = 'dead_letter';
                    $ineligible_entries[$ip] = $entry;
                    continue;
                }

                if ($entry['next_retry'] > $now) {
                    $ineligible_entries[$ip] = $entry;
                    continue;
                }

                $eligible_entries[$ip] = $entry;
            }

            if (!empty($stale_ips_to_evict)) {
                self::mutate_ban_queue(static function (array $q) use ($stale_ips_to_evict): array {
                    foreach ($stale_ips_to_evict as $sip) {
                        unset($q[$sip]);
                    }
                    return $q;
                });
            }

            if (empty($eligible_entries)) {
                return 0;
            }

            $scope = $this->detect_api_scope();
            if ($scope === 'none') {
                return 0;
            }

            $aggregated_targets = $this->aggregate_subnets($eligible_entries);
            if (empty($aggregated_targets)) {
                return 0;
            }

            $sync_result = ($scope === 'account')
                ? $this->sync_via_account_list($aggregated_targets, $eligible_entries)
                : $this->sync_via_zone_access_rules($aggregated_targets, $eligible_entries);

            $confirmed_targets = $sync_result['synced_targets'] ?? [];
            $confirmed_ips = [];

            foreach ($aggregated_targets as $t) {
                if (in_array($t['target'], $confirmed_targets, true)) {
                    foreach (($t['source_ips'] ?? [$t['target']]) as $sip) {
                        $confirmed_ips[$sip] = true;
                    }
                }
            }

            $synced_count = count($confirmed_ips);

            foreach (array_keys($confirmed_ips) as $cip) {
                $op_id = $eligible_entries[$cip]['operation_id'] ?? '';
                self::log_sync_event([
                    'operation_id' => $op_id,
                    'ip'           => $cip,
                    'type'         => 'ban_applied',
                    'status'       => 'completed',
                ]);
            }

            // Safely mutate persistent queue under mutex without clobbering new concurrent entries (Finding 1.2)
            self::mutate_ban_queue(static function (array $queue) use ($confirmed_ips, $eligible_entries, $sync_result, $now): array {
                // Drop confirmed synced items
                foreach (array_keys($confirmed_ips) as $cip) {
                    unset($queue[$cip]);
                }

                // Update unconfirmed/failed items with retry backoff with jitter
                foreach ($eligible_entries as $ip => $entry) {
                    if (empty($confirmed_ips[$ip])) {
                        $attempts = ((int) ($entry['attempts'] ?? 0)) + 1;
                        $entry['attempts']   = $attempts;
                        $entry['last_error'] = (string) ($sync_result['error'] ?? 'Synchronization unconfirmed');
                        $is_dead_letter      = ($attempts >= 5);
                        $entry['status']     = $is_dead_letter ? 'dead_letter' : 'retry';
                        $backoff_sec         = min(3600, 30 * (2 ** $attempts));
                        $jitter              = wp_rand(0, 15);
                        $entry['next_retry'] = $now + $backoff_sec + $jitter;
                        $queue[$ip] = $entry;

                        self::log_sync_event([
                            'operation_id' => $entry['operation_id'] ?? '',
                            'ip'           => $ip,
                            'type'         => $is_dead_letter ? 'ban_dead_letter' : 'ban_retry',
                            'attempts'     => $attempts,
                            'error'        => $entry['last_error'],
                            'status'       => $entry['status'],
                        ]);
                    }
                }

                return $queue;
            });

            return $synced_count;
        } finally {
            self::release_sync_lock($lock_token);
        }
    }

    /**
     * Sync targets to Cloudflare Account Custom IP List.
     * Automatically downgrades to Zone Access Rules on write permission errors (CF-02).
     *
     * @param array $targets
     * @param array $source_entries
     * @return array ['synced_targets' => string[], 'error' => string]
     */
    private function sync_via_account_list(array $targets, array $source_entries = []): array {
        $accounts_res = CloudflareService::request('accounts');
        if (empty($accounts_res['success']) || empty($accounts_res['result'][0]['id'])) {
            // Downgrade scope and fallback immediately to zone access rules (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        $account_id = (string) $accounts_res['result'][0]['id'];
        $list_id = $this->ensure_account_list($account_id);
        if (empty($list_id)) {
            // Downgrade scope and fallback immediately to zone access rules (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        // Build items payload (up to 10,000 items in single call)
        $items = [];
        foreach ($targets as $t) {
            $items[] = [
                'ip'      => $t['target'],
                'comment' => substr((string) ($t['notes'] ?? '[WebCare-WAF] Threat Block'), 0, 240),
            ];
        }

        if (empty($items)) {
            return ['synced_targets' => [], 'error' => ''];
        }

        $post_res = CloudflareService::request(
            "accounts/{$account_id}/rules/lists/{$list_id}/items",
            'POST',
            $items
        );

        if (empty($post_res['success'])) {
            // Write permission error or failure on account list: downgrade scope to zone and retry immediately (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        // Track operation_id if returned by Cloudflare async bulk list API
        $operation_id = !empty($post_res['result']['operation_id']) ? (string) $post_res['result']['operation_id'] : '';
        if (!empty($operation_id)) {
            self::record_pending_operation(
                $operation_id,
                $account_id,
                $list_id,
                'create',
                array_column($targets, 'target')
            );
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (!is_array($active_bans)) {
            $active_bans = [];
        }

        $synced_targets = [];
        if (!empty($post_res['result']) && is_array($post_res['result'])) {
            foreach ($post_res['result'] as $created) {
                $c_ip = (string) ($created['ip'] ?? '');
                $c_id = (string) ($created['id'] ?? '');
                if (!empty($c_ip) && !empty($c_id)) {
                    $active_bans[$c_ip] = [
                        'target'     => $c_ip,
                        'mode'       => 'account',
                        'item_id'    => $c_id,
                        'expires_at' => (int) ($source_entries[$c_ip]['expires_at'] ?? (time() + 86400)),
                        'synced_at'  => time(),
                    ];
                    $synced_targets[] = $c_ip;
                }
            }
        }

        if (empty($synced_targets)) {
            // Attempt to resolve item IDs from list items directly (Finding 2.4)
            $list_items_res = CloudflareService::request("accounts/{$account_id}/rules/lists/{$list_id}/items?per_page=100");
            if (!empty($list_items_res['success']) && !empty($list_items_res['result']) && is_array($list_items_res['result'])) {
                $target_map = array_fill_keys(array_column($targets, 'target'), true);
                foreach ($list_items_res['result'] as $l_item) {
                    $l_ip = (string) ($l_item['ip'] ?? '');
                    $l_id = (string) ($l_item['id'] ?? '');
                    if (!empty($l_ip) && !empty($l_id) && isset($target_map[$l_ip])) {
                        $active_bans[$l_ip] = [
                            'target'     => $l_ip,
                            'mode'       => 'account',
                            'item_id'    => $l_id,
                            'expires_at' => (int) ($source_entries[$l_ip]['expires_at'] ?? (time() + 86400)),
                            'synced_at'  => time(),
                        ];
                        $synced_targets[] = $l_ip;
                    }
                }
            }
        }

        // If items are still pending under an async operation, persist them in pending state
        // rather than immediately falling back to Zone Access Rules while the bulk operation is processing
        // PR-A2: Pending-create items must NOT be treated as confirmed synced; they stay tracked under pending_create
        if (empty($synced_targets) && !empty($operation_id)) {
            foreach ($targets as $t) {
                $t_ip = (string) ($t['target'] ?? '');
                if (!empty($t_ip)) {
                    $active_bans[$t_ip] = [
                        'target'       => $t_ip,
                        'mode'         => 'account',
                        'state'        => 'pending_create',
                        'operation_id' => $operation_id,
                        'expires_at'   => (int) ($source_entries[$t_ip]['expires_at'] ?? (time() + 86400)),
                        'synced_at'    => time(),
                    ];
                }
            }
            if (count($active_bans) > 2000) {
                $active_bans = array_slice($active_bans, -2000, null, true);
            }
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
            return ['synced_targets' => [], 'error' => 'Pending async operation: ' . $operation_id];
        }

        // If items STILL cannot be confirmed or tracked via pending operation, fail closed and downgrade to zone access rules
        if (empty($synced_targets)) {
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        if (count($active_bans) > 2000) {
            $active_bans = array_slice($active_bans, -2000, null, true);
        }
        update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);

        return ['synced_targets' => $synced_targets, 'error' => ''];
    }

    /**
     * Ensure WebCare Threat blocklist exists in Cloudflare Account.
     */
    private function ensure_account_list(string $account_id): string {
        $stored = (string) get_option(self::OPTION_ACCOUNT_LIST_ID, '');
        if (!empty($stored)) {
            return $stored;
        }

        // Check if list already exists on Cloudflare
        $lists_res = CloudflareService::request("accounts/{$account_id}/rules/lists");
        if (!empty($lists_res['success']) && !empty($lists_res['result'])) {
            foreach ($lists_res['result'] as $list) {
                if (($list['name'] ?? '') === self::LIST_NAME) {
                    $id = (string) $list['id'];
                    update_option(self::OPTION_ACCOUNT_LIST_ID, $id, false);
                    return $id;
                }
            }
        }

        // Create list if not existing
        $create_res = CloudflareService::request(
            "accounts/{$account_id}/rules/lists",
            'POST',
            [
                'name'        => self::LIST_NAME,
                'description' => 'WebCare Pro Security Autonomous Threat Blocklist',
                'kind'        => 'ip',
            ]
        );

        if (!empty($create_res['success']) && !empty($create_res['result']['id'])) {
            $id = (string) $create_res['result']['id'];
            update_option(self::OPTION_ACCOUNT_LIST_ID, $id, false);
            return $id;
        }

        return '';
    }

    /**
     * Fallback driver: sync targets via Zone IP Access Rules API.
     *
     * @param array $targets
     * @param array $source_entries
     * @return array ['synced_targets' => string[], 'error' => string]
     */
    private function sync_via_zone_access_rules(array $targets, array $source_entries = []): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return ['synced_targets' => [], 'error' => 'Cloudflare Zone ID missing'];
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (!is_array($active_bans)) {
            $active_bans = [];
        }

        $synced_targets = [];
        $last_error = '';

        foreach ($targets as $t) {
            $raw_note = (string) ($t['notes'] ?? 'WebCare Local Ban');
            $tag = class_exists(CloudflareService::class) ? CloudflareService::WEBCARE_RULE_TAG : '[WebCare Pro Security]';
            if (!str_starts_with($raw_note, $tag) && !str_starts_with($raw_note, '[WebCare-WAF]')) {
                $raw_note = $tag . ' ' . $raw_note;
            }
            $payload = [
                'mode'          => 'block',
                'configuration' => [
                    'target' => $t['type'] === 'ip_range' ? 'ip_range' : 'ip',
                    'value'  => $t['target'],
                ],
                'notes'         => substr($raw_note, 0, 240),
            ];

            $res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);
            if (!empty($res['success'])) {
                $rule_id = (string) ($res['result']['id'] ?? '');
                $tip = $t['target'];
                $synced_targets[] = $tip;
                $active_bans[$tip] = [
                    'target'     => $tip,
                    'mode'       => 'zone',
                    'item_id'    => $rule_id,
                    'expires_at' => (int) ($source_entries[$tip]['expires_at'] ?? (time() + 86400)),
                    'synced_at'  => time(),
                ];
            } else {
                $last_error = $res['errors'][0]['message'] ?? 'Failed to create zone access rule';
            }
        }

        if (!empty($synced_targets)) {
            if (count($active_bans) > 2000) {
                $active_bans = array_slice($active_bans, -2000, null, true);
            }
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
        }

        return ['synced_targets' => $synced_targets, 'error' => $last_error];
    }

    /**
     * Prune expired edge bans from Cloudflare and the active bans ledger.
     * Enforces acknowledgement-based deletion: only removes from local ledger if Cloudflare confirmed (CF-04).
     *
     * @return int Number of pruned items
     */
    public function prune_expired_bans(): int {
        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (empty($active_bans) || !is_array($active_bans)) {
            return 0;
        }

        $now = time();
        $expired_items = [];
        $updated_ledger = [];

        foreach ($active_bans as $target => $meta) {
            $expires_at = (int) ($meta['expires_at'] ?? 0);
            if ($expires_at > 0 && $now >= $expires_at) {
                $expired_items[$target] = $meta;
            } else {
                $updated_ledger[$target] = $meta;
            }
        }

        if (empty($expired_items)) {
            return 0;
        }

        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $account_items_to_del = [];
        $account_targets = [];
        $pruned_count = 0;

        foreach ($expired_items as $target => $meta) {
            $mode = $meta['mode'] ?? 'zone';
            $item_id = (string) ($meta['item_id'] ?? '');

            if ($mode === 'account' && !empty($item_id)) {
                $account_items_to_del[] = ['id' => $item_id];
                $account_targets[$item_id] = [$target, $meta];
            } elseif ($mode === 'zone') {
                if (empty($item_id) || empty($zone_id)) {
                    // No valid Cloudflare ID to delete; safely drop from local ledger
                    $pruned_count++;
                    continue;
                }

                $del_res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$item_id}", 'DELETE');
                $err_code = (int) ($del_res['errors'][0]['code'] ?? 0);
                $err_msg = strtolower((string) ($del_res['errors'][0]['message'] ?? ''));
                $http_code = (int) ($del_res['http_code'] ?? 0);
                $is_already_deleted = ($http_code === 404 || $err_code === 10002 || str_contains($err_msg, 'not found') || str_contains($err_msg, 'does not exist'));

                if (!empty($del_res['success']) || $is_already_deleted) {
                    $pruned_count++;
                } else {
                    // Retain in active bans ledger for retry (CF-04)
                    $meta['unban_status'] = 'unban_retry';
                    $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'Cloudflare DELETE failed';
                    $meta['unban_attempts'] = ((int) ($meta['unban_attempts'] ?? 0)) + 1;
                    $updated_ledger[$target] = $meta;
                }
            } else {
                $pruned_count++;
            }
        }

        // Batch delete from account list if any
        if (!empty($account_items_to_del)) {
            $accounts_res = CloudflareService::request('accounts');
            $account_id = (string) ($accounts_res['result'][0]['id'] ?? '');
            $list_id = !empty($account_id) ? $this->ensure_account_list($account_id) : '';

            if (!empty($list_id)) {
                $del_res = CloudflareService::request(
                    "accounts/{$account_id}/rules/lists/{$list_id}/items",
                    'DELETE',
                    ['items' => $account_items_to_del]
                );

                if (!empty($del_res['success'])) {
                    $pruned_count += count($account_items_to_del);
                } else {
                    // Retain account items in active bans ledger for retry (CF-04)
                    foreach ($account_targets as $item_id => [$target, $meta]) {
                        $meta['unban_status'] = 'unban_retry';
                        $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'Account list item DELETE failed';
                        $meta['unban_attempts'] = ((int) ($meta['unban_attempts'] ?? 0)) + 1;
                        $updated_ledger[$target] = $meta;
                    }
                }
            } else {
                foreach ($account_targets as $item_id => [$target, $meta]) {
                    $meta['unban_status'] = 'unban_retry';
                    $meta['last_unban_error'] = 'Could not resolve Account List ID';
                    $updated_ledger[$target] = $meta;
                }
            }
        }

        // Save ledger AFTER inspecting Cloudflare responses (CF-04)
        if (count($updated_ledger) > 2000) {
            $updated_ledger = array_slice($updated_ledger, -2000, null, true);
        }
        update_option(self::OPTION_ACTIVE_EDGE_BANS, $updated_ledger, false);

        return $pruned_count;
    }

    /**
     * Immediately unban an IP address from Cloudflare Edge (Zone Access Rules and Account Custom List)
     * and clear it from active ledgers and pending queues.
     *
     * Invariant: Never removes local ledger entry before remote edge deletion is confirmed or completed.
     * Tracks async operation_id on Account List DELETE and retains local ledger in 'pending_unban' state.
     *
     * @param string $ip
     * @return bool
     */
    public static function unban_ip_immediately(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Remove from in-memory shutdown queue if present
        if (isset(self::$shutdown_immediate_queue[$ip])) {
            unset(self::$shutdown_immediate_queue[$ip]);
        }

        $unban_gen = null;

        // Monotonic per-IP generation increment AND pending batch queue eviction inside ONE shared mutex transaction
        $queue_removed = self::mutate_ban_queue(static function (array $queue) use ($ip, &$unban_gen): ?array {
            $prev_generations = get_option(self::OPTION_IP_GENERATIONS, []);
            $prev_generations = is_array($prev_generations) ? $prev_generations : [];

            $generations = $prev_generations;
            $current = (int) ($generations[$ip] ?? 0);
            $next_gen = $current + 1;
            $generations[$ip] = $next_gen;
            if (count($generations) > 2000) {
                $generations = array_slice($generations, -1000, null, true);
            }

            if (!self::save_verified_option(self::OPTION_IP_GENERATIONS, $generations)) {
                return null;
            }

            unset($queue[$ip]);
            $unban_gen = $next_gen;
            return $queue;
        });

        if (!$queue_removed || $unban_gen === null) {
            return false;
        }

        self::log_sync_event([
            'ip'         => $ip,
            'type'       => 'ip_unbanned_locally',
            'generation' => $unban_gen,
            'status'     => 'unbanned',
        ]);

        if ($queue_removed === false) {
            return false;
        }

        // 3. Inspect active edge bans ledger
        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        $meta = is_array($active_bans) ? ($active_bans[$ip] ?? null) : null;

        // If not in active edge bans ledger, nothing further on edge to remove
        if ($meta === null) {
            return true;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['cloudflare_api_token'])) {
            // No API token configured: safe to drop from local ledger immediately
            if (is_array($active_bans) && isset($active_bans[$ip])) {
                unset($active_bans[$ip]);
                update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
            }
            return true;
        }

        $sync = new self();
        $scope = $sync->detect_api_scope();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $mode = (string) ($meta['mode'] ?? '');

        // If tracked in Account List
        if ($mode === 'account' || ($scope === 'account' && $mode !== 'zone')) {
            $accounts_res = CloudflareService::request('accounts');
            if (!empty($accounts_res['success']) && !empty($accounts_res['result'][0]['id'])) {
                $account_id = (string) $accounts_res['result'][0]['id'];
                $list_id = $sync->ensure_account_list($account_id);

                if (!empty($list_id)) {
                    $item_id = (string) ($meta['item_id'] ?? '');

                    // If item_id is missing, query the list first to resolve the exact item_id
                    if (empty($item_id)) {
                        $list_items_res = CloudflareService::request("accounts/{$account_id}/rules/lists/{$list_id}/items?search=" . rawurlencode($ip));
                        if (!empty($list_items_res['success']) && !empty($list_items_res['result']) && is_array($list_items_res['result'])) {
                            foreach ($list_items_res['result'] as $l_item) {
                                if (($l_item['ip'] ?? '') === $ip && !empty($l_item['id'])) {
                                    $item_id = (string) $l_item['id'];
                                    break;
                                }
                            }
                        }
                    }

                    if (!empty($item_id)) {
                        $del_res = CloudflareService::request(
                            "accounts/{$account_id}/rules/lists/{$list_id}/items",
                            'DELETE',
                            ['items' => [['id' => $item_id]]]
                        );

                        if (!empty($del_res['success'])) {
                            $operation_id = (string) ($del_res['result']['operation_id'] ?? '');

                            if (!empty($operation_id)) {
                                // Async operation returned: poll operation status
                                $op_status = self::poll_bulk_operation($account_id, $operation_id);

                                if ($op_status === 'completed') {
                                    // 3-state verification: 'confirmed_absent', 'confirmed_present', 'verification_unknown'
                                    $verify_res = CloudflareService::request("accounts/{$account_id}/rules/lists/{$list_id}/items?search=" . rawurlencode($ip));
                                    $verification_state = 'verification_unknown';
                                    if (!empty($verify_res['success']) && isset($verify_res['result']) && is_array($verify_res['result'])) {
                                        $still_present = false;
                                        foreach ($verify_res['result'] as $v_item) {
                                            if (($v_item['ip'] ?? '') === $ip) {
                                                $still_present = true;
                                                break;
                                            }
                                        }
                                        $verification_state = $still_present ? 'confirmed_present' : 'confirmed_absent';
                                    }

                                    if ($verification_state === 'confirmed_absent') {
                                        unset($active_bans[$ip]);
                                        update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                                        return true;
                                    }
                                }

                                // Mark state as pending_unban and record pending operation
                                $meta['state']        = 'pending_unban';
                                $meta['operation_id'] = $operation_id;
                                $meta['item_id']      = $item_id;
                                $active_bans[$ip]     = $meta;
                                update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);

                                self::record_pending_operation($operation_id, $account_id, $list_id, 'delete', [$ip]);
                                return false;
                            }

                            // Synchronous completion without operation_id
                            $verify_res = CloudflareService::request("accounts/{$account_id}/rules/lists/{$list_id}/items?search=" . rawurlencode($ip));
                            $verification_state = 'verification_unknown';
                            if (!empty($verify_res['success']) && isset($verify_res['result']) && is_array($verify_res['result'])) {
                                $still_present = false;
                                foreach ($verify_res['result'] as $v_item) {
                                    if (($v_item['ip'] ?? '') === $ip) {
                                        $still_present = true;
                                        break;
                                    }
                                }
                                $verification_state = $still_present ? 'confirmed_present' : 'confirmed_absent';
                            }

                            if ($verification_state === 'confirmed_absent') {
                                unset($active_bans[$ip]);
                                update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                                return true;
                            }

                            $meta['state']            = 'pending_unban';
                            $meta['unban_status']     = 'unban_retry';
                            $meta['last_unban_error'] = 'Post-verification state: ' . $verification_state;
                            $active_bans[$ip]         = $meta;
                            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                            return false;
                        }

                        // API call failed: retain local ledger entry and record error
                        $meta['state']            = 'pending_unban';
                        $meta['unban_status']     = 'unban_retry';
                        $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'DELETE request rejected';
                        $active_bans[$ip]         = $meta;
                        update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                        return false;
                    }
                }
            }

            // Do not fall through to Zone Access Rules for an account-list tracked IP
            $meta['state']            = 'pending_unban';
            $meta['unban_status']     = 'unban_retry';
            $meta['last_unban_error'] = 'Account list lookup failed for account-tracked IP';
            $active_bans[$ip]         = $meta;
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
            return false;
        }

        // Zone IP Access Rules
        if (!empty($zone_id)) {
            $item_id = (string) ($meta['item_id'] ?? '');
            $mode = (string) ($meta['mode'] ?? '');

            if (!empty($item_id) && $mode === 'zone') {
                $del_res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$item_id}", 'DELETE');
                $http_code = (int) ($del_res['http_code'] ?? 0);
                $is_already_gone = ($http_code === 404 || ($del_res['errors'][0]['code'] ?? 0) === 10002);

                if (!empty($del_res['success']) || $is_already_gone) {
                    unset($active_bans[$ip]);
                    update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                    return true;
                }

                $meta['unban_status']     = 'unban_retry';
                $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'Zone rule DELETE failed';
                $active_bans[$ip]         = $meta;
                update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                return false;
            }

            $search = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules?configuration.value=" . rawurlencode($ip));
            if (!empty($search['success']) && !empty($search['result']) && is_array($search['result'])) {
                $all_deleted = true;
                foreach ($search['result'] as $r) {
                    if (!empty($r['id'])) {
                        $dr = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$r['id']}", 'DELETE');
                        if (empty($dr['success']) && (int) ($dr['http_code'] ?? 0) !== 404) {
                            $all_deleted = false;
                        }
                    }
                }
                if ($all_deleted) {
                    unset($active_bans[$ip]);
                    update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                    return true;
                }

                $meta['unban_status'] = 'unban_retry';
                $active_bans[$ip] = $meta;
                update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
                return false;
            }

            // Not found in zone rules
            unset($active_bans[$ip]);
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
            return true;
        }

        return true;
    }

    /**
     * Poll a bulk operation status from Cloudflare Account API.
     *
     * @param string $account_id
     * @param string $operation_id
     * @return string 'completed' | 'running' | 'failed' | 'pending'
     */
    public static function poll_bulk_operation(string $account_id, string $operation_id): string {
        $res = CloudflareService::request("accounts/{$account_id}/rules/lists/bulk_operations/{$operation_id}");
        if (!empty($res['success']) && !empty($res['result']['status'])) {
            return (string) $res['result']['status'];
        }

        return 'failed';
    }

    /**
     * Record a pending async bulk operation in local database ledger.
     *
     * @param string $operation_id
     * @param string $account_id
     * @param string $list_id
     * @param string $type 'create' | 'delete'
     * @param array<string> $ips
     */
    public static function record_pending_operation(
        string $operation_id,
        string $account_id,
        string $list_id,
        string $type,
        array $ips
    ): void {
        $ops = get_option(self::OPTION_PENDING_OPERATIONS, []);
        $ops = is_array($ops) ? $ops : [];

        $ops[$operation_id] = [
            'operation_id' => $operation_id,
            'account_id'   => $account_id,
            'list_id'      => $list_id,
            'type'         => $type,
            'ips'          => $ips,
            'status'       => 'running',
            'created_at'   => time(),
            'updated_at'   => time(),
        ];

        update_option(self::OPTION_PENDING_OPERATIONS, $ops, false);
    }

    /**
     * Reconcile all pending async bulk operations.
     * Called during periodic sync cron.
     */
    public function reconcile_pending_operations(): void {
        $ops = get_option(self::OPTION_PENDING_OPERATIONS, []);
        if (empty($ops) || !is_array($ops)) {
            return;
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        $active_bans = is_array($active_bans) ? $active_bans : [];
        $ops_modified = false;
        $bans_modified = false;

        foreach ($ops as $op_id => $op_meta) {
            $status = (string) ($op_meta['status'] ?? 'running');
            if ($status === 'completed' || $status === 'failed' || $status === 'failed_terminal') {
                // Drop operations older than 24 hours
                if (time() - (int) ($op_meta['updated_at'] ?? 0) > 86400) {
                    unset($ops[$op_id]);
                    $ops_modified = true;
                }
                continue;
            }

            $account_id = (string) ($op_meta['account_id'] ?? '');
            $list_id    = (string) ($op_meta['list_id'] ?? '');
            $type       = (string) ($op_meta['type'] ?? 'delete');
            $ips        = (array) ($op_meta['ips'] ?? []);

            // Central Polling Invariant: Only poll when a valid Cloudflare operation_id exists.
            // If operation is in awaiting_list_verification state or lacks an operation_id,
            // bypass bulk-operation polling and directly perform list item verification (never fall back to ledger key $op_id).
            $poll_id = !empty($op_meta['operation_id']) ? (string) $op_meta['operation_id'] : '';
            if ($status === 'awaiting_list_verification' || $poll_id === '') {
                $current_status = 'completed';
            } else {
                $current_status = self::poll_bulk_operation($account_id, $poll_id);
            }

            if ($current_status === 'completed') {
                if ($type === 'delete') {
                    $unresolved_deletes = [];
                    $confirmed_present_items = []; // [['id' => $item_id, 'ip' => $ip]]
                    $has_unknown_verification = false;
                    $retry_count = (int) ($op_meta['retry_count'] ?? 0);

                    foreach ($ips as $ip) {
                        // PR-A2: Explicit tri-state verification: 'confirmed_absent', 'confirmed_present', 'verification_unknown'
                        $verify_res = CloudflareService::request("accounts/{$account_id}/rules/lists/{$list_id}/items?search=" . rawurlencode($ip));
                        $verify_state = 'verification_unknown';
                        $found_item_id = '';

                        if (!empty($verify_res['success']) && isset($verify_res['result']) && is_array($verify_res['result'])) {
                            $found = false;
                            foreach ($verify_res['result'] as $v_item) {
                                if (($v_item['ip'] ?? '') === $ip) {
                                    $found = true;
                                    $found_item_id = (string) ($v_item['id'] ?? '');
                                    break;
                                }
                            }
                            $verify_state = $found ? 'confirmed_present' : 'confirmed_absent';
                        }

                        // Only remove from active ledger on confirmed absence from a successful API verification
                        if ($verify_state === 'confirmed_absent') {
                            unset($active_bans[$ip]);
                            $bans_modified = true;
                        } elseif ($verify_state === 'confirmed_present') {
                            $delete_item_id = $found_item_id !== '' ? $found_item_id : (string) ($active_bans[$ip]['item_id'] ?? '');
                            if (!empty($delete_item_id)) {
                                $confirmed_present_items[] = ['id' => $delete_item_id, 'ip' => $ip];
                            }
                            $unresolved_deletes[] = $ip;
                        } else { // verification_unknown
                            $has_unknown_verification = true;
                            $unresolved_deletes[] = $ip;
                        }
                    }

                    // If items are confirmed present and under the retry limit, submit a single consolidated batch DELETE
                    $submitted_new_delete = false;
                    if (!empty($confirmed_present_items)) {
                        if ($retry_count < 5) {
                            $batch_items = array_map(static fn(array $item): array => ['id' => $item['id']], $confirmed_present_items);
                            $fresh_del_res = CloudflareService::request(
                                "accounts/{$account_id}/rules/lists/{$list_id}/items",
                                'DELETE',
                                ['items' => $batch_items]
                            );
                            if (!empty($fresh_del_res['success'])) {
                                $new_op_id = (string) ($fresh_del_res['result']['operation_id'] ?? '');
                                if (!empty($new_op_id)) {
                                    $op_meta['operation_id'] = $new_op_id;
                                    $op_meta['status'] = 'running';
                                    $retry_count++;
                                    $op_meta['retry_count'] = $retry_count;
                                    $submitted_new_delete = true;
                                } else {
                                    // P2: Success without operation_id: enter awaiting_list_verification state
                                    // Bypasses stale operation ID polling and performs direct list verification on next tick
                                    $op_meta['status'] = 'awaiting_list_verification';
                                    $op_meta['last_error'] = 'Cloudflare batch DELETE succeeded without operation_id';
                                    unset($op_meta['operation_id']); // Do not poll stale completed ID
                                    if (class_exists('\\WebCareProScanner\\Audit\\AuditLogger')) {
                                        \WebCareProScanner\Audit\AuditLogger::log_event(
                                            'CF_ASYNC_DELETE_MISSING_OP_ID',
                                            'Cloudflare batch DELETE succeeded without operation_id. Scheduled direct list verification on next tick.'
                                        );
                                    }
                                }
                            } else {
                                $op_meta['status'] = 'awaiting_list_verification';
                                $op_meta['last_error'] = 'Cloudflare batch DELETE request failed';
                                unset($op_meta['operation_id']); // Ensure it never falls back to polling a stale ledger key
                            }
                        } else {
                            // Already submitted 5 attempts, and verification still confirmed items present
                            $op_meta['status'] = 'failed_terminal';
                            if (class_exists('\\WebCareProScanner\\Audit\\AuditLogger')) {
                                \WebCareProScanner\Audit\AuditLogger::log_event(
                                    'CF_ASYNC_DELETE_FAILED_TERMINAL',
                                    sprintf('Cloudflare async delete reached max retry limit (5) with %d confirmed present IP(s): %s', count($confirmed_present_items), implode(', ', array_column($confirmed_present_items, 'ip')))
                                );
                            }
                        }
                    } elseif ($has_unknown_verification) {
                        // P1: verification_unknown does not count as a completed unsuccessful delete attempt
                        // Retain operation for retry verification without incrementing retry_count or terminating.
                        // Preserve awaiting_list_verification whenever there is no valid operation_id.
                        $op_meta['status'] = empty($op_meta['operation_id']) ? 'awaiting_list_verification' : 'running';
                    }

                    // Keep delete operation pending for retry if any IP is still unresolved
                    if (!empty($unresolved_deletes)) {
                        $op_meta['ips'] = $unresolved_deletes;
                        $op_meta['updated_at'] = time();

                        $ops[$op_id] = $op_meta;
                        $ops_modified = true;
                        continue;
                    }
                } elseif ($type === 'create') {
                    // Fetch list items with cursor-based pagination to resolve and persist exact item_id for created items
                    $target_map = array_fill_keys($ips, true);
                    $resolved_ips = [];
                    $cursor = (string) ($op_meta['last_cursor'] ?? '');
                    $max_pages = 10;
                    $page_count = 0;

                    do {
                        $endpoint = "accounts/{$account_id}/rules/lists/{$list_id}/items?per_page=100";
                        if (!empty($cursor)) {
                            $endpoint .= '&cursor=' . rawurlencode($cursor);
                        }

                        $list_items_res = CloudflareService::request($endpoint);
                        $page_count++;

                        if (!empty($list_items_res['success']) && !empty($list_items_res['result']) && is_array($list_items_res['result'])) {
                            foreach ($list_items_res['result'] as $l_item) {
                                $l_ip = (string) ($l_item['ip'] ?? '');
                                $l_id = (string) ($l_item['id'] ?? '');
                                if (!empty($l_ip) && !empty($l_id) && isset($target_map[$l_ip])) {
                                    $entry = $active_bans[$l_ip] ?? [];
                                    $entry['target']     = $l_ip;
                                    $entry['mode']       = 'account';
                                    $entry['item_id']    = $l_id;
                                    $entry['state']      = 'active';
                                    $entry['synced_at']  = time();
                                    unset($entry['operation_id']);
                                    $active_bans[$l_ip]  = $entry;
                                    $bans_modified       = true;
                                    $resolved_ips[$l_ip] = true;
                                }
                            }

                            // Advance cursor if more items remain and unresolved targets exist
                            $cursor = (string) ($list_items_res['result_info']['cursors']['after'] ?? '');
                            if (count($resolved_ips) >= count($ips)) {
                                break;
                            }
                        } else {
                            break;
                        }
                    } while (!empty($cursor) && $page_count < $max_pages);

                    // If not all IPs were resolved, retain only unresolved IPs for retry and persist last_cursor
                    if (count($resolved_ips) < count($ips)) {
                        $unresolved = array_values(array_filter($ips, static fn($ip) => !isset($resolved_ips[$ip])));
                        $op_meta['ips'] = $unresolved;
                        if (!empty($cursor)) {
                            $op_meta['last_cursor'] = $cursor;
                        } else {
                            unset($op_meta['last_cursor']);
                        }
                        $op_meta['updated_at'] = time();
                        $ops[$op_id] = $op_meta;
                        $ops_modified = true;
                        continue;
                    }

                    unset($op_meta['last_cursor']);
                }
                $op_meta['status'] = 'completed';
                $op_meta['updated_at'] = time();
                $ops[$op_id] = $op_meta;
                $ops_modified = true;
            } elseif ($current_status === 'failed') {
                // PR-A2: When pending create fails, re-queue IPs in OPTION_BAN_QUEUE and clean up incomplete pending_create ledger entries
                if ($type === 'create') {
                    $now = time();
                    self::mutate_ban_queue(static function (array $queue) use ($ips, $now): array {
                        foreach ($ips as $f_ip) {
                            $existing = $queue[$f_ip] ?? [];
                            $attempts = ((int) ($existing['attempts'] ?? 0)) + 1;
                            $queue[$f_ip] = [
                                'ip'         => $f_ip,
                                'reason'     => (string) ($existing['reason'] ?? 'WebCare Threat Block (Async Retry)'),
                                'status'     => ($attempts >= 5) ? 'failed' : 'retry',
                                'attempts'   => $attempts,
                                'next_retry' => $now + min(3600, 30 * (2 ** $attempts)),
                                'last_error' => 'Async bulk create operation failed',
                            ];
                        }
                        return $queue;
                    });

                    foreach ($ips as $f_ip) {
                        if (isset($active_bans[$f_ip]) && ($active_bans[$f_ip]['state'] ?? '') === 'pending_create') {
                            unset($active_bans[$f_ip]);
                            $bans_modified = true;
                        }
                    }
                }
                $op_meta['status'] = 'failed';
                $op_meta['updated_at'] = time();
                $ops[$op_id] = $op_meta;
                $ops_modified = true;
            }
        }

        if ($ops_modified) {
            update_option(self::OPTION_PENDING_OPERATIONS, $ops, false);
        }
        if ($bans_modified) {
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
        }
    }

    /**
     * Register asynchronous sync cron hook and AJAX loopback handler.
     */
    public static function register_cron(): void {
        if (class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter')) {
            add_action(self::CRON_HOOK, static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::invoke_task_handler(self::CRON_HOOK, 'wp_cron');
            });

            add_action('init', static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::ensure_scheduled(self::CRON_HOOK, 300, 'webcare_every_five_minutes');
            }, 20);
        } else {
            add_action(self::CRON_HOOK, static function () {
                $sync = new self();
                $sync->process_sync_queue();
            });

            if (!wp_next_scheduled(self::CRON_HOOK)) {
                wp_schedule_event(time() + 300, 'webcare_every_five_minutes', self::CRON_HOOK);
            }
        }

        // Loopback AJAX handler for high-velocity queue flushing
        add_action('wp_ajax_nopriv_webcare_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);
        add_action('wp_ajax_webcare_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);
    }

    /**
     * Handle non-blocking loopback queue flush request.
     */
    public static function handle_loopback_flush(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        $parts = explode(':', $token, 3);
        if (count($parts) !== 3) {
            wp_send_json_error(['message' => 'Malformed loopback token.'], 403);
        }

        [$timestamp, $rand_nonce, $sig] = $parts;
        $now = time();
        if (abs($now - (int) $timestamp) > 300) {
            \wp_send_json_error(['message' => 'Expired loopback token.'], 403);
        }

        $salt = class_exists(\WebCareProScanner\Security\SecretVault::class)
            ? \WebCareProScanner\Security\SecretVault::get_key()
            : (function_exists('wp_salt') ? wp_salt('auth') : '');
        if ($salt === '') {
            \wp_send_json_error(['message' => 'Secret vault unavailable.'], 403);
        }
        $expected_sig = hash_hmac('sha256', "cf_flush|{$timestamp}|{$rand_nonce}", $salt);
        if (!hash_equals($expected_sig, $sig)) {
            \wp_send_json_error(['message' => 'Invalid loopback signature.'], 403);
        }

        // Prevent replay attacks by consuming nonce atomically
        if (!class_exists(\WebCareProScanner\Security\AtomicNonceStore::class) || !\WebCareProScanner\Security\AtomicNonceStore::consume('cf_flush', $rand_nonce, 300)) {
            \wp_send_json_error(['message' => 'Replayed or invalid loopback token.'], 403);
        }

        $sync = new self();
        $sync->process_sync_queue();
        \wp_send_json_success(['flushed' => true]);
    }
}
