<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RuntimeSqlRaspEngine
 *
 * Hooks WordPress's `query` filter strictly for unauthenticated guest requests hitting
 * AJAX / non-core REST / custom plugin entrypoints to abort zero-day SQL injection AST anomalies
 * before MySQL executes them.
 */
class RuntimeSqlRaspEngine implements SecurityModuleInterface {

    const OPTION_EVENTS = 'webcareproscan_sql_rasp_events';

    /** @var bool Prevent recursive option updates while inside query filter */
    private static bool $in_guard = false;

    public function get_id(): string {
        return 'runtime-sql-rasp';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security'),
            'description' => __('Inspects live database queries during unauthenticated plugin/AJAX/REST requests to neutralize zero-day blind and second-order SQL injections before execution.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_sql_rasp_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Next-Gen RASP',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_filter('query', [__CLASS__, 'inspect_guest_sql_query'], 1);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_sql_rasp_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security'),
            ],
            'waf_nextgen_sql_rasp_auto_ban' => [
                'default' => false,
                'type'    => 'bool',
                'label'   => __('Auto-Ban SQL RASP Offenders on Cloudflare Edge', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/sql-rasp-events',
                'methods'  => 'GET',
                'callback' => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return new \WP_REST_Response([
                        'success' => true,
                        'events'  => is_array($events) ? $events : [],
                    ], 200);
                },
            ],
        ];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_sql_rasp_events',
                'description' => 'List intercepted zero-day SQL injection AST anomalies caught inside WordPress query RASP.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return [
                        'isError' => false,
                        'content' => [[
                            'type' => 'text',
                            'text' => (string) wp_json_encode(['events' => is_array($events) ? $events : []]),
                        ]],
                    ];
                },
            ],
        ];
    }

    /**
     * Evaluate whether current request satisfies the strict 3-gate guest plugin surface check.
     * Always evaluates zero-cost URI and runtime checks BEFORE invoking WordPress user/DB lookups.
     */
    public static function is_guest_plugin_surface(): bool {
        if ((defined('WP_CLI') && WP_CLI) || (function_exists('wp_doing_cron') && wp_doing_cron()) || (function_exists('wp_installing') && wp_installing())) {
            return false;
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only surface routing check inside RASP guard
        $uri = strtolower((string) wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
        $is_target_surface = (
            strpos($uri, 'admin-ajax.php') !== false
            || strpos($uri, 'admin-post.php') !== false
            || strpos($uri, 'rest_route=') !== false
            || (strpos($uri, '/wp-json/') !== false && strpos($uri, '/wp-json/webcare-pro-security/') === false)
        );
        if (!$is_target_surface) {
            return false;
        }

        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return false;
        }
        if (class_exists(FirewallEngine::class)) {
            if (FirewallEngine::is_authenticated_administrator() || FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Pure testable SQL AST anomaly analyzer (strips quoted literals before structural checks).
     *
     * @param string $sql
     * @return string|null Anomaly identifier if dangerous AST construct found, null otherwise.
     */
    public static function detect_sql_anomaly(string $sql): ?string {
        global $wpdb;

        $trimmed = trim($sql);
        if ($trimmed === '') {
            return null;
        }

        $users_tbl    = isset($wpdb->users) ? preg_quote($wpdb->users, '/') : 'wp_users';
        $usermeta_tbl = isset($wpdb->usermeta) ? preg_quote($wpdb->usermeta, '/') : 'wp_usermeta';
        $options_tbl  = isset($wpdb->options) ? preg_quote($wpdb->options, '/') : 'wp_options';
        $posts_tbl    = isset($wpdb->posts) ? preg_quote($wpdb->posts, '/') : 'wp_posts';

        // Never block WebCare's own internal queries or standard WP transient writes
        if (stripos($trimmed, 'webcareproscan_') !== false || stripos($trimmed, 'SELECT NULL WHERE 1=0') === 0) {
            return null;
        }

        // Strip balanced string literals to prevent false positives on blog/post text content
        $skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $trimmed);

        // 1. Cross-table UNION SELECT touching credential/usermeta tables
        if (preg_match('/\bUNION\s+(?:ALL\s+)?SELECT\b/i', $skeleton) && preg_match('/\b(?:' . $users_tbl . '|' . $usermeta_tbl . ')\b/i', $skeleton)) {
            return 'UNION_SELECT_CREDENTIAL_TABLE';
        }

        // 2. INFORMATION_SCHEMA metadata probing or time/file SQLi primitives in unquoted SQL skeleton
        if (preg_match('/\bINFORMATION_SCHEMA\.(?:TABLES|COLUMNS|SCHEMATA|USER_PRIVILEGES)\b/i', $skeleton)) {
            return 'INFORMATION_SCHEMA_PROBE';
        }
        if (preg_match('/\b(?:SLEEP|BENCHMARK)\s*\(/i', $skeleton)) {
            return 'TIME_BLIND_SQL_FUNCTION';
        }
        if (preg_match('/\bLOAD_FILE\s*\(/i', $skeleton) || preg_match('/\bINTO\s+(?:OUT|DUMP)FILE\b/i', $skeleton)) {
            return 'FILE_IO_SQLI_PRIMITIVE';
        }

        // 3. Unauthenticated critical privilege mutations inside guest plugin contexts
        if (preg_match('/^\s*(?:INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+`?' . $users_tbl . '`?\b/i', $skeleton)) {
            if (self::is_legitimate_users_table_mutation($trimmed)) {
                return null;
            }
            return 'UNAUTH_USERS_TABLE_MUTATION';
        }
        if (
            preg_match('/^\s*UPDATE\s+`?' . $options_tbl . '`?\s+SET\b/i', $skeleton)
            && preg_match('/\b(?:siteurl|home|users_can_register|default_role|active_plugins|admin_email)\b/i', $trimmed)
        ) {
            return 'UNAUTH_CRITICAL_OPTION_SQL_MUTATION';
        }
        if (preg_match('/^\s*DELETE\s+FROM\s+`?' . $posts_tbl . '`?\b/i', $skeleton) && stripos($skeleton, 'WHERE') === false) {
            return 'UNAUTH_MASS_POST_DELETE';
        }

        return null;
    }

    /**
     * Multi-factor verification for legitimate user registrations, password resets,
     * and guest checkout mutations on $wpdb->users.
     *
     * @param string $sql
     * @return bool
     */
    public static function is_legitimate_users_table_mutation(string $sql): bool {
        // 1. Verify caller provenance: immediate caller invoking $wpdb must be Core or WooCommerce user engine
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Provenance validation for RASP
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        $origin_frame = null;

        // Skip internal RASP, WAF, and $wpdb database frames to locate the true SQL originator
        foreach ($frames as $frame) {
            $file = isset($frame['file']) ? wp_normalize_path((string) $frame['file']) : '';
            if ($file === '') {
                continue;
            }
            if (
                strpos($file, '/includes/Firewall/') !== false
                || strpos($file, '/wp-includes/class-wpdb.php') !== false
                || strpos($file, '/wp-includes/wp-db.php') !== false
            ) {
                continue;
            }
            $origin_frame = $frame;
            break;
        }

        if (!$origin_frame || !isset($origin_frame['file'])) {
            return false;
        }

        $origin_file = wp_normalize_path((string) $origin_frame['file']);

        // The query MUST be directly executed by WordPress Core user functions or WooCommerce user data stores
        $is_core_origin = (
            strpos($origin_file, '/wp-includes/user.php') !== false
            || strpos($origin_file, '/wp-includes/pluggable.php') !== false
        );

        $is_wc_origin = (
            strpos($origin_file, '/plugins/woocommerce/includes/wc-user-functions.php') !== false
            || strpos($origin_file, '/plugins/woocommerce/includes/data-stores/class-wc-customer-data-store') !== false
            || strpos($origin_file, '/plugins/woocommerce/packages/') !== false
            || strpos($origin_file, '/plugins/woocommerce/src/StoreApi/') !== false
        );

        if (!$is_core_origin && !$is_wc_origin) {
            // Origin was a third-party plugin callback or non-core file
            return false;
        }

        // 2. Allowed column boundaries for legitimate user creation/update
        $allowed_columns = [
            'user_login',
            'user_pass',
            'user_nicename',
            'user_email',
            'user_url',
            'user_registered',
            'user_activation_key',
            'user_status',
            'display_name',
            'id',
        ];

        // Reject any query containing subqueries, UNIONs, stacked statements, or dangerous system functions
        $skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $sql);
        if (preg_match('/\b(?:SELECT|UNION|BENCHMARK|SLEEP|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b|;/i', $skeleton)) {
            return false;
        }

        // 3. Inspect columns and enforce single-row tuple in INSERT query
        if (preg_match('/^\s*INSERT\s+INTO\s+`?[a-zA-Z0-9_]+`?\s*\(([^)]+)\)\s*VALUES\s*(.+)$/is', $sql, $insert_matches)) {
            $cols = array_map(function ($c) {
                return strtolower(trim(str_replace('`', '', $c)));
            }, explode(',', $insert_matches[1]));

            foreach ($cols as $col) {
                if (!in_array($col, $allowed_columns, true)) {
                    return false;
                }
            }

            // Enforce single-row INSERT: reject multiple value tuples like `(...), (...)`
            $values_clause = trim($insert_matches[2]);
            $values_skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $values_clause);
            if (preg_match('/\)\s*,\s*\(/', $values_skeleton)) {
                return false;
            }
            if (!preg_match('/^\s*\([^()]+\)\s*;?\s*$/', $values_skeleton)) {
                return false;
            }

            return true;
        }

        // 4. Require an explicit, strictly bounded single-row WHERE clause on all UPDATE statements
        if (preg_match('/^\s*UPDATE\s+`?[a-zA-Z0-9_]+`?\s+SET\s+(.+?)\s+WHERE\s+(.+)$/is', $sql, $update_matches)) {
            $set_clause_raw   = $update_matches[1];
            $where_clause_raw = trim($update_matches[2]);

            // Strip trailing semicolons
            $where_clause_raw = rtrim($where_clause_raw, ';');

            // Skeleton of WHERE clause with strings stripped for syntax checks
            $where_skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $where_clause_raw);

            // Reject tautologies, range expansions, inequalities, comments, and multi-record predicates
            if (preg_match('/\b(?:1\s*=\s*1|0\s*=\s*0|true|null\s+is\s+null)\b|--|\/\*|\bOR\b|!=|<>|>|<|\bLIKE\b|\bNOT\b|\bIN\b|\bBETWEEN\b/i', $where_skeleton)) {
                return false;
            }

            // Single-row uniqueness constraint: ONLY `ID` / `id` (PRIMARY KEY) or `user_login` (UNIQUE constraint).
            // Reject non-unique columns like user_email and user_activation_key which lack unique schema constraints.
            if (!preg_match('/^\s*`?(ID|id|user_login)`?\s*=\s*(.+?)(?:\s+LIMIT\s+\d+)?\s*$/i', $where_clause_raw, $pred_matches)) {
                return false;
            }

            $pred_col = strtolower($pred_matches[1]);
            $pred_val = trim($pred_matches[2]);

            // Validate that the predicate target value is non-empty, strictly typed, and bounds exactly one row:
            if ($pred_col === 'id') {
                // Must be a positive integer > 0 (WordPress user IDs start at 1)
                if (!preg_match('/^[1-9]\d*$/', $pred_val)) {
                    return false;
                }
            } elseif ($pred_col === 'user_login') {
                // Must be a non-empty string literal or prepared statement placeholder (%s or ?)
                if ($pred_val === '%s' || $pred_val === '?') {
                    // Valid prepared statement placeholder
                } elseif (preg_match('/^\'([^\'\\\\]+)\'$/', $pred_val, $login_match)) {
                    if (trim($login_match[1]) === '') {
                        return false;
                    }
                } elseif (preg_match('/^"([^"\\\\]+)"$/', $pred_val, $login_match)) {
                    if (trim($login_match[1]) === '') {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }

            // Inspect columns in SET clause
            $set_skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $set_clause_raw);
            if (preg_match_all('/`?([a-zA-Z0-9_]+)`?\s*=/i', $set_skeleton, $col_matches) && !empty($col_matches[1])) {
                foreach ($col_matches[1] as $col) {
                    if (!in_array(strtolower($col), $allowed_columns, true)) {
                        return false;
                    }
                }

                // 5. Target User Boundary & Registration Window (during unauthenticated guest sessions)
                if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
                    if ($pred_col === 'id') {
                        $target_id = (int) $pred_val;
                        if (function_exists('get_userdata')) {
                            $target_user = get_userdata($target_id);
                            if ($target_user instanceof \WP_User) {
                                if (
                                    $target_user->has_cap('manage_options')
                                    || $target_user->has_cap('administrator')
                                    || (class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role((string) ($target_user->roles[0] ?? '')))
                                ) {
                                    return false;
                                }

                                $reg_ts = strtotime((string) $target_user->user_registered);
                                if ($reg_ts && (time() - $reg_ts) > 120) {
                                    return false;
                                }
                            }
                        }
                    } elseif ($pred_col === 'user_login') {
                        $login_val = trim($pred_val, "'\"");
                        if (function_exists('get_user_by')) {
                            $target_user = get_user_by('login', $login_val);
                            if ($target_user instanceof \WP_User) {
                                if (
                                    $target_user->has_cap('manage_options')
                                    || $target_user->has_cap('administrator')
                                    || (class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role((string) ($target_user->roles[0] ?? '')))
                                ) {
                                    return false;
                                }

                                $reg_ts = strtotime((string) $target_user->user_registered);
                                if ($reg_ts && (time() - $reg_ts) > 120) {
                                    return false;
                                }
                            }
                        }
                    }
                }

                return true;
            }
        }

        return false;
    }

    /**
     * WordPress `query` filter callback aborting dangerous guest plugin SQL queries before MySQL executes them.
     *
     * @param string $query
     * @return string
     */
    public static function inspect_guest_sql_query(string $query): string {
        if (self::$in_guard) {
            return $query;
        }

        self::$in_guard = true;
        try {
            if (!self::is_guest_plugin_surface()) {
                return $query;
            }

            $anomaly = self::detect_sql_anomaly($query);
            if ($anomaly === null) {
                return $query;
            }

            $caller = self::resolve_culprit_caller();
            $ip     = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : '127.0.0.1';
            $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

            $rule_id = 'WAF-SQL-RASP-' . $anomaly;
            $reason  = sprintf('Runtime SQL RASP aborted anomalous guest query (%s) originating from %s', $anomaly, $caller);

            self::record_event($ip, $anomaly, $caller, $uri);

            if (class_exists(FirewallEngine::class)) {
                FirewallEngine::log_incident([
                    'id'          => $rule_id,
                    'name'        => 'Runtime SQL Query AST RASP Guard',
                    'category'    => 'Next-Gen SQL RASP Defense',
                    'description' => $reason,
                    'match_type'  => 'SQL AST Anomaly',
                    'match_value' => $anomaly,
                    'payload'     => "Caller: {$caller} URI: {$uri}",
                ], 'blocked');

                $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                    ? \WebCareProScanner\System\SettingsManager::get_settings()
                    : [];
                if (!empty($settings['waf_nextgen_sql_rasp_auto_ban']) && !FirewallEngine::is_server_origin_or_loopback($ip)) {
                    FirewallEngine::add_blocked_ip(
                        $ip,
                        $reason,
                        86400,
                        $rule_id,
                        'Runtime SQL RASP Guard',
                        'Next-Gen SQL RASP Defense',
                        null,
                        null,
                        true
                    );
                }
            }
        } finally {
            self::$in_guard = false;
        }

        // Safely neutralize execution in MySQL without risking table corruption
        return 'SELECT NULL WHERE 1=0';
    }

    /**
     * Resolve first plugin/theme frame from debug_backtrace for attribution.
     */
    private static function resolve_culprit_caller(): string {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Security forensics attribution to pinpoint vulnerable plugin file on blocked SQLi query
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15);
        foreach ($frames as $frame) {
            $file = isset($frame['file']) ? wp_normalize_path((string) $frame['file']) : '';
            if ($file === '' || strpos($file, 'wcp-security-scanner') !== false || strpos($file, 'webcare-pro-security') !== false) {
                continue;
            }
            if (strpos($file, '/wp-content/plugins/') !== false || strpos($file, '/wp-content/themes/') !== false) {
                $rel  = preg_replace('#^.*/wp-content/#', 'wp-content/', $file);
                $line = intval($frame['line'] ?? 0);
                return $rel . ':' . $line;
            }
        }
        return 'wp-content/unknown';
    }

    /**
     * Record bounded RASP telemetry history.
     */
    private static function record_event(string $ip, string $anomaly, string $caller, string $uri): void {
        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }
        array_unshift($events, [
            'timestamp' => time(),
            'ip'        => sanitize_text_field($ip),
            'anomaly'   => sanitize_key($anomaly),
            'caller'    => sanitize_text_field($caller),
            'uri'       => sanitize_text_field(substr($uri, 0, 160)),
        ]);
        if (count($events) > 50) {
            $events = array_slice($events, 0, 50);
        }
        update_option(self::OPTION_EVENTS, $events, false);
    }
}
