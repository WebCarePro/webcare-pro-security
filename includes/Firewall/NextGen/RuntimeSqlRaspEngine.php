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

    /** @var int Internal query re-entrancy depth counter */
    private static int $internal_query_depth = 0;

    /** @var array<int, array{hash: string, timestamp: int}> Bound authentication records for password rehash */
    private static array $verified_password_users = [];

    /** @var array<int, array{activation_key: string, timestamp: int}> Bound authentication records for password reset */
    private static array $verified_reset_users = [];

    public static function reset_runtime_auth_state(): void {
        self::$verified_password_users = [];
        self::$verified_reset_users    = [];
        self::$internal_query_depth    = 0;
    }

    /**
     * Safely execute an internal query closure with re-entrancy depth tracking.
     * Queries executed within this callback bypass SQL RASP without fragile substring heuristics.
     *
     * @template T
     * @param callable(): T $callback
     * @return T
     */
    public static function run_internal_query(callable $callback): mixed {
        self::$internal_query_depth++;
        try {
            return $callback();
        } finally {
            if (self::$internal_query_depth > 0) {
                self::$internal_query_depth--;
            }
        }
    }

    public static function get_verified_password_user(int $uid): ?array {
        return self::$verified_password_users[$uid] ?? null;
    }

    public function get_id(): string {
        return 'runtime-sql-rasp';
    }

    public function get_enable_key(): string {
        return 'waf_nextgen_sql_rasp_enabled';
    }

    public function get_manifest(): array {
        return [
            'title'       => did_action('init') ? __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security') : 'Runtime SQL Query AST RASP Guard',
            'description' => did_action('init') ? __('Inspects live database queries during unauthenticated plugin/AJAX/REST requests to neutralize zero-day blind and second-order SQL injections before execution.', 'webcare-pro-security') : 'Inspects live database queries during unauthenticated plugin/AJAX/REST requests to neutralize zero-day blind and second-order SQL injections before execution.',
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_sql_rasp_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-firewall&tab=protection',
            'badge'       => 'Next-Gen RASP',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_filter('query', [__CLASS__, 'inspect_guest_sql_query'], 1);
        add_filter('check_password', [__CLASS__, 'observe_verified_password_check'], 9999, 4);
        add_action('validate_password_reset', [__CLASS__, 'observe_verified_password_reset'], 1, 2);
    }

    /**
     * Record when WordPress Core verifies a user's password during authentic authentication.
     * Validates caller provenance to prevent third-party plugins from forging authentication events.
     *
     * @param bool       $check
     * @param string     $password
     * @param string     $hash
     * @param int|string $user_id
     * @return bool
     */
    public static function observe_verified_password_check($check, $password, $hash, $user_id = 0) {
        if ($check !== true || !is_numeric($user_id) || (int) $user_id <= 0 || !is_string($hash) || $hash === '') {
            return $check;
        }

        $uid = (int) $user_id;

        // Password rehash is only performed by WordPress Core if the hash actually needs rehashing.
        // In WordPress 6.8+, wp_password_needs_rehash($hash, $user_id) evaluates whether a hash needs migrating to modern bcrypt ($wp).
        // If wp_password_needs_rehash does not exist or returns false, Core will never invoke wp_set_password. Fail closed.
        if (!function_exists('wp_password_needs_rehash') || !wp_password_needs_rehash($hash, $uid)) {
            return $check;
        }

        // Verify caller provenance: MUST be invoked by WordPress Core's wp_check_password()
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Cryptographic caller verification
        $frames              = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8);
        $own_file            = wp_normalize_path(__FILE__);
        $canonical_pluggable = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/pluggable.php') : '';
        $canonical_hook      = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/class-wp-hook.php') : '';
        $canonical_plugin    = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/plugin.php') : '';
        $is_core_caller      = false;

        for ($i = 0; $i < count($frames); $i++) {
            $file = isset($frames[$i]['file']) ? wp_normalize_path((string) $frames[$i]['file']) : '';

            // Skip observer's own frame if present
            if ($file === $own_file) {
                continue;
            }

            // Skip WordPress hook dispatcher frames
            if ($file === $canonical_hook || $file === $canonical_plugin) {
                continue;
            }

            // The direct caller invoking apply_filters('check_password', ...) must be exact canonical wp-includes/pluggable.php
            if ($canonical_pluggable !== '' && $file === $canonical_pluggable) {
                $is_core_caller = true;
                break;
            }

            // If any other file (such as a third-party plugin or spoofed path) invoked the filter, reject immediately
            break;
        }

        if (!$is_core_caller) {
            return $check;
        }

        // Verify target user exists and the authenticated hash matches current user_pass
        $target_user = function_exists('get_userdata') ? get_userdata($uid) : null;
        if (!($target_user instanceof \WP_User) || !hash_equals((string) $target_user->user_pass, $hash)) {
            return $check;
        }

        // Bind one-time authorization record strictly to user ID, expected rehash operation, and authenticated hash
        self::$verified_password_users[$uid] = [
            'operation'     => 'password_rehash',
            'original_hash' => $hash,
            'timestamp'     => time(),
        ];

        return $check;
    }

    /**
     * Record when WordPress Core validates a password reset key for a target WP_User.
     * Validates caller provenance to prevent third-party plugins from forging reset events.
     *
     * @param \WP_Error          $errors
     * @param \WP_User|\WP_Error $user
     * @return void
     */
    public static function observe_verified_password_reset($errors, $user): void {
        if (!($user instanceof \WP_User) || (int) $user->ID <= 0 || ($errors instanceof \WP_Error && $errors->has_errors())) {
            return;
        }

        $uid          = (int) $user->ID;
        $existing_key = isset($user->user_activation_key) ? trim((string) $user->user_activation_key) : '';
        if ($existing_key === '') {
            return;
        }

        // Verify caller provenance: MUST originate from authentic Core wp-login.php, user.php, or WooCommerce
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Cryptographic caller verification
        $frames               = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8);
        $own_file             = wp_normalize_path(__FILE__);
        $canonical_hook       = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/class-wp-hook.php') : '';
        $canonical_plugin     = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/plugin.php') : '';
        $canonical_login      = defined('ABSPATH') ? wp_normalize_path(ABSPATH . 'wp-login.php') : '';
        $canonical_user       = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/user.php') : '';
        $canonical_wc_handler = defined('WP_PLUGIN_DIR') ? wp_normalize_path(WP_PLUGIN_DIR . '/woocommerce/includes/class-wc-form-handler.php') : '';
        $is_valid_caller      = false;

        for ($i = 0; $i < count($frames); $i++) {
            $file = isset($frames[$i]['file']) ? wp_normalize_path((string) $frames[$i]['file']) : '';

            // Skip observer's own frame if present
            if ($file === $own_file) {
                continue;
            }

            // Skip WordPress hook dispatcher frames
            if ($file === $canonical_hook || $file === $canonical_plugin) {
                continue;
            }

            if (
                ($canonical_login !== '' && $file === $canonical_login)
                || ($canonical_user !== '' && $file === $canonical_user)
                || ($canonical_wc_handler !== '' && $file === $canonical_wc_handler)
            ) {
                $is_valid_caller = true;
                break;
            }

            // If any other file (such as a third-party plugin or spoofed path) invoked the hook, reject immediately
            break;
        }

        if (!$is_valid_caller) {
            return;
        }

        // Bind one-time authorization record to user ID and exact activation key
        self::$verified_reset_users[$uid] = [
            'activation_key' => $existing_key,
            'timestamp'      => time(),
        ];
    }

    public function get_settings_defaults(): array {
        return [
            'waf_nextgen_sql_rasp_enabled'  => true,
            'waf_nextgen_sql_rasp_auto_ban' => false,
        ];
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_sql_rasp_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security') : 'Runtime SQL Query AST RASP Guard',
            ],
            'waf_nextgen_sql_rasp_auto_ban' => [
                'default' => false,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('Auto-Ban SQL RASP Offenders on Cloudflare Edge', 'webcare-pro-security') : 'Auto-Ban SQL RASP Offenders on Cloudflare Edge',
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

        // Loopback interfaces and host server outbound IP addresses are trusted internal surfaces, never guest visitors
        $client_ip = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '');
        if ($client_ip !== '') {
            if (in_array($client_ip, ['127.0.0.1', '::1'], true)) {
                return false;
            }
            if (class_exists(FirewallEngine::class)) {
                if (FirewallEngine::is_server_origin_or_loopback($client_ip) || FirewallEngine::is_ip_whitelisted($client_ip)) {
                    return false;
                }
            }
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw URI routing path requires multi-pass decoding without percent octet distortion
        $raw_request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $request_uri = str_replace(["\0", "\r", "\n"], '', $raw_request_uri);
        $request_path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '');
        $path_candidates = [$request_path];
        foreach (['PATH_INFO', 'PHP_SELF'] as $server_path_key) {
            if (isset($_SERVER[$server_path_key])) {
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Server routing paths require multi-pass decoding without percent octet distortion
                $server_val = str_replace(["\0", "\r", "\n"], '', (string) wp_unslash($_SERVER[$server_path_key]));
                if ($server_val !== '') {
                    $path_candidates[] = $server_val;
                }
            }
        }

        $normalized_paths = array_map(static function (string $path): string {
            $path = strtolower((string) (wp_parse_url($path, PHP_URL_PATH) ?? $path));
            $path = FirewallEngine::normalize_inspect_value($path);
            return (string) preg_replace('#/+#', '/', $path);
        }, $path_candidates);
        $has_ajax_surface = false;
        $has_rest_surface = false;
        $has_xmlrpc_surface = false;
        foreach ($normalized_paths as $path) {
            $has_ajax_surface = $has_ajax_surface || strpos($path, 'admin-ajax.php') !== false || strpos($path, 'admin-post.php') !== false;
            $has_rest_surface = $has_rest_surface || strpos($path, '/wp-json/') !== false;
            $has_xmlrpc_surface = $has_xmlrpc_surface || (bool) preg_match('#(?:^|/)xmlrpc\.php(?:/|$)#', $path);
        }

        $path_rest_route = '';
        foreach ($normalized_paths as $path) {
            if (preg_match('#/wp-json(/[^?]+)#i', $path, $route_match)) {
                $path_rest_route = '/' . trim($route_match[1], '/');
                break;
            }
        }
        $rest_route = $path_rest_route !== ''
            ? $path_rest_route
            : (class_exists(FirewallEngine::class) ? FirewallEngine::resolve_normalized_rest_route($request_uri) : '');
        $is_webcare_rest_route = str_starts_with(strtolower($rest_route), '/webcare-pro-security/');
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing check for WooCommerce AJAX surface.
        $has_wc_ajax_surface = isset($_GET['wc-ajax']) && is_string($_GET['wc-ajax']) && $_GET['wc-ajax'] !== '';
        $is_target_surface = $has_ajax_surface
            || $has_xmlrpc_surface
            || $has_wc_ajax_surface
            || ($has_rest_surface && !$is_webcare_rest_route)
            || ($rest_route !== '' && !$is_webcare_rest_route);
        if (!$is_target_surface) {
            return false;
        }

        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (function_exists('current_user_can') && current_user_can('manage_options')) {
                return false;
            }
            if (class_exists(FirewallEngine::class) && (FirewallEngine::is_authenticated_administrator() || FirewallEngine::is_trusted_plugin_check_or_cli_runtime())) {
                return false;
            }
        } elseif (class_exists(FirewallEngine::class)) {
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

        // Never block if currently inside an internal plugin operation or standard neutralized query
        if (self::$internal_query_depth > 0 || stripos($trimmed, 'SELECT NULL WHERE 1=0') === 0) {
            return null;
        }

        // Pre-process SQL: unwrap MySQL conditional comments (e.g., /*!50000 SELECT */ -> SELECT)
        $unwrapped = (string) preg_replace('#/\*!\d*\s*([\s\S]*?)\s*\*/#', ' $1 ', $trimmed);

        // Strip standard SQL comments (/* ... */, -- ..., # ...) to defeat keyword splitting evasion
        // We strip inline block comments first without spaces so split tokens like UN/**/ION re-join into UNION,
        // and replace line comments with space.
        $clean_sql = (string) preg_replace('#/\*[\s\S]*?\*/#', '', $unwrapped);
        $clean_sql = (string) preg_replace('/(?:--[ \t][^\r\n]*|--[\r\n]|\#[^\r\n]*)/', ' ', $clean_sql);

        // Strip balanced string literals to prevent false positives on blog/post text content
        $skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $clean_sql);

        // 1. Cross-table UNION SELECT touching credential/usermeta tables
        if (preg_match('/\bUNION\s+(?:ALL\s+)?SELECT\b/i', $skeleton) && preg_match('/\b(?:' . $users_tbl . '|' . $usermeta_tbl . ')\b/i', $skeleton)) {
            return 'UNION_SELECT_CREDENTIAL_TABLE';
        }

        // 2. INFORMATION_SCHEMA metadata probing or time/file SQLi primitives in unquoted SQL skeleton
        if (preg_match('/\bINFORMATION_SCHEMA\.(?:TABLES|COLUMNS|SCHEMATA|USER_PRIVILEGES)\b/i', $skeleton)) {
            if (self::is_legitimate_security_or_core_caller()) {
                return null;
            }
            return 'INFORMATION_SCHEMA_PROBE';
        }
        if (preg_match('/\b(?:SLEEP|BENCHMARK|PG_SLEEP)\s*\(/i', $skeleton)) {
            return 'TIME_BLIND_SQL_FUNCTION';
        }
        // Context-sensitive GET_LOCK detection:
        // MySQL advisory locks (e.g. "SELECT GET_LOCK('lock_name', 10)") are legitimately used by plugins for concurrency.
        // Only flag GET_LOCK when chained into injection logic (WHERE/AND/OR/UNION/CASE/WHEN/IF/HAVING) or boolean comparisons.
        if (preg_match('/\b(?:AND|OR|UNION|CASE|WHEN|IF|HAVING)\b[\s\S]*?\bGET_LOCK\s*\(/i', $skeleton)
            || preg_match('/\bGET_LOCK\s*\([\s\S]*?\)\s*(?:AND|OR|=|!=|<|>|IS|LIKE)/i', $skeleton)
        ) {
            return 'TIME_BLIND_SQL_FUNCTION';
        }
        if (preg_match('/\bLOAD_FILE\s*\(/i', $skeleton) || preg_match('/\bINTO\s+(?:OUT|DUMP)FILE\b/i', $skeleton)) {
            return 'FILE_IO_SQLI_PRIMITIVE';
        }

        // Stacked queries execution attempt (e.g., ; DROP TABLE ... or ; UPDATE ...)
        if (preg_match('/;\s*(?:DROP\s+TABLE|ALTER\s+TABLE|UPDATE\s+|INSERT\s+INTO|DELETE\s+FROM)\b/i', $skeleton)) {
            return 'STACKED_QUERY_ATTEMPT';
        }

        // Error-based SQL injection extraction primitives (e.g. EXTRACTVALUE, UPDATEXML, FLOOR(RAND()))
        if (preg_match('/\b(?:EXTRACTVALUE|UPDATEXML)\s*\(/i', $skeleton)
            || (preg_match('/\bFLOOR\s*\(\s*RAND\s*\(/i', $skeleton) && preg_match('/\bCOUNT\s*\(/i', $skeleton))
        ) {
            return 'ERROR_BASED_SQLI_PRIMITIVE';
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
     * Check if current SQL query originates from a verified security scanner (Wordfence, Solid Security, Sucuri, etc.) or Core schema maintenance.
     *
     * @return bool
     */
    public static function is_legitimate_security_or_core_caller(): bool {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Provenance validation for RASP
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15);
        $origin_frame = null;

        // Skip internal RASP, WAF, and $wpdb database frames to locate the true direct SQL originator
        foreach ($frames as $frame) {
            $file = isset($frame['file']) ? wp_normalize_path((string) $frame['file']) : '';
            if ($file === '') {
                continue;
            }
            if (
                strpos($file, '/includes/Firewall/') !== false
                || strpos($file, '/wp-includes/class-wpdb.php') !== false
                || strpos($file, '/wp-includes/wp-db.php') !== false
                || strpos($file, '/wp-includes/class-wp-hook.php') !== false
                || strpos($file, '/wp-includes/plugin.php') !== false
                || strpos($file, '/wp-includes/option.php') !== false
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

        // Explicitly exclude generic AJAX and POST routing entry points
        if (
            str_ends_with($origin_file, '/wp-admin/admin-ajax.php')
            || str_ends_with($origin_file, '/wp-admin/admin-post.php')
        ) {
            return false;
        }

        // Anchor legitimate security plugin callers to defined WP_PLUGIN_DIR
        $plugin_dir = defined('WP_PLUGIN_DIR') ? wp_normalize_path(WP_PLUGIN_DIR) : '';
        if ($plugin_dir !== '') {
            $legitimate_plugin_prefixes = [
                $plugin_dir . '/wordfence/',
                $plugin_dir . '/better-wp-security/',
                $plugin_dir . '/sucuri-scanner/',
                $plugin_dir . '/all-in-one-wp-security-and-firewall/',
            ];
            foreach ($legitimate_plugin_prefixes as $prefix) {
                if (str_starts_with($origin_file, $prefix)) {
                    return true;
                }
            }
        }

        // Anchor legitimate WordPress Core schema maintenance callers in /wp-admin/includes/
        $admin_includes_dir = defined('ABSPATH') ? wp_normalize_path(ABSPATH . 'wp-admin/includes/') : '';
        if ($admin_includes_dir !== '' && str_starts_with($origin_file, $admin_includes_dir)) {
            if (
                str_ends_with($origin_file, '/wp-admin/includes/upgrade.php')
                || str_ends_with($origin_file, '/wp-admin/includes/schema.php')
            ) {
                return true;
            }
        }

        return false;
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
                || strpos($file, '/wp-includes/class-wp-hook.php') !== false
                || strpos($file, '/wp-includes/plugin.php') !== false
                || strpos($file, '/wp-includes/option.php') !== false
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

        // 3. Inspect columns, enforce single-row tuple, and verify role/registration policy in INSERT query
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

            // 3b. Pre-Insert Role & Registration Policy Verification (during unauthenticated guest sessions)
            if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
                // Verify default_role option has not been poisoned to a privileged role
                $default_role = function_exists('get_option') ? (string) get_option('default_role', 'subscriber') : 'subscriber';
                if (class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role($default_role)) {
                    return false;
                }

                // Inspect full call stack with arguments to verify wp_insert_user($userdata) role boundaries
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- RASP argument inspection for guest user creation
                $full_frames = debug_backtrace(0, 20);
                foreach ($full_frames as $ff) {
                    $fn = (string) ($ff['function'] ?? '');
                    if (in_array($fn, ['wp_insert_user', 'wp_create_user', 'wc_create_new_customer', 'register_new_user'], true)) {
                        $arg0 = $ff['args'][0] ?? null;
                        if (is_object($arg0)) {
                            $arg0 = get_object_vars($arg0);
                        }
                        if (is_array($arg0)) {
                            if (!empty($arg0['role']) && is_string($arg0['role'])) {
                                if (class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role($arg0['role'])) {
                                    return false;
                                }
                            }
                            if (!empty($arg0['roles']) && is_array($arg0['roles'])) {
                                foreach ($arg0['roles'] as $r_item) {
                                    if (is_string($r_item) && class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role($r_item)) {
                                        return false;
                                    }
                                }
                            }
                            if (!empty($arg0['wp_capabilities']) && is_array($arg0['wp_capabilities'])) {
                                foreach (array_keys(array_filter($arg0['wp_capabilities'])) as $cap_item) {
                                    if (class_exists(FirewallEngine::class) && FirewallEngine::is_privileged_role((string) $cap_item)) {
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                }
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
                } elseif (preg_match('/^\'((?:\\\\.|[^\'\\\\])+)\'$/s', $pred_val, $login_match)) {
                    if (trim(stripslashes($login_match[1])) === '') {
                        return false;
                    }
                } elseif (preg_match('/^"((?:\\\\.|[^"\\\\])+)"$/s', $pred_val, $login_match)) {
                    if (trim(stripslashes($login_match[1])) === '') {
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
                $mutated_cols = [];
                foreach ($col_matches[1] as $col) {
                    $col_clean = strtolower($col);
                    if (!in_array($col_clean, $allowed_columns, true)) {
                        return false;
                    }
                    $mutated_cols[] = $col_clean;
                }
                $mutated_cols = array_values(array_unique($mutated_cols));

                // 5. Target User Boundary & Cryptographic Auth Lifecycle Verification (during unauthenticated guest sessions)
                if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
                    $target_user = null;

                    if ($pred_col === 'id') {
                        $target_id = (int) $pred_val;
                        if (function_exists('get_userdata')) {
                            $target_user = get_userdata($target_id);
                        }
                    } elseif ($pred_col === 'user_login') {
                        $login_val = stripslashes(trim($pred_val, "'\""));
                        if (function_exists('get_user_by')) {
                            $target_user = get_user_by('login', $login_val);
                        }
                    }

                    // Target user must exist and be an authentic WP_User instance
                    if (!($target_user instanceof \WP_User)) {
                        return false;
                    }

                    $target_uid = (int) $target_user->ID;

                    // 5A. Password-Reset Key Issuance (get_password_reset_key / retrieve_password):
                    // Permitted when called from get_password_reset_key / retrieve_password, mutating user_activation_key
                    // to a non-empty token, and NOT altering user_pass (written user_pass must match existing user_pass).
                    if ($is_core_origin && in_array('user_activation_key', $mutated_cols, true)) {
                        $has_reset_key_generator = false;
                        foreach ($frames as $fr) {
                            $fn = (string) ($fr['function'] ?? '');
                            if ($fn === 'get_password_reset_key' || $fn === 'retrieve_password') {
                                $has_reset_key_generator = true;
                                break;
                            }
                        }
                        // Ensure SET user_activation_key is writing a non-empty token (not clearing it without reset verification)
                        $writes_non_empty_key = !preg_match('/`?user_activation_key`?\s*=\s*(?:\'\'|""|\'\s*\'|"\s*")/i', $set_clause_raw);

                        // If user_pass is in the query, verify it is identical to existing user_pass (never altered)
                        $pass_not_altered = true;
                        if (in_array('user_pass', $mutated_cols, true)) {
                            if (preg_match('/`?user_pass`?\s*=\s*([\'"])(.+?)\1/i', $set_clause_raw, $pass_m)) {
                                $pass_not_altered = hash_equals((string) $target_user->user_pass, $pass_m[2]);
                            } else {
                                $pass_not_altered = false;
                            }
                        }

                        if ($has_reset_key_generator && $writes_non_empty_key && $pass_not_altered) {
                            return true;
                        }
                    }

                    // 5B. Password Rehash or Verified Password Reset (mutating user_pass and/or user_activation_key):
                    if (in_array('user_pass', $mutated_cols, true) || in_array('user_activation_key', $mutated_cols, true)) {
                        if ($is_core_origin && self::is_verified_password_mutation_authorized($target_user)) {
                            return true;
                        }
                        return false;
                    }

                    // 5C. All other unauthenticated wp_users UPDATE mutations (e.g. profile/email/display_name during registration):
                    // Never allow mutations on privileged/administrative accounts
                    if (
                        (class_exists(FirewallEngine::class) && FirewallEngine::is_user_privileged($target_user))
                        || $target_user->has_cap('manage_options')
                        || $target_user->has_cap('administrator')
                        || $target_user->has_cap('edit_users')
                    ) {
                        return false;
                    }

                    // Require a valid, non-future registration timestamp within the 120s window (fail-closed)
                    if (!self::is_within_registration_window($target_user, 120)) {
                        return false;
                    }
                }

                return true;
            }
        }

        return false;
    }

    /**
     * Cryptographically verify that an unauthenticated `user_pass` mutation on `$target_user`
     * is authorized by either:
     * 1. A verified login password check (`wp_check_password`) matching `$target_user->ID` and `$target_user->user_pass`, OR
     * 2. A verified password-reset key check (`check_password_reset_key` / `validate_password_reset`) where
     *    `$target_user->user_activation_key` is non-empty and matches the request's reset token.
     *
     * Rejects unverified direct calls to `reset_password($user, $pass)` or `wp_set_password($pass, $uid)`
     * from vulnerable guest plugin handlers.
     */
    private static function is_verified_password_mutation_authorized(\WP_User $target_user): bool {
        $uid = (int) $target_user->ID;
        if ($uid <= 0) {
            return false;
        }

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- RASP call-stack verification with arguments
        $full_frames              = debug_backtrace(0, 20);
        $candidate_key_from_frame = '';
        $in_wp_check_password     = false;
        $in_reset_password        = false;

        foreach ($full_frames as $fr) {
            $fn   = (string) ($fr['function'] ?? '');
            $file = isset($fr['file']) ? wp_normalize_path((string) $fr['file']) : '';

            // Reject if any third-party plugin (outside WooCommerce) directly called wp_set_password()
            if ($fn === 'wp_set_password' && $file !== '' && str_contains($file, '/wp-content/plugins/') && !str_contains($file, '/plugins/woocommerce/')) {
                return false;
            }

            if ($fn === 'wp_check_password') {
                $arg_uid = isset($fr['args'][2]) && is_numeric($fr['args'][2]) ? (int) $fr['args'][2] : 0;
                if ($arg_uid === 0 || $arg_uid === $uid) {
                    $in_wp_check_password = true;
                }
            } elseif ($fn === 'wp_authenticate_username_password' || $fn === 'wp_authenticate_email_password') {
                $raw_login = $fr['args'][1] ?? '';
                if ($raw_login instanceof \SensitiveParameterValue) {
                    $raw_login = $raw_login->getValue();
                }
                $arg_login = is_string($raw_login) ? trim($raw_login) : '';
                if (
                    $arg_login === ''
                    || strcasecmp($arg_login, $target_user->user_login) === 0
                    || strcasecmp($arg_login, $target_user->user_email) === 0
                ) {
                    $in_wp_check_password = true;
                }
            }

            if ($fn === 'reset_password') {
                $arg_user = $fr['args'][0] ?? null;
                if ($arg_user instanceof \WP_User && (int) $arg_user->ID === $uid) {
                    $in_reset_password = true;
                }
            }

            if ($fn === 'check_password_reset_key') {
                $arg_login = isset($fr['args'][1]) && is_string($fr['args'][1]) ? trim($fr['args'][1]) : '';
                if ($arg_login === $target_user->user_login) {
                    $in_reset_password = true;
                    $raw_key = $fr['args'][0] ?? '';
                    if ($raw_key instanceof \SensitiveParameterValue) {
                        $raw_key = $raw_key->getValue();
                    }
                    if (is_string($raw_key) && $raw_key !== '') {
                        $candidate_key_from_frame = trim($raw_key);
                    }
                }
            }
        }

        // Path 1: Legitimate password reset completion inside reset_password() or check_password_reset_key()
        if ($in_reset_password) {
            $existing_key = isset($target_user->user_activation_key) ? trim((string) $target_user->user_activation_key) : '';
            if ($existing_key === '' || !str_contains($existing_key, ':')) {
                return false;
            }

            [$key_time_str, $hash_part] = explode(':', $existing_key, 2);
            if (!ctype_digit($key_time_str) || (int) $key_time_str <= 0 || $hash_part === '') {
                return false;
            }

            $key_ts = (int) $key_time_str;
            if ($key_ts > (time() + 5)) {
                return false;
            }

            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
            $expiration_duration = function_exists('apply_filters') ? (int) apply_filters('password_reset_expiration', 86400) : 86400;
            if ((time() - $key_ts) > $expiration_duration) {
                return false;
            }

            if (!empty(self::$verified_reset_users[$uid])) {
                $reset_rec  = self::$verified_reset_users[$uid];
                $saved_key  = is_array($reset_rec) ? ($reset_rec['activation_key'] ?? '') : '';
                $saved_time = is_array($reset_rec) ? (int) ($reset_rec['timestamp'] ?? 0) : 0;

                if (
                    $saved_key !== ''
                    && $saved_time > 0
                    && (time() - $saved_time) <= 120
                    && hash_equals($saved_key, $existing_key)
                ) {
                    unset(self::$verified_reset_users[$uid]);
                    return true;
                }
            }

            $candidate_key = $candidate_key_from_frame;
            // phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            if ($candidate_key === '' && !empty($_REQUEST['key']) && is_string($_REQUEST['key'])) {
                $candidate_key = sanitize_text_field(wp_unslash($_REQUEST['key']));
            } elseif ($candidate_key === '' && !empty($_REQUEST['rp_key']) && is_string($_REQUEST['rp_key'])) {
                $candidate_key = sanitize_text_field(wp_unslash($_REQUEST['rp_key']));
            } elseif ($candidate_key === '' && !empty($_POST['reset_key']) && is_string($_POST['reset_key'])) {
                $candidate_key = sanitize_text_field(wp_unslash($_POST['reset_key']));
            } elseif ($candidate_key === '' && !empty($_COOKIE) && is_array($_COOKIE)) {
                foreach ($_COOKIE as $ck_name => $ck_val) {
                    if (is_string($ck_name) && str_starts_with($ck_name, 'wp-resetpass-') && is_string($ck_val)) {
                        $parts = explode(':', sanitize_text_field(wp_unslash($ck_val)), 2);
                        if (count($parts) === 2 && rawurldecode($parts[0]) === $target_user->user_login) {
                            $candidate_key = trim($parts[1]);
                            break;
                        }
                    }
                }
            }
            // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing

            if ($candidate_key !== '' && preg_match('/^[a-zA-Z0-9]{16,64}$/', $candidate_key)) {
                if (function_exists('wp_verify_fast_hash') && wp_verify_fast_hash($candidate_key, $hash_part)) {
                    unset(self::$verified_reset_users[$uid]);
                    return true;
                }
            }

            return false;
        }

        // Path 2: Legitimate login password rehash inside authentic WordPress 7.0 Core authentication stack
        if ($in_wp_check_password) {
            $canonical_user      = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/user.php') : '';
            $canonical_pluggable = defined('ABSPATH') && defined('WPINC') ? wp_normalize_path(ABSPATH . WPINC . '/pluggable.php') : '';
            $has_direct_rehash_stack = false;

            for ($i = 0; $i < count($full_frames); $i++) {
                $fn = $full_frames[$i]['function'] ?? '';
                if ($fn === 'wp_set_password') {
                    $arg_uid     = isset($full_frames[$i]['args'][1]) ? (int) $full_frames[$i]['args'][1] : 0;
                    $caller_fn   = $full_frames[$i + 1]['function'] ?? '';
                    $caller_file = isset($full_frames[$i]['file']) ? wp_normalize_path((string) $full_frames[$i]['file']) : '';

                    $is_core_auth_caller = (
                        (($caller_fn === 'wp_authenticate_username_password' || $caller_fn === 'wp_authenticate_email_password')
                            && $canonical_user !== '' && $caller_file === $canonical_user)
                        || ($caller_fn === 'wp_check_password'
                            && $canonical_pluggable !== '' && $caller_file === $canonical_pluggable)
                    );

                    if ($arg_uid === $uid && $is_core_auth_caller) {
                        $has_direct_rehash_stack = true;
                    }
                    break;
                }
            }

            if (!$has_direct_rehash_stack) {
                return false;
            }

            $current_hash = (string) $target_user->user_pass;
            $needs_rehash = (strlen($current_hash) <= 32)
                || (function_exists('wp_password_needs_rehash') && wp_password_needs_rehash($current_hash, $uid));

            if (!$needs_rehash) {
                return false;
            }

            unset(self::$verified_password_users[$uid]);
            return true;
        }

        return false;
    }

    /**
     * Verify whether a target user was authentically registered within the allowed registration window.
     * Delegates directly to the canonical FirewallEngine::is_within_registration_window helper.
     * Fails closed if FirewallEngine is unavailable.
     *
     * @param \WP_User $user
     * @param int      $max_age_seconds Default 120 seconds
     * @return bool
     */
    public static function is_within_registration_window(\WP_User $user, int $max_age_seconds = 120): bool {
        if (class_exists(FirewallEngine::class)) {
            return FirewallEngine::is_within_registration_window($user, $max_age_seconds);
        }

        // Fail-closed if core FirewallEngine is unavailable
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
            if ($file === '' || strpos($file, 'webcare-pro-security') !== false) {
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
