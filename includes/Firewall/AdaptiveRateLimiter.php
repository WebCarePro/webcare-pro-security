<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\AuditLogger;
use WebCareProScanner\Firewall\CAF\ThreatScoreTracker;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AdaptiveRateLimiter (CAF Phase 3)
 *
 * Sliding-Window Multi-Bucket Velocity Limiter & Smart Throttler.
 *
 * Mathematical Sliding Window Model:
 *   C_{eff} = C_{prev} * (1 - (t - t_{window_start}) / W) + C_{curr}
 *
 * Protects 5 isolated velocity boundaries:
 * 1. BUCKET_AUTH: /wp-login.php, xmlrpc.php, jwt-auth, wc-ajax=login (Strict limit: 5 / 300s)
 * 2. BUCKET_CHECKOUT: wc-ajax=checkout, /wp-json/wc/store/v1/checkout (Limit: 8 / 60s, JSON response)
 * 3. BUCKET_CART_AJAX: add_to_cart, update_order_review, get_refreshed_fragments (Limit: 30 / 60s, JSON response)
 * 4. BUCKET_REST_WRITE: POST/PUT/PATCH/DELETE on /wp-json/ (Limit: 30 / 60s)
 * 5. BUCKET_SEARCH_PROBE: ?s= and /wp-json/wp/v2/search (Limit: 25 / 60s)
 *
 * On throttle on checkout/cart boundaries, always emits valid WooCommerce-compatible JSON.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class AdaptiveRateLimiter {

    public const OPTION_SETTINGS      = 'webcareproscan_rate_limiter_settings';
    public const TRANSIENT_PREFIX     = 'webcareproscan_rl_';

    // Bucket Identifier Constants
    public const BUCKET_AUTH          = 'auth';
    public const BUCKET_CHECKOUT      = 'checkout';
    public const BUCKET_CART_AJAX     = 'cart_ajax';
    public const BUCKET_REST_WRITE    = 'rest_write';
    public const BUCKET_SEARCH_PROBE  = 'search_probe';
    public const BUCKET_GLOBAL        = 'global';

    // Bucket Default Thresholds
    public const LIMIT_AUTH           = 5;   // 5 hits per 300s (5 min)
    public const WINDOW_AUTH          = 300;
    public const LIMIT_CHECKOUT       = 8;   // 8 hits per 60s
    public const WINDOW_CHECKOUT      = 60;
    public const LIMIT_CART_AJAX      = 30;  // 30 hits per 60s
    public const WINDOW_CART_AJAX     = 60;
    public const LIMIT_REST_WRITE     = 30;  // 30 mutations per 60s
    public const WINDOW_REST_WRITE    = 60;
    public const LIMIT_SEARCH_PROBE   = 25;  // 25 queries per 60s
    public const WINDOW_SEARCH_PROBE  = 60;
    public const LIMIT_GLOBAL         = 300; // 300 hits per 60s
    public const WINDOW_GLOBAL        = 60;

    /**
     * Get rate limiter settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                => true,
            'limit_auth'             => self::LIMIT_AUTH,
            'window_auth'            => self::WINDOW_AUTH,
            'limit_checkout'         => self::LIMIT_CHECKOUT,
            'window_checkout'        => self::WINDOW_CHECKOUT,
            'limit_cart_ajax'        => self::LIMIT_CART_AJAX,
            'window_cart_ajax'       => self::WINDOW_CART_AJAX,
            'limit_rest_write'       => self::LIMIT_REST_WRITE,
            'window_rest_write'      => self::WINDOW_REST_WRITE,
            'limit_search_probe'     => self::LIMIT_SEARCH_PROBE,
            'window_search_probe'    => self::WINDOW_SEARCH_PROBE,
            'limit_global'           => self::LIMIT_GLOBAL,
            'window_global'          => self::WINDOW_GLOBAL,
            'retry_after_seconds'    => 30,
            'escalate_to_ban'        => false,
            'enable_auto_escalation' => false,
        ];

        $stored = get_option(self::OPTION_SETTINGS, []);
        return array_merge($defaults, is_array($stored) ? $stored : []);
    }

    /**
     * Update rate limiter settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();

        $updated = [
            'enabled'                => isset($new_settings['enabled']) ? !empty($new_settings['enabled']) : !empty($current['enabled']),
            'limit_auth'             => max(2, min(50, intval($new_settings['limit_auth'] ?? $current['limit_auth']))),
            'window_auth'            => max(60, min(1800, intval($new_settings['window_auth'] ?? $current['window_auth']))),
            'limit_checkout'         => max(3, min(60, intval($new_settings['limit_checkout'] ?? $current['limit_checkout']))),
            'window_checkout'        => max(30, min(300, intval($new_settings['window_checkout'] ?? $current['window_checkout']))),
            'limit_cart_ajax'        => max(10, min(200, intval($new_settings['limit_cart_ajax'] ?? $current['limit_cart_ajax']))),
            'window_cart_ajax'       => max(30, min(300, intval($new_settings['window_cart_ajax'] ?? $current['window_cart_ajax']))),
            'limit_rest_write'       => max(10, min(200, intval($new_settings['limit_rest_write'] ?? $current['limit_rest_write']))),
            'window_rest_write'      => max(30, min(300, intval($new_settings['window_rest_write'] ?? $current['window_rest_write']))),
            'limit_search_probe'     => max(5, min(100, intval($new_settings['limit_search_probe'] ?? ($new_settings['limit_search'] ?? $current['limit_search_probe'])))),
            'window_search_probe'    => max(30, min(300, intval($new_settings['window_search_probe'] ?? ($new_settings['window_search'] ?? $current['window_search_probe'])))),
            'limit_global'           => max(50, min(2000, intval($new_settings['limit_global'] ?? $current['limit_global']))),
            'window_global'          => max(30, min(300, intval($new_settings['window_global'] ?? $current['window_global']))),
            'retry_after_seconds'    => max(5, min(300, intval($new_settings['retry_after_seconds'] ?? $current['retry_after_seconds']))),
            'escalate_to_ban'        => false,
            'enable_auto_escalation' => false,
        ];

        update_option(self::OPTION_SETTINGS, $updated);

        $diff = SettingsManager::compute_settings_diff($current, $updated);
        if (!empty($diff) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'rate_limiter_settings_updated',
                'firewall',
                [
                    'changed_count' => count($diff),
                    'description'   => sprintf('Adaptive Rate Limiting multi-bucket thresholds updated (%d parameter(s)).', count($diff)),
                    'module'        => 'rate_limiter',
                    'diff'          => $diff,
                ]
            );
        }

        return $updated;
    }

    /**
     * Check velocity budget using Sliding-Window Counter for an explicit bucket and IP.
     *
     * Formula:
     *   C_{eff} = C_{prev} * (1 - (now - window_start) / window) + C_{curr}
     *
     * @param string $bucket Name of velocity bucket ('auth', 'checkout', 'cart_ajax', 'rest_write', 'search_probe', 'global')
     * @param string $ip Client IP
     * @param int $limit Maximum allowed requests in window
     * @param int $window Window duration in seconds
     * @return array ['allowed' => bool, 'remaining' => int, 'retry_after' => int, 'current' => float, 'limit' => int, 'window' => int]
     */
    public static function check_bucket_velocity(string $bucket, string $ip, int $limit, int $window): array {
        $ip_hash = substr(md5($ip), 0, 16);
        $cache_key = self::TRANSIENT_PREFIX . $bucket . '_' . $ip_hash;
        $now = time();

        $current_window_idx = (int) floor($now / $window);
        $window_start = $current_window_idx * $window;
        $elapsed_in_window = max(0, $now - $window_start);

        $data = null;
        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            $data = apcu_fetch($cache_key);
        } elseif (wp_using_ext_object_cache()) {
            $data = wp_cache_get($cache_key, 'webcareproscan_rl');
        } else {
            $data = self::file_get_rate_limit($cache_key);
            if ($data === null) {
                $data = get_transient($cache_key);
            }
        }

        if (!is_array($data) || ($data['window_idx'] ?? 0) !== $current_window_idx) {
            // New window or expired
            $prev_count = 0;
            if (is_array($data) && ($data['window_idx'] ?? 0) === ($current_window_idx - 1)) {
                $prev_count = (int) ($data['curr'] ?? 0);
            }
            $curr_count = 1;
            $data = [
                'window_idx' => $current_window_idx,
                'prev'       => $prev_count,
                'curr'       => $curr_count,
            ];
        } else {
            // Existing current window
            $data['curr'] = (int) ($data['curr'] ?? 0) + 1;
        }

        // Sliding window effective count: C_{prev} * (1 - elapsed/W) + C_{curr}
        $prev_weight = max(0.0, 1.0 - ($elapsed_in_window / (float) $window));
        $effective_count = round(($data['prev'] * $prev_weight) + $data['curr'], 2);

        // Store back
        $ttl = $window * 2;
        $has_fast_cache = false;
        if (function_exists('apcu_store') && ini_get('apc.enabled')) {
            apcu_store($cache_key, $data, $ttl);
            $has_fast_cache = true;
        }
        if (wp_using_ext_object_cache()) {
            wp_cache_set($cache_key, $data, 'webcareproscan_rl', $ttl);
            $has_fast_cache = true;
        }

        // Fallback to secured file storage first, and only transient as last resort
        if (!$has_fast_cache) {
            $file_written = self::file_set_rate_limit($cache_key, $data, $ttl);
            if (!$file_written) {
                set_transient($cache_key, $data, $ttl);
            }
        }

        $allowed = ($effective_count <= (float) $limit);
        $remaining = max(0, (int) floor($limit - $effective_count));
        $retry_after = $allowed ? 0 : max(5, $window - $elapsed_in_window);

        return [
            'allowed'     => $allowed,
            'remaining'   => $remaining,
            'retry_after' => $retry_after,
            'current'     => (int) ceil($effective_count),
            'limit'       => $limit,
            'window'      => $window,
        ];
    }

    /**
     * Evaluate incoming request against context-aware 5-bucket velocity limiters.
     *
     * @param string $client_ip
     * @return bool True if permitted, false if throttled/blocked.
     */
    public static function check_request(string $client_ip): bool {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return true;
        }

        // Exempt logged-in administrators, store managers, and editor/builders (including early authentication detection at plugins_loaded: 0)
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            if (FirewallEngine::is_authenticated_administrator() || FirewallEngine::is_authenticated_editor_or_builder()) {
                return true;
            }
        }
        if (function_exists('current_user_can') && (current_user_can('manage_options') || current_user_can('manage_woocommerce'))) {
            return true;
        }

        // Exempt local loopback in dev
        if ($client_ip === '127.0.0.1' || $client_ip === '::1') {
            return true;
        }

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $decoded_uri = rawurldecode($raw_uri);
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early passive packet rate-limiting
        $post_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $search_query = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';

        // Classify into one of 5 isolated velocity boundaries:
        $bucket = self::BUCKET_GLOBAL;
        $limit = (int) ($settings['limit_global'] ?? self::LIMIT_GLOBAL);
        $window = (int) ($settings['window_global'] ?? self::WINDOW_GLOBAL);

        if (
            str_contains($decoded_uri, 'wp-login.php') ||
            str_contains($decoded_uri, 'xmlrpc.php') ||
            str_contains($decoded_uri, '/wp-json/jwt-auth/') ||
            str_contains($decoded_uri, 'wc-ajax=login')
        ) {
            // Bucket 1: Auth
            $bucket = self::BUCKET_AUTH;
            $limit = (int) ($settings['limit_auth'] ?? self::LIMIT_AUTH);
            $window = (int) ($settings['window_auth'] ?? self::WINDOW_AUTH);
        } elseif (
            str_contains($decoded_uri, 'wc-ajax=checkout') ||
            str_contains($decoded_uri, '/wp-json/wc/store/v1/checkout') ||
            in_array($post_action, ['woocommerce_checkout'], true)
        ) {
            // Bucket 2: Checkout (High priority e-commerce boundary)
            $bucket = self::BUCKET_CHECKOUT;
            $limit = (int) ($settings['limit_checkout'] ?? self::LIMIT_CHECKOUT);
            $window = (int) ($settings['window_checkout'] ?? self::WINDOW_CHECKOUT);
        } elseif (
            str_contains($decoded_uri, 'wc-ajax=add_to_cart') ||
            str_contains($decoded_uri, 'wc-ajax=update_order_review') ||
            str_contains($decoded_uri, 'wc-ajax=get_refreshed_fragments') ||
            in_array($post_action, ['woocommerce_add_to_cart', 'woocommerce_update_order_review', 'woocommerce_json_search_products', 'aws_action', 'dgwt_wcas_ajax_search', 'jet_ajax_search'], true)
        ) {
            // Bucket 3: Cart AJAX (Frequent legit interactions & live product search queries)
            $bucket = self::BUCKET_CART_AJAX;
            $limit = (int) ($settings['limit_cart_ajax'] ?? self::LIMIT_CART_AJAX);
            $window = (int) ($settings['window_cart_ajax'] ?? self::WINDOW_CART_AJAX);
        } elseif (
            trim($search_query) !== '' ||
            str_contains($decoded_uri, '/wp-json/wp/v2/search')
        ) {
            // Bucket 5: Search Probe (Prevents expensive wildcard queries)
            $bucket = self::BUCKET_SEARCH_PROBE;
            $limit = (int) ($settings['limit_search_probe'] ?? self::LIMIT_SEARCH_PROBE);
            $window = (int) ($settings['window_search_probe'] ?? self::WINDOW_SEARCH_PROBE);
        } elseif (
            str_contains($decoded_uri, '/wp-json/') &&
            in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
        ) {
            // Bucket 4: REST Mutation/Write
            $bucket = self::BUCKET_REST_WRITE;
            $limit = (int) ($settings['limit_rest_write'] ?? self::LIMIT_REST_WRITE);
            $window = (int) ($settings['window_rest_write'] ?? self::WINDOW_REST_WRITE);
        }

        // Customer-Safe Shopper Headroom Policy: Verified shoppers receive increased headroom buffer
        // on dynamic commerce interaction boundaries (Cart AJAX, Search, and Checkout) without granting blanket immunity.
        if (
            class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard')
            && \WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()
        ) {
            if ($bucket === self::BUCKET_CART_AJAX || $bucket === self::BUCKET_SEARCH_PROBE || $bucket === self::BUCKET_CHECKOUT) {
                $limit = (int) ceil($limit * 1.5); // 50% extra headroom for legitimate shoppers
            }
        }

        $result = self::check_bucket_velocity($bucket, $client_ip, $limit, $window);
        if ($result['allowed']) {
            return true;
        }

        $count = $result['current'];
        $retry_after = (int) ($settings['retry_after_seconds'] ?? 30);

        // Record in differential threat score engine
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            $event_tag = ($bucket === self::BUCKET_AUTH) ? 'auth_fail' : 'probe_404';
            ThreatScoreTracker::record_event($client_ip, $event_tag, 10.0);
        }


        // Record throttle telemetry
        self::record_throttle_incident($client_ip, $bucket, $count, $limit);

        // Notify if behavioral rate limit exceeded notification is active (debounced per IP)
        $rl_notif_lock = 'webcareproscan_rl_notif_' . md5($client_ip . '_' . $bucket);
        if (!get_transient($rl_notif_lock)) {
            set_transient($rl_notif_lock, 1, 900); // 15-minute debounce per IP and bucket
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('behavioral_rate_limit_exceeded', [
                    'severity' => 'high',
                    /* translators: 1: client IP, 2: rate limit bucket name, 3: request count, 4: limit */
                    'message'  => sprintf(__('Client IP %1$s exceeded the velocity threshold for %2$s (%3$d requests against limit of %4$d).', 'webcare-pro-security'), $client_ip, strtoupper($bucket), $count, $limit),
                    'details'  => [
                        'Offending IP'    => $client_ip,
                        'Boundary Bucket' => strtoupper($bucket),
                        'Request Count'   => $count,
                        'Window Limit'    => $limit,
                        'Retry-After'     => $retry_after . 's',
                    ],
                ]);
            }
        }

        status_header(429);
        header('Retry-After: ' . $retry_after);
        header('X-WebCare-Rate-Limit-Bucket: ' . rawurlencode($bucket));
        header('X-WebCare-Rate-Limit-Limit: ' . (int) $limit);
        header('X-WebCare-Rate-Limit-Current: ' . (int) $count);

        // Special handling for E-Commerce / Checkout: Return structured JSON to prevent UI corruption
        $is_wc_or_json = wp_is_json_request() ||
            str_contains($decoded_uri, '/wp-json/') ||
            str_contains($decoded_uri, 'wc-ajax=') ||
            $bucket === self::BUCKET_CHECKOUT ||
            $bucket === self::BUCKET_CART_AJAX;

        if ($is_wc_or_json) {
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'result'      => 'failure',
                'status'      => 429,
                'error'       => 'too_many_requests',
                /* translators: %1$s: velocity bucket name, %2$d: retry after seconds */
                'message'     => sprintf(__('Too many %1$s requests. Please wait %2$d seconds before retrying.', 'webcare-pro-security'), esc_html($bucket), $retry_after),
                /* translators: %d: retry after seconds */
                'messages'    => sprintf('<ul class="woocommerce-error"><li>%s</li></ul>', esc_html(sprintf(__('Too many requests. Please wait %d seconds before retrying.', 'webcare-pro-security'), $retry_after))),
                'retry_after' => $retry_after,
                'bucket'      => $bucket,
            ]);
        } else {
            header('Content-Type: text/plain; charset=utf-8');
            echo esc_html(sprintf('HTTP 429 Too Many Requests: Rate limit exceeded on %s boundary. Please wait %d seconds before retrying.', $bucket, $retry_after));
        }
        exit;
    }

    /**
     * Record a throttling incident.
     */
    private static function record_throttle_incident(string $ip, string $bucket, int $count, int $limit): void {
        $transient_key = 'webcareproscan_rl_stats_day';
        $stats = get_transient($transient_key);
        if (!is_array($stats)) {
            $stats = ['total_throttled' => 0, 'by_bucket' => []];
        }
        $stats['total_throttled']++;
        $stats['by_bucket'][$bucket] = ($stats['by_bucket'][$bucket] ?? 0) + 1;
        set_transient($transient_key, $stats, 86400);
    }

    /**
     * Get aggregate rate limiting telemetry.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $stats = get_transient('webcareproscan_rl_stats_day');
        if (!is_array($stats)) {
            $stats = ['total_throttled' => 0, 'by_bucket' => []];
        }

        $distributed = class_exists('\\WebCareProScanner\\Firewall\\DistributedVelocityShield')
            ? DistributedVelocityShield::get_telemetry()
            : [];

        return [
            'settings'                 => self::get_settings(),
            'total_throttled'          => $stats['total_throttled'] ?? 0,
            'total_throttled_requests' => $stats['total_throttled'] ?? 0,
            'active_tracked_ips'       => count($stats['by_bucket'] ?? []),
            'distributed_shield'       => $distributed,
            'by_bucket'                => $stats['by_bucket'] ?? [
                self::BUCKET_AUTH         => 0,
                self::BUCKET_CHECKOUT     => 0,
                self::BUCKET_CART_AJAX    => 0,
                self::BUCKET_REST_WRITE   => 0,
                self::BUCKET_SEARCH_PROBE => 0,
                self::BUCKET_GLOBAL       => 0,
            ],
        ];
    }

    private const FILE_STORAGE_SUBDIR = 'webcare-pro-security/rate-limits';

    /**
     * Get storage directory for file-backed rate limiting.
     *
     * @return string
     */
    private static function get_rate_limit_storage_dir(): string {
        $upload_dir = wp_upload_dir();
        $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
        if (empty($base_dir)) {
            return '';
        }
        return rtrim($base_dir, '/\\') . '/' . self::FILE_STORAGE_SUBDIR;
    }

    /**
     * Ensure rate-limit storage directory exists and is secured.
     *
     * @return bool
     */
    private static function ensure_storage_dir(): bool {
        $dir = self::get_rate_limit_storage_dir();
        if (empty($dir)) {
            return false;
        }
        if (!is_dir($dir)) {
            // phpcs:ignore WordPress.WP.AlternativeFileSystem.mkdir_mkdir
            wp_mkdir_p($dir);
        }
        if (!is_dir($dir) || !wp_is_writable($dir)) {
            return false;
        }

        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $content = "# WebCare Pro Security - Protect Rate Limiting State\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($htaccess, $content);
        }
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
        return true;
    }

    /**
     * Read rate-limit data from sharded file buffer.
     *
     * @param string $cache_key
     * @return array|null
     */
    private static function file_get_rate_limit(string $cache_key): ?array {
        $dir = self::get_rate_limit_storage_dir();
        if (empty($dir)) {
            return null;
        }
        $shard = substr(md5($cache_key), 0, 2);
        $file = $dir . "/rl_{$shard}.php";
        if (!file_exists($file)) {
            return null;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file, 'r');
        if (!$fp) {
            return null;
        }

        $locked = @flock($fp, LOCK_SH | LOCK_NB);
        if (!$locked) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            @fclose($fp);
            return null;
        }

        $raw = '';
        while (!feof($fp)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $raw .= fread($fp, 8192);
        }
        @flock($fp, LOCK_UN);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($fp);

        if (str_starts_with($raw, "<?php exit; ?>\n")) {
            $json = substr($raw, 15);
            $store = json_decode($json, true);
            if (is_array($store) && isset($store[$cache_key])) {
                $item = $store[$cache_key];
                if (($item['exp'] ?? 0) > time()) {
                    return $item['data'] ?? null;
                }
            }
        }
        return null;
    }

    /**
     * Store rate-limit data into sharded file buffer.
     *
     * @param string $cache_key
     * @param array  $data
     * @param int    $ttl
     * @return bool
     */
    private static function file_set_rate_limit(string $cache_key, array $data, int $ttl): bool {
        if (!self::ensure_storage_dir()) {
            return false;
        }

        $dir = self::get_rate_limit_storage_dir();
        $shard = substr(md5($cache_key), 0, 2);
        $file = $dir . "/rl_{$shard}.php";

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file, 'c+');
        if (!$fp) {
            return false;
        }

        $locked = @flock($fp, LOCK_EX | LOCK_NB);
        if (!$locked) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            @fclose($fp);
            return false;
        }

        $raw = '';
        while (!feof($fp)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $raw .= fread($fp, 8192);
        }

        $store = [];
        if (str_starts_with($raw, "<?php exit; ?>\n")) {
            $json = substr($raw, 15);
            $parsed = json_decode($json, true);
            if (is_array($parsed)) {
                $store = $parsed;
            }
        }

        $now = time();
        foreach ($store as $k => $v) {
            if (($v['exp'] ?? 0) <= $now) {
                unset($store[$k]);
            }
        }

        $store[$cache_key] = [
            'data' => $data,
            'exp'  => $now + $ttl,
        ];

        $payload = "<?php exit; ?>\n" . json_encode($store);
        ftruncate($fp, 0);
        rewind($fp);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
        fwrite($fp, $payload);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fflush
        fflush($fp);
        @flock($fp, LOCK_UN);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($fp);
        return true;
    }
}
