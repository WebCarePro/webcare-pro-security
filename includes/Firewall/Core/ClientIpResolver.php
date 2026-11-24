<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\ServerInfo;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Client IP Resolver & Trusted Proxy Sentinel.
 *
 * Resolves authentic visitor IP addresses, performs reverse-traversal on multi-proxy chains,
 * verifies Cloudflare Anycast CIDRs, and validates RFC 1918 / RFC 4193 private ranges.
 *
 * @package WebCareProScanner\Firewall\Core
 */
class ClientIpResolver {

    /**
     * Cached resolved client IP address for the current PHP lifecycle.
     */
    private static ?string $real_ip = null;

    /**
     * Immutable TCP connecting peer IP before any normalization occurs.
     */
    private static ?string $connecting_peer_ip = null;

    /**
     * Get the immutable direct TCP connecting peer IP.
     *
     * @return string
     */
    public static function get_connecting_peer_ip(): string {
        if (self::$connecting_peer_ip !== null) {
            return self::$connecting_peer_ip;
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::$connecting_peer_ip !== null) {
            self::$connecting_peer_ip = \WebCareProScanner\Firewall\FirewallEngine::$connecting_peer_ip;
            return self::$connecting_peer_ip;
        }
        $raw = isset($_SERVER['REMOTE_ADDR']) ? trim(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']))) : '';
        self::$connecting_peer_ip = filter_var($raw, FILTER_VALIDATE_IP) ? $raw : '127.0.0.1';
        return self::$connecting_peer_ip;
    }

    /**
     * Reset internal static cache (for testing environments).
     *
     * @return void
     */
    public static function reset_cache(): void {
        self::$real_ip = null;
        self::$connecting_peer_ip = null;
    }

    /**
     * Synchronize and normalize $_SERVER['REMOTE_ADDR'] to the resolved real visitor IP.
     *
     * Gated behind opt-in setting 'waf_rewrite_server_remote_addr' (default false)
     * so $_SERVER['REMOTE_ADDR'] is not mutated globally unless explicitly enabled by admin.
     *
     * @return void
     */
    public static function normalize_server_remote_addr(): void {
        if (empty($_SERVER['REMOTE_ADDR'])) {
            return;
        }

        // Capture immutable direct connecting peer IP before $_SERVER['REMOTE_ADDR'] is mutated
        if (self::$connecting_peer_ip === null) {
            self::get_connecting_peer_ip();
        }

        // Opt-in check: only rewrite $_SERVER['REMOTE_ADDR'] if explicitly enabled in settings
        $settings = class_exists(SettingsManager::class) ? SettingsManager::get_settings() : [];
        if (empty($settings['waf_rewrite_server_remote_addr'])) {
            return;
        }

        $real_ip = self::get_client_ip();
        if (!empty($real_ip) && $real_ip !== $_SERVER['REMOTE_ADDR']) {
            $_SERVER['REMOTE_ADDR'] = $real_ip;
        }
    }

    /**
     * Resolve Real Client IP Address with Strict Trusted Proxy Verification.
     *
     * Strictly verifies REMOTE_ADDR against Cloudflare and configured trusted proxies.
     * If the direct connecting peer is untrusted, forwarding headers (CF-Connecting-IP,
     * X-Forwarded-For) are completely ignored to prevent IP spoofing of firewalls and allowlists.
     *
     * @return string
     */
    public static function get_client_ip(): string {
        if (self::$real_ip !== null) {
            return self::$real_ip;
        }

        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']))) : '';
        if (stripos($remote_addr, '::ffff:') === 0) {
            $mapped_v4 = substr($remote_addr, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $remote_addr = $mapped_v4;
            }
        }
        if (!filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            $remote_addr = '127.0.0.1';
        }

        // DEFENSE: If REMOTE_ADDR is NOT a trusted proxy, forwarding headers MUST NOT be trusted.
        // Return REMOTE_ADDR directly to prevent spoofing of allowlists, rate limiters, and logs.
        if (!self::is_trusted_proxy($remote_addr)) {
            self::$real_ip = $remote_addr;
            return self::$real_ip;
        }

        $resolved_ip = '';

        // Check Cloudflare Proxy Trust Mode & Origin Secret
        $settings = class_exists(SettingsManager::class) ? SettingsManager::get_settings() : [];
        $cf_trust_mode = (string) ($settings['waf_cloudflare_proxy_trust_mode'] ?? 'disabled');
        $cf_origin_secret = (string) ($settings['waf_cloudflare_origin_secret'] ?? '');

        $cf_trusted = false;
        if ($cf_trust_mode === 'enabled') {
            $cf_trusted = true;
        } elseif ($cf_trust_mode === 'auto_detected') {
            $cf_trusted = !empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
        }

        // If origin secret is configured, require matching header via timing-attack safe comparison
        // Unslash and validate byte bounds ONLY (preserve exact special / percent-encoded characters)
        if ($cf_trusted && $cf_origin_secret !== '') {
            $incoming_secret = '';
            foreach (['HTTP_X_ORIGIN_SECRET', 'HTTP_CF_ORIGIN_SECRET'] as $secret_hdr_key) {
                if (isset($_SERVER[$secret_hdr_key]) && is_string($_SERVER[$secret_hdr_key])) {
                    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exact secret bytes are length/control-char validated without lossy sanitization before hash_equals()
                    $candidate_secret = (string) wp_unslash($_SERVER[$secret_hdr_key]);
                    if ($candidate_secret !== '') {
                        $incoming_secret = $candidate_secret;
                        break;
                    }
                }
            }
            $sec_len = strlen($incoming_secret);
            $valid_secret_shape = ($sec_len > 0 && $sec_len <= 512 && preg_match('/[\x00-\x1F\x7F]/', $incoming_secret) !== 1);
            if (!$valid_secret_shape || !hash_equals($cf_origin_secret, $incoming_secret)) {
                $cf_trusted = false;
            }
        }

        // Priority 1: Cloudflare CF-Connecting-IP (ONLY if trust mode allows AND connecting peer is a verified Cloudflare proxy IP)
        if ($cf_trusted && !empty($_SERVER['HTTP_CF_CONNECTING_IP']) && self::is_cloudflare_ip($remote_addr)) {
            $cf_ip = trim(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
            if (stripos($cf_ip, '::ffff:') === 0) {
                $mapped_cf = substr($cf_ip, 7);
                if (filter_var($mapped_cf, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $cf_ip = $mapped_cf;
                }
            }
            if (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
                $resolved_ip = $cf_ip;
            }
        }

        // Priority 2: X-Forwarded-For (Multi-proxy chain defense: reverse order traversal)
        if (empty($resolved_ip) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $raw_xff = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
            $parts = array_map('sanitize_text_field', array_map('trim', explode(',', $raw_xff)));
            $reversed = array_reverse($parts);
            foreach ($reversed as $candidate) {
                if (stripos($candidate, '::ffff:') === 0) {
                    $mapped_c = substr($candidate, 7);
                    if (filter_var($mapped_c, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $candidate = $mapped_c;
                    }
                }
                if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                    if (!self::is_trusted_proxy($candidate)) {
                        $resolved_ip = $candidate;
                        break;
                    }
                }
            }
        }

        self::$real_ip = $resolved_ip ?: $remote_addr;
        if (stripos(self::$real_ip, '::ffff:') === 0) {
            $mapped_final = substr(self::$real_ip, 7);
            if (filter_var($mapped_final, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                self::$real_ip = $mapped_final;
            }
        }
        return self::$real_ip;
    }

    /**
     * Reset the cached resolved IP address (used for testing and lifecycle hooks).
     *
     * @return void
     */
    public static function reset_client_ip_cache(): void {
        self::$real_ip = null;
    }

    public const CRON_HOOK_REFRESH_CIDRS = 'webcareproscan_refresh_cf_cidrs';
    public const OPTION_CF_CIDR_CACHE     = 'webcareproscan_cf_cidr_cache';

    /**
     * Official Cloudflare IPv4 and IPv6 CIDR ranges for Anycast edge proxy verification.
     * Checks persistent cache first; falls back to embedded defaults.
     *
     * @return array<int, string>
     */
    public static function get_cloudflare_ip_ranges(): array {
        $cached = get_option(self::OPTION_CF_CIDR_CACHE, []);
        if (is_array($cached) && !empty($cached)) {
            return $cached;
        }

        return [
            // Cloudflare IPv4 CIDRs
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '173.245.48.0/20',
            '188.114.96.0/20',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',

            // Cloudflare IPv6 CIDRs
            '2400:cb00::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2405:b500::/32',
            '2405:8100::/32',
            '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];
    }

    /**
     * Asynchronously refresh official Cloudflare IPv4 and IPv6 CIDR lists from cloudflare.com.
     *
     * @return bool True if CIDRs were refreshed, false otherwise.
     */
    public static function refresh_cloudflare_cidrs(): bool {
        // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Official Cloudflare plain-text Anycast CIDR IP list endpoint, not an offloaded asset
        $v4_res = wp_safe_remote_get('https://www.cloudflare.com/ips-v4', ['timeout' => 5]);
        // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Official Cloudflare plain-text Anycast CIDR IP list endpoint, not an offloaded asset
        $v6_res = wp_safe_remote_get('https://www.cloudflare.com/ips-v6', ['timeout' => 5]);

        if (is_wp_error($v4_res) || is_wp_error($v6_res)) {
            return false;
        }

        $v4_body = wp_remote_retrieve_body($v4_res);
        $v6_body = wp_remote_retrieve_body($v6_res);

        $v4_lines = array_filter(array_map('trim', explode("\n", $v4_body)));
        $v6_lines = array_filter(array_map('trim', explode("\n", $v6_body)));

        $valid_cidrs = [];
        foreach (array_merge($v4_lines, $v6_lines) as $cidr) {
            if ($cidr === '') {
                continue;
            }
            if (str_contains($cidr, '/')) {
                [$sub, $bits] = explode('/', $cidr, 2);
                if (filter_var($sub, FILTER_VALIDATE_IP) && ctype_digit($bits)) {
                    $valid_cidrs[] = $cidr;
                }
            }
        }

        if (count($valid_cidrs) >= 15) {
            update_option(self::OPTION_CF_CIDR_CACHE, $valid_cidrs, false);
            return true;
        }

        return false;
    }

    /**
     * Check if an IPv4 or IPv6 address belongs to Cloudflare's Anycast Proxy ranges.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        foreach (self::get_cloudflare_ip_ranges() as $cidr) {
            if (self::ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a remote connecting IP address belongs to a verified trusted proxy.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_trusted_proxy(string $ip): bool {
        $ip = trim($ip);
        if (stripos($ip, '::ffff:') === 0) {
            $mapped_v4 = substr($ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped_v4;
            }
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // 1. Check Cloudflare edge network proxy ranges
        if (self::is_cloudflare_ip($ip)) {
            return true;
        }

        // 2. Check explicitly configured reverse proxy CIDRs/IPs
        $configured = self::get_configured_trusted_proxies();
        foreach ($configured as $range) {
            if (self::ip_in_range($ip, $range)) {
                return true;
            }
        }

        // 3. Localhost / loopback / internal reverse proxy check
        $is_local_or_private = ($ip === '127.0.0.1' || $ip === '::1' || self::is_private_ip($ip));
        if ($is_local_or_private) {
            if (defined('WEBCARE_TRUST_LOCAL_PROXY') && WEBCARE_TRUST_LOCAL_PROXY) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP address belongs to private or loopback ranges (RFC 1918 / RFC 4193).
     *
     * @param string $ip
     * @return bool
     */
    public static function is_private_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Retrieve array of configured trusted proxy IPs/CIDRs from constants, environment, or settings.
     *
     * @return array<int, string>
     */
    public static function get_configured_trusted_proxies(): array {
        $proxies = [];

        // 1. From constant WEBCARE_TRUSTED_PROXIES
        if (defined('WEBCARE_TRUSTED_PROXIES') && is_string(WEBCARE_TRUSTED_PROXIES) && WEBCARE_TRUSTED_PROXIES !== '') {
            $parts = preg_split('/[\s,;]+/', WEBCARE_TRUSTED_PROXIES);
            if (is_array($parts)) {
                foreach ($parts as $p) {
                    $p = trim($p);
                    if ($p !== '') {
                        $proxies[] = $p;
                    }
                }
            }
        }

        // 2. From environment variable WEBCARE_TRUSTED_PROXIES
        $env_proxies = getenv('WEBCARE_TRUSTED_PROXIES') ?: (isset($_ENV['WEBCARE_TRUSTED_PROXIES']) ? sanitize_text_field(wp_unslash($_ENV['WEBCARE_TRUSTED_PROXIES'])) : '');
        if (!empty($env_proxies) && is_string($env_proxies)) {
            $parts = preg_split('/[\s,;]+/', $env_proxies);
            if (is_array($parts)) {
                foreach ($parts as $p) {
                    $p = trim($p);
                    if ($p !== '') {
                        $proxies[] = $p;
                    }
                }
            }
        }

        // 3. From WordPress option and SettingsManager proxy keys
        $opt_sources = [
            function_exists('get_option') ? get_option('webcareproscan_trusted_proxies', '') : '',
            class_exists(SettingsManager::class) ? SettingsManager::get('trusted_proxy_ips', '') : '',
            class_exists(SettingsManager::class) ? SettingsManager::get('waf_trusted_proxy_cidrs', '') : '',
        ];
        foreach ($opt_sources as $opt) {
            if (!empty($opt) && is_string($opt)) {
                $parts = preg_split('/[\s,;]+/', $opt);
                if (is_array($parts)) {
                    foreach ($parts as $p) {
                        $p = trim($p);
                        if ($p !== '') {
                            $proxies[] = $p;
                        }
                    }
                }
            }
        }

        return array_values(array_unique($proxies));
    }

    /**
     * Check if an IP address belongs to the server itself (Loopback or Host Origin IPv4/IPv6).
     *
     * @param string $ip
     * @return bool
     */
    public static function is_server_origin_or_loopback(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Standard loopback
        if (in_array($ip, ['127.0.0.1', '::1'], true)) {
            return true;
        }

        // 2. Direct server environment address
        if (!empty($_SERVER['SERVER_ADDR']) && $ip === $_SERVER['SERVER_ADDR']) {
            return true;
        }
        if (!empty($_SERVER['LOCAL_ADDR']) && $ip === $_SERVER['LOCAL_ADDR']) {
            return true;
        }

        // 3. Compare against all resolved ServerInfo IPs (IPv4 and IPv6) with binary normalization
        if (class_exists(ServerInfo::class)) {
            $all_server_ips = ServerInfo::get_all_server_ips();
            if (in_array($ip, $all_server_ips, true)) {
                return true;
            }
            $ip_bin = @inet_pton($ip);
            if ($ip_bin !== false) {
                foreach ($all_server_ips as $sip) {
                    $sip_bin = @inet_pton($sip);
                    if ($sip_bin !== false && $sip_bin === $ip_bin) {
                        return true;
                    }
                }
            }
        }

        // 4. Local Docker / Container bridge gateway in local environments
        if (str_starts_with($ip, '172.17.') || str_starts_with($ip, '172.18.') || str_starts_with($ip, '172.19.') || str_starts_with($ip, '10.0.2.')) {
            $site_host = function_exists('home_url') ? (string) wp_parse_url(home_url(), PHP_URL_HOST) : '';
            $req_host  = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
            $combined  = strtolower($site_host . ' ' . $req_host);
            if (str_contains($combined, 'localhost') || str_contains($combined, '127.0.0.1') || str_contains($combined, '.local') || str_contains($combined, '.test')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP address falls within a given CIDR subnet or matches a single IP.
     * Supports both IPv4 and IPv6 CIDR notations.
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    public static function ip_in_range(string $ip, string $range): bool {
        $ip = trim($ip);
        $range = trim($range);

        // Normalize IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        if (stripos($ip, '::ffff:') === 0) {
            $mapped_v4 = substr($ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped_v4;
            }
        }

        if (!str_contains($range, '/')) {
            if (stripos($range, '::ffff:') === 0) {
                $mapped_r = substr($range, 7);
                if (filter_var($mapped_r, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $range = $mapped_r;
                }
            }
            return $ip === $range;
        }

        $parts = explode('/', $range, 2);
        if (count($parts) !== 2 || !ctype_digit(trim($parts[1]))) {
            return false;
        }

        $subnet = trim($parts[0]);
        if (stripos($subnet, '::ffff:') === 0) {
            $mapped_sub = substr($subnet, 7);
            if (filter_var($mapped_sub, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $subnet = $mapped_sub;
            }
        }
        $bits = (int) trim($parts[1]);

        // IPv4 check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return false;
            }
            if ($bits < 0 || $bits > 32) {
                return false;
            }
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            if ($ip_long === false || $subnet_long === false) {
                return false;
            }
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
            return (($ip_long & $mask) === ($subnet_long & $mask));
        }

        // IPv6 check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return false;
            }
            if ($bits < 0 || $bits > 128) {
                return false;
            }
            $ip_bin = @inet_pton($ip);
            $subnet_bin = @inet_pton($subnet);
            if ($ip_bin === false || $subnet_bin === false) {
                return false;
            }

            $bytes = intdiv($bits, 8);
            if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) {
                return false;
            }

            $rem_bits = $bits % 8;
            if ($rem_bits > 0) {
                $mask = (0xFF << (8 - $rem_bits)) & 0xFF;
                if ((ord($ip_bin[$bytes]) & $mask) !== (ord($subnet_bin[$bytes]) & $mask)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
}
