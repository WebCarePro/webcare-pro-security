<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AllowlistManager
 *
 * Manages IP, URL, and targeted allowlist rules, rDNS validations, ASN lookups,
 * and enforces confirmed-exploit precedence.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AllowlistManager {

    private const SUPPORTED_HMAC_PROVIDERS = ['stripe', 'shopify', 'github', 'generic_sha256'];

    /**
     * Test seam allowing unit tests to simulate RequestBodyReader unavailability without unloading classes.
     */
    public static bool $force_body_reader_unavailable_for_tests = false;

    /**
     * Check whether the bounded RequestBodyReader is available.
     */
    private static function is_bounded_body_reader_available(): bool {
        if (self::$force_body_reader_unavailable_for_tests) {
            return false;
        }
        return class_exists(RequestBodyReader::class);
    }

    /**
     * Return canonical supported cryptographic webhook HMAC providers.
     *
     * @return list<string>
     */
    public static function get_supported_hmac_providers(): array {
        return self::SUPPORTED_HMAC_PROVIDERS;
    }

    /**
     * Return per-provider replay defense posture metadata.
     * - stripe: signed t= timestamp window + AtomicNonceStore v1 signature consumption
     * - github: X-Hub-Signature-256 + mandatory X-GitHub-Delivery UUID consumption
     * - shopify: X-Shopify-Hmac-Sha256 + X-Shopify-Webhook-Id consumption when header is present (signature_only if absent)
     * - generic_sha256: payload HMAC integrity only (no built-in timestamp/replay header unless paired with IP/CIDR pinning)
     */
    public static function get_provider_replay_capability(string $provider): string {
        return match (strtolower(trim($provider))) {
            'stripe'         => 'signed_timestamp_and_nonce',
            'github'         => 'delivery_id_nonce',
            'shopify'        => 'optional_event_id_nonce',
            'generic_sha256' => 'signature_only',
            default          => 'none',
        };
    }

    public static function is_ip_whitelisted(string $ip, ?string $whitelist_str = null): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        if ($whitelist_str === null) {
            $settings = SettingsManager::get_settings();
            $whitelist_str = $settings['waf_whitelisted_ips'] ?? '';
        }

        // 0. Auto-accept server's own origin IP (IPv4 and IPv6) and loopback addresses across all sites
        if (FirewallEngine::is_server_origin_or_loopback($ip)) {
            return true;
        }

        // Emergency wp-config override constant: WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP
        if (defined('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP')) {
            $override_ips = is_array(WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP) ? WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP : explode(',', (string) WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP);
            foreach ($override_ips as $override_ip) {
                $override_ip = trim($override_ip);
                if (!empty($override_ip)) {
                    if ($override_ip === $ip || (strpos($override_ip, '/') !== false && FirewallEngine::ip_in_range($ip, $override_ip))) {
                        return true;
                    }
                }
            }
        }

        if (empty($whitelist_str)) {
            return false;
        }

        $lines = explode("\n", str_replace("\r", "", $whitelist_str));
        foreach ($lines as $line) {
            $clean = trim($line);
            if ($clean === '') {
                continue;
            }
            if ($clean === $ip) {
                return true;
            }
            // Simple CIDR / subnet support
            if (strpos($clean, '/') !== false && FirewallEngine::ip_in_range($ip, $clean)) {
                return true;
            }
        }

        // Check active temporary customer/merchant bypass allowlists (e.g. 24-hour customer unblock)
        if (get_transient('webcareproscan_temp_allow_' . md5($ip))) {
            return true;
        }

        return false;
    }

    /**
     * Check if a given request URI is whitelisted
     */
    public static function is_url_whitelisted(string $uri, string $whitelist_text): bool {
        if (empty(trim($whitelist_text))) {
            return false;
        }

        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $whitelist_text))));
        $path  = (string) wp_parse_url($uri, PHP_URL_PATH);

        foreach ($lines as $allowed) {
            if ($allowed === '') {
                continue;
            }
            // Strip any query or hash from whitelist line for comparison
            $allowed_clean = (string) wp_parse_url($allowed, PHP_URL_PATH);
            if (empty($allowed_clean)) {
                $allowed_clean = $allowed;
            }

            // Exact match or prefix match with boundary check (prevents / from wiping out entire whitelist)
            $trimmed = rtrim($allowed_clean, '/');
            if ($uri === $allowed || $path === $allowed_clean || ($trimmed !== '' && ($path === $trimmed || strpos($path, $trimmed . '/') === 0))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compare the request path with the configured support URL using an exact path boundary.
     *
     * @param string $request_uri
     * @param string $configured_contact_url
     * @return bool
     */
    public static function is_configured_support_path(string $request_uri, string $configured_contact_url): bool {
        $contact_path = rtrim(strtolower((string) wp_parse_url($configured_contact_url, PHP_URL_PATH)), '/');
        $request_path = rtrim(strtolower((string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '')), '/');

        return $contact_path !== '' && $contact_path !== '/' && $request_path === $contact_path;
    }

    /**
     * Check if an incoming request matches any Targeted Allowlist Rules (User-Agent, Endpoint, and optional IP)
     * If matched, returns the matching rule definition array, or null if no match.
     */
    public static function match_targeted_allowlist_rule(string $uri, string $user_agent, string $ip, string $method, array $rules): ?array {
        if (empty($rules)) {
            return null;
        }

        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        if (empty($path)) {
            $path = '/';
        }
        $upper_method = strtoupper($method);

        foreach ($rules as $rule) {
            if (empty($rule['enabled'])) {
                continue;
            }

            // Security Hardening (S2 Finding 3): Reject allowlist rules that have NO effective constraints.
            // An allowlist rule must contain at least one non-empty IP/CIDR, canonical endpoint, verified rDNS hostname, or verified ASN.
            // A rule specifying ONLY User-Agents or having empty arrays for all criteria is rejected.
            $has_ip_constraint       = !empty($rule['ip_addresses']) && is_array($rule['ip_addresses']) && !empty(array_filter($rule['ip_addresses'], fn($v) => trim((string)$v) !== ''));
            $has_endpoint_constraint = !empty($rule['endpoints']) && is_array($rule['endpoints']) && !empty(array_filter($rule['endpoints'], fn($v) => trim((string)$v) !== ''));
            $has_hostname_constraint = !empty($rule['hostnames']) && is_array($rule['hostnames']) && !empty(array_filter($rule['hostnames'], fn($v) => trim((string)$v) !== ''));
            $has_asn_constraint      = !empty($rule['asns']) && is_array($rule['asns']) && !empty(array_filter($rule['asns'], fn($v) => trim((string)$v) !== ''));

            if (!$has_ip_constraint && !$has_endpoint_constraint && !$has_hostname_constraint && !$has_asn_constraint) {
                continue; // Reject empty or unanchored match-all allowlist rule
            }

            // 1. Method Check
            $allowed_methods = !empty($rule['methods']) && is_array($rule['methods']) ? array_map('strtoupper', $rule['methods']) : ['ALL'];
            if (!in_array('ALL', $allowed_methods, true) && !in_array($upper_method, $allowed_methods, true)) {
                continue;
            }

            // 2. IP / Subnet Check (If empty, any IP is allowed)
            $rule_ips = !empty($rule['ip_addresses']) && is_array($rule['ip_addresses']) ? $rule['ip_addresses'] : [];
            if (!empty($rule_ips)) {
                $ip_matched = false;
                foreach ($rule_ips as $target_ip) {
                    $target_ip = trim($target_ip);
                    if ($target_ip === '') {
                        continue;
                    }
                    if ($target_ip === $ip || (strpos($target_ip, '/') !== false && FirewallEngine::ip_in_range($ip, $target_ip))) {
                        $ip_matched = true;
                        break;
                    }
                }
                if (!$ip_matched) {
                    continue; // IP condition specified but didn't match
                }
            }

            // 3. Endpoint / URL Check (If empty, any endpoint passes)
            $rule_endpoints = !empty($rule['endpoints']) && is_array($rule['endpoints']) ? $rule['endpoints'] : [];
            if (!empty($rule_endpoints)) {
                $endpoint_matched = false;
                foreach ($rule_endpoints as $endpoint_pattern) {
                    $endpoint_pattern = trim((string) $endpoint_pattern);
                    if ($endpoint_pattern === '') {
                        continue;
                    }
                    // Defense in depth: Reject universal wildcards or path traversal dots
                    if ($endpoint_pattern === '*' || $endpoint_pattern === '/*' || $endpoint_pattern === '/**' || str_contains($endpoint_pattern, '..')) {
                        continue;
                    }

                    // Strip host/query for matching
                    $clean_pattern = (string) wp_parse_url($endpoint_pattern, PHP_URL_PATH);
                    if (empty($clean_pattern)) {
                        $clean_pattern = $endpoint_pattern;
                    }

                    // Canonicalize leading slash and multi-slashes
                    if (!str_starts_with($clean_pattern, '/')) {
                        $clean_pattern = '/' . $clean_pattern;
                    }
                    $clean_pattern = (string) preg_replace('#/{2,}#', '/', $clean_pattern);
                    if ($clean_pattern === '/' || $clean_pattern === '/*') {
                        continue;
                    }

                    // Check exact, wildcard, or prefix
                    if (strpos($clean_pattern, '*') !== false) {
                        $regex = '#^' . str_replace('\*', '.*', preg_quote($clean_pattern, '#')) . '$#i';
                        if (preg_match($regex, $uri) || preg_match($regex, $path)) {
                            $endpoint_matched = true;
                            break;
                        }
                    } else {
                        // Exact match or prefix match with boundary check
                        $trimmed = rtrim($clean_pattern, '/');
                        if ($uri === $clean_pattern || $path === $clean_pattern || ($trimmed !== '' && ($path === $trimmed || strpos($path, $trimmed . '/') === 0))) {
                            $endpoint_matched = true;
                            break;
                        }
                    }
                }
                if (!$endpoint_matched) {
                    continue; // Endpoint condition specified but didn't match
                }
            }

            // 4. User-Agent Check (If empty, any User-Agent passes)
            $rule_uas = !empty($rule['user_agents']) && is_array($rule['user_agents']) ? $rule['user_agents'] : [];
            if (!empty($rule_uas)) {
                $ua_matched = false;
                foreach ($rule_uas as $ua_pattern) {
                    $ua_pattern = trim($ua_pattern);
                    if ($ua_pattern === '') {
                        continue;
                    }
                    if (strpos($ua_pattern, '*') !== false) {
                        $regex = '#^' . str_replace('\*', '.*', preg_quote($ua_pattern, '#')) . '$#i';
                        if (preg_match($regex, $user_agent)) {
                            $ua_matched = true;
                            break;
                        }
                    } else {
                        if (stripos($user_agent, $ua_pattern) !== false) {
                            $ua_matched = true;
                            break;
                        }
                    }
                }
                if (!$ua_matched) {
                    continue; // User-Agent condition specified but didn't match
                }
            }

            // 5. Hostname / Reverse DNS (rDNS) Verification (If specified, verify IP resolves to allowed domain/hostname)
            $rule_hostnames = !empty($rule['hostnames']) && is_array($rule['hostnames']) ? $rule['hostnames'] : [];
            if (!empty($rule_hostnames)) {
                $host_matched = false;
                foreach ($rule_hostnames as $allowed_host) {
                    $allowed_host = trim($allowed_host);
                    if ($allowed_host === '') {
                        continue;
                    }
                    if (self::verify_rdns_domain($ip, $allowed_host)) {
                        $host_matched = true;
                        break;
                    }
                }
                if (!$host_matched) {
                    continue; // Hostname/rDNS condition specified but didn't match
                }
            }

            // 6. Autonomous System Number (ASN) Check (If specified, verify client ASN)
            $rule_asns = !empty($rule['asns']) && is_array($rule['asns']) ? $rule['asns'] : [];
            if (!empty($rule_asns)) {
                $client_asn = self::get_client_asn($ip);
                if (empty($client_asn)) {
                    continue; // ASN specified but could not be determined
                }
                $asn_matched = false;
                foreach ($rule_asns as $target_asn) {
                    $clean_target = strtoupper(trim($target_asn));
                    if ($clean_target === '') {
                        continue;
                    }
                    if ($clean_target === $client_asn || $clean_target === ('AS' . $client_asn) || ('AS' . $clean_target) === $client_asn) {
                        $asn_matched = true;
                        break;
                    }
                }
                if (!$asn_matched) {
                    continue; // ASN condition specified but didn't match
                }
            }

            // 7. Required HTTP Headers Presence (required_header_presence) & Cryptographic HMAC Verification
            // Note: This checks the presence of headers and verifies HMAC signature if a webhook secret is configured.
            $rule_headers = !empty($rule['required_headers']) && is_array($rule['required_headers']) ? $rule['required_headers'] : [];
            if (!empty($rule_headers)) {
                $headers_matched = true;
                foreach ($rule_headers as $req_header) {
                    $req_header = trim($req_header);
                    if ($req_header === '') {
                        continue;
                    }
                    // Normalize to HTTP_ format
                    $server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $req_header));
                    if (!isset($_SERVER[$server_key]) && !isset($_SERVER[strtoupper(str_replace('-', '_', $req_header))])) {
                        $headers_matched = false;
                        break;
                    }
                }
                if (!$headers_matched) {
                    continue; // Required header missing
                }
            }

            // Cryptographic Webhook HMAC Signature Verification (Strictly Fail-Closed)
            $raw_provider  = strtolower(trim((string) ($rule['webhook_hmac_provider'] ?? 'none')));
            $hmac_provider = $raw_provider === '' ? 'none' : $raw_provider;
            $secret_ref    = trim((string) ($rule['webhook_secret_ref'] ?? ''));

            // Fail closed whenever HMAC protection is declared OR a secret reference is attached
            if ($hmac_provider !== 'none' || $secret_ref !== '') {
                if (!in_array($hmac_provider, self::SUPPORTED_HMAC_PROVIDERS, true)) {
                    continue; // Unsupported or 'none' provider with secret_ref -> fail closed
                }
                if ($secret_ref === '') {
                    continue; // Provider declared without secret_ref -> fail closed
                }
                $decrypted_secret = self::get_webhook_secret_by_ref($secret_ref);
                if ($decrypted_secret === '') {
                    continue; // Missing, unreadable, or undecryptable SecretVault entry -> fail closed
                }

                // Read bounded body stream strictly via RequestBodyReader (never fall back to unbounded php://input).
                // Fail closed if RequestBodyReader is unavailable, truncated, or unreadable.
                if (!self::is_bounded_body_reader_available()) {
                    continue;
                }
                if (RequestBodyReader::is_truncated() || RequestBodyReader::has_read_failed()) {
                    continue; // Truncated or failed body stream cannot validly verify cryptographic HMAC
                }
                $raw_body = RequestBodyReader::get_bounded_body();

                $tolerance = isset($rule['webhook_replay_window_sec'])
                    ? max(30, min(900, (int) $rule['webhook_replay_window_sec']))
                    : 300;

                if (!self::verify_webhook_hmac($hmac_provider, $decrypted_secret, $raw_body, $tolerance)) {
                    continue; // Invalid signature, missing delivery ID, or replayed delivery -> fail closed
                }

                if ($hmac_provider === 'shopify') {
                    $shopify_wh_id = isset($_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'])
                        ? trim(sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'])))
                        : '';
                    $rule['replay_protection'] = $shopify_wh_id !== '' ? 'event_id_nonce' : 'signature_only';
                } else {
                    $rule['replay_protection'] = self::get_provider_replay_capability($hmac_provider);
                }
            }

            // 8. Parameter-Scoped Exemption Check (PR 1.4: route_path + param_key + user_role)
            $rule_param = trim((string) ($rule['param_key'] ?? ''));
            if ($rule_param !== '') {
                // If rule specifies a param_key, check if that param exists in GET or POST
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
                $param_present = isset($_GET[$rule_param]) || isset($_POST[$rule_param]) || isset($_REQUEST[$rule_param]);
                if (!$param_present) {
                    continue; // Specified parameter not present in incoming request
                }
            }

            // 9. User Role Constraint Check (e.g. 'administrator', 'editor', 'customer')
            $rule_roles = !empty($rule['user_roles']) && is_array($rule['user_roles']) ? $rule['user_roles'] : (!empty($rule['user_role']) ? [(string) $rule['user_role']] : []);
            if (!empty($rule_roles)) {
                $role_matched = false;
                if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('wp_get_current_user')) {
                    $current_user = wp_get_current_user();
                    $user_roles = (array) ($current_user->roles ?? []);
                    foreach ($rule_roles as $req_role) {
                        if (in_array(strtolower(trim($req_role)), $user_roles, true)) {
                            $role_matched = true;
                            break;
                        }
                    }
                }
                if (!$role_matched) {
                    continue; // User role condition not satisfied
                }
            }

            // If we reached here, all specified conditions matched!
            return $rule;
        }

        return null;
    }

    /**
     * Cryptographically verify IP reverse DNS (PTR) with forward DNS (A) resolution.
     * Caches verdict in WordPress transient for 24 hours to prevent DNS resolution latency.
     */
    public static function verify_rdns_domain(string $ip, string $target_domain): bool {
        $clean_target = strtolower(trim(ltrim($target_domain, '*.')));
        if ($clean_target === '') {
            return false;
        }

        $transient_key = 'webcare_rdns_' . md5($ip . '_' . $clean_target);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return ($cached === 'valid');
        }

        $is_valid = false;
        $hostname = @gethostbyaddr($ip);
        if (!empty($hostname) && $hostname !== $ip) {
            $hostname_lower = strtolower($hostname);
            if ($hostname_lower === $clean_target || str_ends_with($hostname_lower, '.' . $clean_target)) {
                // Forward DNS check to prevent PTR spoofing
                $resolved_ip = @gethostbyname($hostname);
                if ($resolved_ip === $ip) {
                    $is_valid = true;
                }
            }
        }

        // Cache 24 hours if valid, 2 hours if failed
        set_transient($transient_key, $is_valid ? 'valid' : 'invalid', $is_valid ? DAY_IN_SECONDS : 7200);
        return $is_valid;
    }

    /**
     * Resolve Client Autonomous System Number (ASN).
     * Checks Cloudflare CF-Connecting-ASN header (only if connecting peer is verified Cloudflare IP), or Team Cymru DNS lookup.
     */
    public static function get_client_asn(string $ip): string {
        // 1. Direct Cloudflare Edge ASN Header - ONLY trust if connecting peer is a verified Cloudflare proxy IP
        if (!empty($_SERVER['HTTP_CF_CONNECTING_ASN'])) {
            $connecting_peer = ClientIpResolver::get_connecting_peer_ip();
            if (ClientIpResolver::is_cloudflare_ip($connecting_peer)) {
                return strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_ASN'])));
            }
        }

        // 2. Check transient cache
        $transient_key = 'webcare_asn_' . md5($ip);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return (string) $cached;
        }

        // 3. Reverse DNS check against Team Cymru ASN mapping DNS service (origin.asn.cymru.com)
        $asn = '';
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $octets = explode('.', $ip);
            $rev_ip = implode('.', array_reverse($octets));
            $query_host = $rev_ip . '.origin.asn.cymru.com';
            $txt_records = @dns_get_record($query_host, DNS_TXT);
            if (!empty($txt_records[0]['txt'])) {
                // Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
                $parts = explode('|', $txt_records[0]['txt']);
                $raw_asn = trim($parts[0] ?? '');
                if (!empty($raw_asn) && is_numeric($raw_asn)) {
                    $asn = 'AS' . $raw_asn;
                }
            }
        }

        set_transient($transient_key, $asn, !empty($asn) ? WEEK_IN_SECONDS : DAY_IN_SECONDS);
        return $asn;
    }

    /**
     * Check allowlist context flags for an IP.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed>|null $rule
     * @return array{is_whitelisted: bool, full_bypass: bool, rule_bypass: bool, is_admin: bool}
     */
    /**
     * Determine if an IP matches the configured whitelist and whether the current session qualifies for complete bypass.
     *
     * Two-Tier Context-Aware Architecture:
     * - Tier 1 (Pre-Auth): IP is in whitelist, but user is NOT logged in as Administrator.
     *   Can bypass operational/rate-limiting/debug rules, but CANNOT bypass critical exploits (SQLi, Webshell, RCE, LFI).
     * - Tier 2 (Post-Auth): IP is in whitelist AND user is verified Authenticated Administrator.
     *   Full developer/administrator bypass across all firewall checks.
     *
     * @param string $client_ip
     * @param array  $settings
     * @return array [ 'is_whitelisted' => bool, 'is_admin' => bool, 'full_bypass' => bool ]
     */
    public static function check_ip_whitelist_context(string $client_ip, array $settings, ?array $rule = null): array {
        $is_admin = FirewallEngine::is_authenticated_administrator();
        $whitelist_str = $settings['waf_whitelisted_ips'] ?? '';
        $is_whitelisted = self::is_ip_whitelisted($client_ip, $whitelist_str);

        // Auto-whitelist verified authenticated administrator sessions operating strictly within WebCare Pro REST API
        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $clean_uri = str_replace(["\0", "\r", "\n"], '', $req_uri);
        $norm_rest_route = FirewallEngine::resolve_normalized_rest_route($clean_uri);
        $is_admin_context = $is_admin && str_starts_with($norm_rest_route, '/webcare-pro-security/v1/');

        if ($is_admin_context) {
            return [
                'is_whitelisted' => true,
                'is_admin'       => true,
                'full_bypass'    => true,
                'rule_bypass'    => false,
            ];
        }

        if (!$is_whitelisted) {
            return [
                'is_whitelisted' => false,
                'is_admin'       => $is_admin,
                'full_bypass'    => false,
                'rule_bypass'    => false,
            ];
        }

        // Check if this IP has granular rule or category scoping
        $all_meta = FirewallEngine::get_all_whitelist_meta();
        $meta = $all_meta[$client_ip] ?? null;

        if ($meta && !empty($meta['expires_at']) && time() > (int) $meta['expires_at']) {
            return [
                'is_whitelisted' => false,
                'is_admin'       => $is_admin,
                'full_bypass'    => false,
                'rule_bypass'    => false,
            ];
        }

        $rule_bypass = false;
        if ($meta && !empty($meta['scope']) && $meta['scope'] !== 'global') {
            $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            $endpoint_allowed = empty($meta['endpoint']) || strpos($req_uri, $meta['endpoint']) !== false;

            if ($endpoint_allowed && $rule !== null) {
                if ($meta['scope'] === 'rule') {
                    $rule_id = (string) ($rule['id'] ?? '');
                    $allowed_rules = (array) ($meta['allowed_rules'] ?? []);
                    if (!empty($rule_id) && in_array($rule_id, $allowed_rules, true)) {
                        $rule_bypass = true;
                    }
                } elseif ($meta['scope'] === 'category') {
                    $rule_cat = (string) ($rule['category'] ?? '');
                    $allowed_cats = (array) ($meta['allowed_cats'] ?? []);
                    if (!empty($rule_cat) && in_array($rule_cat, $allowed_cats, true)) {
                        $rule_bypass = true;
                    }
                }
            }

            // Scoped rule allowlist: only bypasses if matched!
            return [
                'is_whitelisted' => true,
                'is_admin'       => $is_admin,
                'full_bypass'    => false,
                'rule_bypass'    => $rule_bypass,
            ];
        }

        $is_admin = FirewallEngine::is_authenticated_administrator();
        $require_admin = isset($settings['waf_whitelist_require_admin']) ? !empty($settings['waf_whitelist_require_admin']) : true;

        // If require_admin is FALSE, all whitelisted traffic gets full bypass (classic mode).
        // If require_admin is TRUE, only authenticated admins get full bypass; unauthenticated get tiered pre-auth protection.
        $full_bypass = !$require_admin || $is_admin;

        return [
            'is_whitelisted' => true,
            'is_admin'       => $is_admin,
            'full_bypass'    => $full_bypass,
            'rule_bypass'    => false,
        ];
    }

    /**
     * Authoritatively determines if an IP allowlist context permits bypassing a firewall rule violation.
     * Enforces the invariant that pre-authenticated traffic can NEVER bypass confirmed exploits or critical categories.
     *
     * @param bool $is_admin             Whether the session is a verified authenticated administrator.
     * @param bool $full_bypass          Whether global full bypass is granted.
     * @param bool $rule_bypass          Whether scoped rule/category bypass matched.
     * @param bool $is_critical_exploit  Whether the rule is a confirmed exploit or critical attack category.
     * @return bool True if bypass is permitted, false otherwise.
     */
    public static function can_ip_whitelist_bypass_rule(bool $is_admin, bool $full_bypass, bool $rule_bypass, bool $is_critical_exploit): bool {
        if ($is_admin) {
            return $full_bypass || $rule_bypass || !$is_critical_exploit;
        }

        // Pre-authenticated / unauthenticated traffic: strictly prohibited from bypassing critical exploits or confirmed exploit signatures
        return !$is_critical_exploit && ($full_bypass || $rule_bypass);
    }

    /**
     * Resolve and decrypt webhook secret by vault reference.
     * Strictly fails closed (returns '') if SecretVault is unavailable, entry is missing,
     * entry is unencrypted plaintext, or AEAD decryption/authentication fails.
     */
    public static function get_webhook_secret_by_ref(string $secret_ref): string {
        $secret_ref = trim($secret_ref);
        if ($secret_ref === '' || !class_exists(\WebCareProScanner\Security\SecretVault::class)) {
            return '';
        }
        $vault = get_option('webcareproscan_vault_webhook_secrets', []);
        if (!is_array($vault) || empty($vault[$secret_ref]) || !is_string($vault[$secret_ref])) {
            return '';
        }

        $encrypted = $vault[$secret_ref];
        if (!\WebCareProScanner\Security\SecretVault::is_encrypted($encrypted)) {
            return ''; // Never trust or return unencrypted vault strings
        }

        $decrypted = \WebCareProScanner\Security\SecretVault::decrypt($encrypted);
        return is_string($decrypted) && $decrypted !== '' ? $decrypted : '';
    }

    /**
     * Store and encrypt a webhook secret in dedicated SecretVault storage under an opaque ref.
     * Never falls back to plaintext storage and verifies option persistence.
     */
    public static function store_webhook_secret(string $secret_ref, string $plaintext_secret): bool {
        $secret_ref = trim($secret_ref);
        if ($secret_ref === '' || $plaintext_secret === '') {
            return false;
        }

        if (!class_exists(\WebCareProScanner\Security\SecretVault::class)) {
            return false;
        }

        try {
            $encrypted = \WebCareProScanner\Security\SecretVault::encrypt($plaintext_secret);
        } catch (\Throwable) {
            return false;
        }

        if (!is_string($encrypted) || $encrypted === '' || !\WebCareProScanner\Security\SecretVault::is_encrypted($encrypted)) {
            return false;
        }

        $vault = get_option('webcareproscan_vault_webhook_secrets', []);
        if (!is_array($vault)) {
            $vault = [];
        }

        $vault[$secret_ref] = $encrypted;
        $updated = update_option('webcareproscan_vault_webhook_secrets', $vault, false);
        if (!$updated) {
            return false;
        }

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete('webcareproscan_vault_webhook_secrets', 'options');
        }
        $persisted = get_option('webcareproscan_vault_webhook_secrets', []);
        return is_array($persisted) && ($persisted[$secret_ref] ?? null) === $encrypted;
    }

    /**
     * Delete a webhook secret reference from SecretVault storage.
     */
    public static function delete_webhook_secret_by_ref(string $secret_ref): void {
        if ($secret_ref === '') {
            return;
        }
        $vault = get_option('webcareproscan_vault_webhook_secrets', []);
        if (is_array($vault) && isset($vault[$secret_ref])) {
            unset($vault[$secret_ref]);
            update_option('webcareproscan_vault_webhook_secrets', $vault, false);
        }
    }

    /**
     * Verify cryptographic HMAC signature on incoming webhooks with honest per-provider replay protection.
     *
     * Supported providers:
     * - 'stripe': Stripe-Signature header with signed timestamp t= within tolerance + single-use v1 signature consumption via AtomicNonceStore
     * - 'shopify': X-Shopify-Hmac-Sha256 base64 header + X-Shopify-Webhook-Id single-use consumption via AtomicNonceStore (when header is present; signature_only if absent)
     * - 'github': X-Hub-Signature-256 header (sha256=hex) + mandatory X-GitHub-Delivery UUID single-use consumption via AtomicNonceStore
     * - 'generic_sha256': X-Signature-Sha256 / X-Webhook-Signature hex HMAC-SHA256 payload integrity verification ONLY (no built-in timestamp/replay header unless paired with IP/CIDR pinning)
     *
     * @param string $provider
     * @param string $secret
     * @param string $raw_body
     * @param int    $tolerance_seconds
     * @return bool
     */
    public static function verify_webhook_hmac(string $provider, string $secret, string $raw_body, int $tolerance_seconds = 300): bool {
        if ($secret === '') {
            return false;
        }

        $replay_window = max(30, min(900, $tolerance_seconds));
        $normalized_provider = strtolower(trim($provider));

        return match ($normalized_provider) {
            'stripe'         => self::verify_stripe_hmac($secret, $raw_body, $replay_window),
            'shopify'        => self::verify_shopify_hmac($secret, $raw_body, $replay_window),
            'github'         => self::verify_github_hmac($secret, $raw_body, $replay_window),
            'generic_sha256' => self::verify_generic_hmac($secret, $raw_body),
            default          => false,
        };
    }

    /**
     * Read and validate a raw cryptographic header from $_SERVER without lossy sanitization.
     * Enforces unslashing, type, bounded byte length, and strict control-character rejection.
     */
    private static function read_cryptographic_header(string $server_key, int $max_len = 512): string {
        if (!isset($_SERVER[$server_key]) || !is_string($_SERVER[$server_key])) {
            return '';
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Cryptographic header bytes are strictly validated below without lossy text rewriting
        $val = (string) wp_unslash($_SERVER[$server_key]);
        $len = strlen($val);
        if ($len === 0 || $len > $max_len || preg_match('/[\x00-\x1F\x7F]/', $val) === 1) {
            return '';
        }

        return $val;
    }

    private static function verify_stripe_hmac(string $secret, string $raw_body, int $tolerance_seconds): bool {
        $sig_header = self::read_cryptographic_header('HTTP_STRIPE_SIGNATURE', 1024);
        if ($sig_header === '' || preg_match('/^[a-zA-Z0-9_=,\s]+$/', $sig_header) !== 1) {
            return false;
        }

        $timestamp = 0;
        $signatures = [];
        foreach (explode(',', $sig_header) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) === 2) {
                if ($kv[0] === 't' && ctype_digit($kv[1])) {
                    $timestamp = (int) $kv[1];
                } elseif (preg_match('/^v\d+$/', $kv[0]) === 1 && preg_match('/^[a-fA-F0-9]{64}$/', $kv[1]) === 1) {
                    if ($kv[0] === 'v1') {
                        $signatures[] = $kv[1];
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        if ($timestamp <= 0 || empty($signatures)) {
            return false;
        }

        if (abs(time() - $timestamp) > $tolerance_seconds) {
            return false;
        }

        $signed_payload = $timestamp . '.' . $raw_body;
        $expected = hash_hmac('sha256', $signed_payload, $secret);

        $matched_sig = '';
        foreach ($signatures as $sig) {
            if (hash_equals($expected, $sig)) {
                $matched_sig = $sig;
                break;
            }
        }

        if ($matched_sig === '') {
            return false;
        }

        // Bounded replay defense: consume verified v1 signature within replay window
        $sig_hash = hash('sha256', $timestamp . '|' . $matched_sig);
        return \WebCareProScanner\Security\AtomicNonceStore::consume('wh_stripe', $sig_hash, $tolerance_seconds);
    }

    private static function verify_shopify_hmac(string $secret, string $raw_body, int $tolerance_seconds): bool {
        $header = self::read_cryptographic_header('HTTP_X_SHOPIFY_HMAC_SHA256', 128);
        if ($header === '' || preg_match('/^[A-Za-z0-9+\/]{43}=$/', $header) !== 1) {
            return false;
        }

        $calculated = base64_encode(hash_hmac('sha256', $raw_body, $secret, true));
        if (!hash_equals($calculated, $header)) {
            return false;
        }

        // Consume X-Shopify-Webhook-Id when present; if absent, caller marks replay_protection = 'signature_only'
        $webhook_id = isset($_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'])
            ? trim(sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'])))
            : '';
        if ($webhook_id !== '') {
            if (strlen($webhook_id) > 128) {
                return false;
            }
            return \WebCareProScanner\Security\AtomicNonceStore::consume('wh_shopify', $webhook_id, $tolerance_seconds);
        }

        return true;
    }

    private static function verify_github_hmac(string $secret, string $raw_body, int $tolerance_seconds): bool {
        $header = self::read_cryptographic_header('HTTP_X_HUB_SIGNATURE_256', 128);
        if ($header === '' || preg_match('/^sha256=[a-fA-F0-9]{64}$/', $header) !== 1) {
            return false;
        }

        $sig = substr($header, 7);
        $calculated = hash_hmac('sha256', $raw_body, $secret);
        if (!hash_equals($calculated, $sig)) {
            return false;
        }

        // Require and consume unique X-GitHub-Delivery UUID for bounded replay protection
        $delivery_id = isset($_SERVER['HTTP_X_GITHUB_DELIVERY'])
            ? trim(sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_GITHUB_DELIVERY'])))
            : '';
        if ($delivery_id === '' || strlen($delivery_id) > 128) {
            return false;
        }

        return \WebCareProScanner\Security\AtomicNonceStore::consume('wh_github', $delivery_id, $tolerance_seconds);
    }

    /**
     * Verify generic SHA-256 HMAC signature (X-Signature-Sha256 or X-Webhook-Signature).
     * Note: generic_sha256 verifies payload integrity ONLY. It provides no built-in signed
     * timestamp or delivery-ID replay header unless paired with static IP/CIDR pinning.
     */
    private static function verify_generic_hmac(string $secret, string $raw_body): bool {
        $header = self::read_cryptographic_header('HTTP_X_SIGNATURE_SHA256', 128);
        if ($header === '') {
            $header = self::read_cryptographic_header('HTTP_X_WEBHOOK_SIGNATURE', 128);
        }
        if ($header === '' || preg_match('/^(?:sha256=)?[a-fA-F0-9]{64}$/', $header) !== 1) {
            return false;
        }

        $sig = str_starts_with(strtolower($header), 'sha256=') ? substr($header, 7) : $header;
        $calculated = hash_hmac('sha256', $raw_body, $secret);
        return hash_equals($calculated, strtolower($sig));
    }
}
