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

            // Security Hardening (Roadmap Finding 3): A rule specifying ONLY User-Agents
            // without an IP, specific Endpoint, or verified Hostname constraint is easily forged by attackers.
            // Reject allowlist rules that lack at least one network, endpoint, or cryptographic constraint.
            $has_ip_constraint       = !empty($rule['ip_addresses']) && is_array($rule['ip_addresses']);
            $has_endpoint_constraint = !empty($rule['endpoints']) && is_array($rule['endpoints']);
            $has_hostname_constraint = !empty($rule['hostnames']) && is_array($rule['hostnames']);
            $has_ua_constraint       = !empty($rule['user_agents']) && is_array($rule['user_agents']);

            if ($has_ua_constraint && !$has_ip_constraint && !$has_endpoint_constraint && !$has_hostname_constraint) {
                continue;
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
                    $endpoint_pattern = trim($endpoint_pattern);
                    if ($endpoint_pattern === '') {
                        continue;
                    }
                    // Strip host/query for matching
                    $clean_pattern = (string) wp_parse_url($endpoint_pattern, PHP_URL_PATH);
                    if (empty($clean_pattern)) {
                        $clean_pattern = $endpoint_pattern;
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

            // 7. Required HTTP Headers (e.g. X-Shopify-Hmac-Sha256, Stripe-Signature, X-Square-Hmacsha256-Signature)
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

            // 8. Parameter-Scoped Exemption Check (PR 1.4: route_path + param_key + user_role)
            $rule_param = trim((string) ($rule['param_key'] ?? ''));
            if ($rule_param !== '') {
                // If rule specifies a param_key, check if that param exists in GET or POST
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
     * Checks Cloudflare CF-Connecting-ASN header, proxy headers, or Team Cymru DNS lookup.
     */
    public static function get_client_asn(string $ip): string {
        // 1. Direct Cloudflare Edge ASN Header
        if (!empty($_SERVER['HTTP_CF_CONNECTING_ASN'])) {
            return strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_ASN'])));
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
}
