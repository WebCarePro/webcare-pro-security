<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Auth\SessionSentinel;
use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\ServerInfo;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPAntiLockoutValidator
 *
 * Centralized invariant checks ensuring MCP-initiated firewall rules, IP bans,
 * and setting mutations can never lock out active administrators, origin servers,
 * Cloudflare proxy ranges, the Rescue Assistant, or the MCP endpoint itself.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class MCPAntiLockoutValidator {

    /**
     * Verify an MCP Bearer request and all configured token restrictions.
     *
     * @param mixed  $request
     * @param string $client_ip
     * @return array{allowed:bool,reason:string}
     */
    public static function verify_mcp_bearer_request($request, string $client_ip): array {
        if (!($request instanceof \WP_REST_Request)) {
            return ['allowed' => false, 'reason' => 'invalid_request'];
        }

        $enabled = SettingsManager::get('mcp_enabled', false);
        if (!in_array($enabled, [true, 1, '1'], true)) {
            return ['allowed' => false, 'reason' => 'disabled'];
        }

        $auth_header = $request->get_header('Authorization');
        if (!is_string($auth_header) || !preg_match('/\ABearer[ \t]+([^\s]+)\z/i', trim($auth_header), $matches)) {
            return ['allowed' => false, 'reason' => 'invalid_bearer'];
        }

        $expected_token = SettingsManager::get('mcp_token', '');
        if (!is_string($expected_token) || $expected_token === '' || !hash_equals($expected_token, $matches[1])) {
            return ['allowed' => false, 'reason' => 'invalid_token'];
        }

        $lifetime = self::validate_mcp_token_lifetime(
            SettingsManager::get('mcp_token_ttl_days', 0),
            SettingsManager::get('mcp_token_created_at', 0)
        );
        if (empty($lifetime['valid'])) {
            return ['allowed' => false, 'reason' => (string) ($lifetime['reason'] ?? 'invalid_ttl')];
        }

        $raw_cidrs = SettingsManager::get('mcp_allowed_cidrs', '');
        if (!is_string($raw_cidrs)) {
            return ['allowed' => false, 'reason' => 'invalid_cidr_configuration'];
        }
        if ($raw_cidrs !== '') {
            $trimmed_cidrs = trim($raw_cidrs);
            if ($trimmed_cidrs === '') {
                // Explicitly configured non-empty setting consisting only of whitespace: fail closed
                return ['allowed' => false, 'reason' => 'cidr_denied'];
            }
            $cidrs = self::parse_cidr_list($trimmed_cidrs);
            if (!self::is_valid_cidr_list($cidrs) || !self::ip_matches_cidr_list($client_ip, $cidrs)) {
                return ['allowed' => false, 'reason' => 'cidr_denied'];
            }
        }

        // Track and alert on first-seen or changed client IP for active MCP Bearer session
        $last_seen_ip = (string) get_option('webcareproscan_mcp_last_seen_ip', '');
        if ($last_seen_ip === '') {
            update_option('webcareproscan_mcp_last_seen_ip', $client_ip, false);
            if (class_exists(\WebCareProScanner\System\AuditLogger::class)) {
                \WebCareProScanner\System\AuditLogger::log('MCP_BEARER_FIRST_SEEN', sprintf('MCP Bearer connection initialized from new client IP: %s', $client_ip));
            }
        } elseif ($last_seen_ip !== $client_ip) {
            update_option('webcareproscan_mcp_last_seen_ip', $client_ip, false);
            if (class_exists(\WebCareProScanner\System\AuditLogger::class)) {
                \WebCareProScanner\System\AuditLogger::log('MCP_BEARER_IP_CHANGED', sprintf('MCP Bearer client IP transitioned from %s to %s', $last_seen_ip, $client_ip));
            }
        }

        return ['allowed' => true, 'reason' => ''];
    }

    /**
     * Validate the configured token lifetime without lossy numeric casts.
     *
     * @param mixed    $ttl_value
     * @param mixed    $created_at_value
     * @param int|null $now
     * @return array{valid:bool,reason:string}
     */
    public static function validate_mcp_token_lifetime($ttl_value, $created_at_value, ?int $now = null): array {
        $ttl_days = self::parse_non_negative_integer($ttl_value, 365);
        if ($ttl_days === null) {
            return ['valid' => false, 'reason' => 'invalid_ttl'];
        }

        if ($ttl_days === 0) {
            return ['valid' => true, 'reason' => ''];
        }

        $created_at = self::parse_non_negative_integer($created_at_value, PHP_INT_MAX);
        $now = $now ?? time();
        if ($created_at === null || $created_at <= 0 || $created_at > $now) {
            return ['valid' => false, 'reason' => 'invalid_created_at'];
        }

        $ttl_seconds = $ttl_days * (defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400);
        if ($now >= ($created_at + $ttl_seconds)) {
            return ['valid' => false, 'reason' => 'expired'];
        }

        return ['valid' => true, 'reason' => ''];
    }

    /**
     * Parse a non-negative integer setting without accepting partial or lossy casts.
     *
     * @param mixed $value
     * @param int   $max
     * @return int|null
     */
    private static function parse_non_negative_integer($value, int $max): ?int {
        if (is_int($value)) {
            return ($value >= 0 && $value <= $max) ? $value : null;
        }

        if (!is_string($value) || !preg_match('/\A(?:0|[1-9][0-9]*)\z/D', $value)) {
            return null;
        }

        $parsed = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => $max]]);
        return ($parsed === false) ? null : (int) $parsed;
    }

    /**
     * Gather all protected IP addresses and ranges that MCP actions must never ban.
     *
     * @return array<int, string>
     */
    public static function get_protected_ips(): array {
        $ips = ['127.0.0.1', '::1'];

        if (class_exists(FirewallEngine::class)) {
            $client_ip = FirewallEngine::get_client_ip();
            if ($client_ip !== '') {
                $ips[] = $client_ip;
            }
        }

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $ips[] = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        if (class_exists(ServerInfo::class)) {
            foreach (ServerInfo::get_all_server_ips() as $srv_ip) {
                if (is_string($srv_ip) && $srv_ip !== '') {
                    $ips[] = $srv_ip;
                }
            }
        }

        if (class_exists(SessionSentinel::class)) {
            foreach (SessionSentinel::get_active_sessions() as $sess) {
                if (!empty($sess['ip']) && is_string($sess['ip'])) {
                    $ips[] = $sess['ip'];
                }
            }
        }

        return array_values(array_unique(array_filter(array_map('trim', $ips))));
    }

    /**
     * Check whether an IP address matches any IP or CIDR range in a list.
     *
     * @param string            $ip
     * @param array<int,string> $entries
     * @return bool
     */
    public static function ip_matches_cidr_list(string $ip, array $entries): bool {
        $ip = trim($ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $ip_bin = @inet_pton($ip);
        if ($ip_bin === false) {
            return false;
        }

        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === false) {
                $entry_bin = @inet_pton($entry);
                if ($entry_bin !== false && $entry_bin === $ip_bin) {
                    return true;
                }
                continue;
            }
            $parts = explode('/', $entry);
            if (count($parts) !== 2 || !preg_match('/\A[0-9]+\z/D', $parts[1])) {
                continue;
            }
            [$subnet, $prefix] = $parts;
            $subnet_bin = @inet_pton(trim($subnet));
            if ($subnet_bin === false || strlen($subnet_bin) !== strlen($ip_bin)) {
                continue;
            }
            $bits      = strlen($ip_bin) * 8;
            $prefix_i  = (int) $prefix;
            // Enforce strict prefix bounds: reject /0, out-of-bounds prefixes, and non-canonical representations (/000, /033)
            if ($prefix_i < 1 || $prefix_i > $bits || (string) $prefix_i !== $prefix) {
                continue;
            }
            $full_bytes = intdiv($prefix_i, 8);
            $rem_bits  = $prefix_i % 8;

            if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
                continue;
            }
            if ($rem_bits === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rem_bits)) & 0xFF;
            if ((ord($ip_bin[$full_bytes]) & $mask) === (ord($subnet_bin[$full_bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Require a non-empty list containing only valid IP addresses or CIDR ranges.
     *
     * @param array<int,string> $entries
     * @return bool
     */
    public static function is_valid_cidr_list(array $entries): bool {
        if (empty($entries)) {
            return false;
        }

        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                return false;
            }
            $entry = trim($entry);
            if ($entry === '') {
                return false;
            }

            if (filter_var($entry, FILTER_VALIDATE_IP)) {
                continue;
            }

            $parts = explode('/', $entry);
            if (count($parts) !== 2 || !filter_var(trim($parts[0]), FILTER_VALIDATE_IP)) {
                return false;
            }

            // Strictly require canonical positive integer prefix without leading zeros or non-digits (rejects /000, /033)
            $prefix_raw = trim($parts[1]);
            if (!preg_match('/\A(?:0|[1-9][0-9]*)\z/D', $prefix_raw)) {
                return false;
            }

            $address = trim($parts[0]);
            $bits    = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 32 : 128;
            // Security Policy: Restrict CIDR prefix to min_range => 1. A prefix of /0 (0.0.0.0/0 or ::/0)
            // intentionally matches all internet traffic and negates IP allowlisting.
            $prefix  = filter_var($prefix_raw, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => $bits]]);
            if ($prefix === false || (string) $prefix !== $prefix_raw) {
                return false;
            }
        }

        return true;
    }

    /**
     * Parse newline- or comma-separated CIDR/IP entries into a clean array.
     *
     * @param string $raw
     * @return array<int, string>
     */
    public static function parse_cidr_list(string $raw): array {
        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        $out   = [];
        foreach ($parts as $part) {
            $item = trim($part);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * Validate that banning an IP or CIDR will not lock out active admins, origin server, or Cloudflare proxy.
     *
     * @param string $target_ip
     * @return array{allowed:bool,reason:string}
     */
    public static function validate_ip_ban(string $target_ip): array {
        $target_ip = trim($target_ip);
        if ($target_ip === '') {
            return ['allowed' => false, 'reason' => __('Target IP address is empty.', 'webcare-pro-security')];
        }

        $is_valid_single = (bool) filter_var($target_ip, FILTER_VALIDATE_IP);
        $is_valid_cidr   = false;
        if (!$is_valid_single && strpos($target_ip, '/') !== false) {
            [$sub, $mask] = explode('/', $target_ip, 2);
            if (filter_var(trim($sub), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && is_numeric($mask) && (int) $mask >= 8 && (int) $mask <= 32) {
                $is_valid_cidr = true;
            } elseif (filter_var(trim($sub), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && is_numeric($mask) && (int) $mask >= 32 && (int) $mask <= 128) {
                $is_valid_cidr = true;
            }
        }
        if (!$is_valid_single && !$is_valid_cidr) {
            return ['allowed' => false, 'reason' => __('Invalid IPv4/IPv6 address or overly broad CIDR subnet.', 'webcare-pro-security')];
        }

        foreach (self::get_protected_ips() as $protected) {
            if (self::ip_matches_cidr_list($protected, [$target_ip])) {
                return [
                    'allowed' => false,
                    'reason'  => sprintf(
                        /* translators: %s: protected IP address */
                        __('Anti-Lockout Guard: "%s" matches a protected administrator, loopback, or server IP.', 'webcare-pro-security'),
                        $target_ip
                    ),
                ];
            }
        }

        if ($is_valid_single && class_exists(CloudflareService::class) && CloudflareService::is_cloudflare_ip($target_ip)) {
            return [
                'allowed' => false,
                'reason'  => __('Anti-Lockout Guard: Cannot ban an official Cloudflare proxy IP range.', 'webcare-pro-security'),
            ];
        }

        return ['allowed' => true, 'reason' => ''];
    }

    /**
     * Inspect a Visual/Modular rule payload for self-lockout risks against MCP control routes or admin paths.
     *
     * @param array<string, mixed> $rule_data
     * @return array{allowed:bool,escalate_tier:int,reason:string,warnings:array<int,string>}
     */
    public static function validate_custom_rule(array $rule_data): array {
        $action   = strtolower((string) ($rule_data['action_type'] ?? 'block'));
        $expr     = strtolower((string) ($rule_data['wirefilter_expr'] ?? $rule_data['expression'] ?? ''));
        $warnings = [];
        $escalate = 0;

        if (!empty($rule_data['conditions']) && is_array($rule_data['conditions']) && $expr === '') {
            $expr = strtolower((string) wp_json_encode($rule_data['conditions']));
        }

        $is_blocking = in_array($action, ['block', 'block_and_ban', 'challenge_pow', 'rate_limit'], true);
        if (!$is_blocking) {
            return ['allowed' => true, 'escalate_tier' => 0, 'reason' => '', 'warnings' => []];
        }

        // Never allow blocking MCP control routes or Rescue Assistant callbacks
        if (strpos($expr, 'webcare-pro-security/v1/mcp') !== false || strpos($expr, 'webcare_rescue') !== false) {
            return [
                'allowed'       => false,
                'escalate_tier' => 4,
                'reason'        => __('Anti-Lockout Guard: Firewall rules cannot block WebCare Pro MCP or Rescue Assistant endpoints.', 'webcare-pro-security'),
                'warnings'      => [],
            ];
        }

        // Block banning protected admin/server IPs via Custom Firewall Rule IP equals/in clauses
        foreach (self::get_protected_ips() as $protected) {
            if ($protected !== '' && strpos($expr, strtolower($protected)) !== false) {
                return [
                    'allowed'       => false,
                    'escalate_tier' => 4,
                    'reason'        => __('Anti-Lockout Guard: Rule references a protected administrator, loopback, or server IP.', 'webcare-pro-security'),
                    'warnings'      => [],
                ];
            }
        }

        // Admin or login paths without explicit logged-in exemption escalate to Tier 3 confirmation
        $targets_admin = (strpos($expr, '/wp-admin') !== false || strpos($expr, 'wp-login.php') !== false);
        $has_login_exempt = (strpos($expr, 'not wp.user.is_logged_in') !== false || strpos($expr, 'wp.user.is_logged_in eq false') !== false);
        if ($targets_admin && !$has_login_exempt) {
            $escalate   = 3;
            $warnings[] = __('Rule targets /wp-admin or wp-login.php without "not wp.user.is_logged_in" exemption; human approval is required.', 'webcare-pro-security');
        }

        return [
            'allowed'       => true,
            'escalate_tier' => $escalate,
            'reason'        => '',
            'warnings'      => $warnings,
        ];
    }
}
