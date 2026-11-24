<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ResponseDlpSentinel
 *
 * Outbound Data-Loss Prevention (DLP) & Secret Leak Redactor.
 * Inspects unauthenticated HTTP/REST responses for credential dumps, private keys,
 * wp-config secrets, or /etc/passwd exfiltration before leaving the origin.
 */
class ResponseDlpSentinel implements SecurityModuleInterface {

    const OPTION_EVENTS = 'webcareproscan_dlp_events';

    /**
     * Optional testing flag to simulate DLP exception.
     *
     * @var bool
     */
    public static bool $throw_mock_exception = false;

    public function get_id(): string {
        return 'response-dlp-sentinel';
    }

    public function get_enable_key(): string {
        return 'waf_nextgen_response_dlp_enabled';
    }

    public function get_manifest(): array {
        return [
            'title'       => did_action('init') ? __('Outbound Response DLP & Secret Redactor', 'webcare-pro-security') : 'Outbound Response DLP & Secret Redactor',
            'description' => did_action('init') ? __('Scans unauthenticated HTTP and REST responses to block leaked wp-config credentials, AWS keys, PEM private keys, and /etc/passwd before egress.', 'webcare-pro-security') : 'Scans unauthenticated HTTP and REST responses to block leaked wp-config credentials, AWS keys, PEM private keys, and /etc/passwd before egress.',
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_response_dlp_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-firewall&tab=waf-rules',
            'badge'       => 'Next-Gen DLP',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_filter('rest_post_dispatch', [__CLASS__, 'filter_rest_response'], 999, 3);
        add_action('template_redirect', [__CLASS__, 'start_guest_output_buffer'], -999);
    }

    public function get_settings_defaults(): array {
        return [
            'waf_nextgen_response_dlp_enabled' => true,
            'waf_nextgen_dlp_auto_ban'         => false,
        ];
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_response_dlp_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('Outbound Response DLP & Secret Redactor', 'webcare-pro-security') : 'Outbound Response DLP & Secret Redactor',
            ],
            'waf_nextgen_dlp_auto_ban' => [
                'default' => false,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('Auto-Ban Offenders Triggering Response DLP', 'webcare-pro-security') : 'Auto-Ban Offenders Triggering Response DLP',
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/dlp-events',
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
                'name'        => 'webcareproscan_get_dlp_leak_events',
                'description' => 'Retrieve blocked outbound credential/secret exfiltration attempts caught by ResponseDlpSentinel.',
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
     * Maximum response buffer size to inspect (256 KB) to prevent memory exhaustion on media streams.
     */
    const MAX_INSPECT_BYTES = 262144;

    /**
     * Pure detector analyzing outbound response text for high-confidence credential/system leaks.
     * Performs format-aware inline redaction preserving HTML/text content structure.
     *
     * @param string $body
     * @param bool   $is_guest
     * @return array{leaked: bool, pattern: string, safe_body: string}
     */
    public static function inspect_and_redact(string $body, bool $is_guest = true): array {
        if (!$is_guest || strlen($body) < 16) {
            return ['leaked' => false, 'pattern' => '', 'safe_body' => $body];
        }

        // Fast magic-byte binary media/archive stream exemption:
        // PNG, JPEG, PDF, WebP (RIFF....WEBP), ZIP (PK..), GZIP (\x1f\x8b), MP4 (ftyp)
        $head = substr($body, 0, 16);
        if (
            str_starts_with($head, "\x89PNG")
            || str_starts_with($head, "\xFF\xD8")
            || str_starts_with($head, '%PDF-')
            || (str_starts_with($head, 'RIFF') && str_contains(substr($head, 8, 4), 'WEBP'))
            || str_starts_with($head, "PK\x03\x04")
            || str_starts_with($head, "\x1F\x8B")
            || str_contains($head, 'ftyp')
        ) {
            return ['leaked' => false, 'pattern' => '', 'safe_body' => $body];
        }

        // Sliding-window chunked inspection (256 KB chunks with 4 KB overlap)
        $chunk_size = self::MAX_INSPECT_BYTES;
        $overlap = 4096;
        $body_len = strlen($body);

        $redactions = [
            'WP_CONFIG_SECRET_DEFINE' => [
                'pattern'     => '/(define\s*\(\s*[\'"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT)[\'"]\s*,\s*[\'"])(?:[^\'"]*)([\'"]\s*\))/i',
                'replacement' => '$1[REDACTED_BY_WEBCARE_DLP]$2',
            ],
            'LINUX_PASSWD_FILE_DUMP' => [
                'pattern'     => '/root:[x*]:0:0:[^:\r\n]*:[^:\r\n]*:[^\r\n]*/',
                'replacement' => 'root:x:0:0:[REDACTED_BY_WEBCARE_DLP]',
            ],
            'AWS_IAM_ACCESS_KEY' => [
                'pattern'     => '/\bAKIA[0-9A-Z]{16}\b/',
                'replacement' => '[REDACTED_AWS_KEY]',
            ],
            'PRIVATE_CRYPTO_PEM_KEY' => [
                'pattern'     => '/-----BEGIN (?:RSA |OPENSSH |EC |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |OPENSSH |EC |PGP |ENCRYPTED )?PRIVATE KEY-----|$)/',
                'replacement' => '[REDACTED_PRIVATE_KEY_BY_WEBCARE_DLP]',
            ],
            'RAW_DB_AUTH_ERROR_DUMP' => [
                'pattern'     => '/Access denied for user\s+\'[^\']+\'@\'[^\']+\'|SQLSTATE\[HY000\](?:\s*\[\d+\])?(?::\s*[^\r\n<]+)?/i',
                'replacement' => '[DATABASE_ERROR_REDACTED_BY_WEBCARE_DLP]',
            ],
        ];

        $leaked          = false;
        $matched_pattern = '';
        $redacted_body   = $body;

        // Iterate through overlapping chunks to ensure secrets across chunk boundaries are caught
        $offset = 0;
        while ($offset < $body_len) {
            $chunk = substr($body, $offset, $chunk_size);
            foreach ($redactions as $name => $cfg) {
                if (preg_match($cfg['pattern'], $chunk) === 1) {
                    $leaked = true;
                    if (empty($matched_pattern)) {
                        $matched_pattern = $name;
                    }
                    $redacted_body = (string) preg_replace($cfg['pattern'], $cfg['replacement'], $redacted_body);
                }
            }
            if ($offset + $chunk_size >= $body_len) {
                break;
            }
            $offset += ($chunk_size - $overlap);
        }

        return [
            'leaked'    => $leaked,
            'pattern'   => $matched_pattern,
            'safe_body' => $redacted_body,
        ];
    }

    /**
     * Maximum depth and node limits for safe recursive DLP inspection.
     */
    public const MAX_RECURSION_DEPTH = 25;
    public const MAX_RECURSION_NODES = 25000;

    /**
     * Recursively inspect and redact strings inside nested arrays or objects (for REST responses).
     *
     * @param mixed              $data
     * @param bool               $has_leak
     * @param string             $matched_pattern
     * @param int                $depth
     * @param int                $nodes
     * @param array<int, bool>   $visited
     * @param int                $max_depth_seen
     * @return mixed Normalized array/primitive with secrets redacted.
     * @throws \RuntimeException If recursion depth, node budget, or circular reference detected.
     */
    public static function redact_data_recursive(
        $data,
        bool &$has_leak,
        string &$matched_pattern,
        int $depth = 0,
        int &$nodes = 0,
        array &$visited = [],
        int &$max_depth_seen = 0
    ) {
        if (self::$throw_mock_exception) {
            throw new \RuntimeException('Mock DLP exception for fail-closed testing.');
        }

        $nodes++;
        if ($depth > $max_depth_seen) {
            $max_depth_seen = $depth;
        }

        if ($depth > self::MAX_RECURSION_DEPTH) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \RuntimeException(
                // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
                sprintf('DLP recursion limit exceeded (depth %d > %d); failing closed.', $depth, self::MAX_RECURSION_DEPTH),
                1001
            );
        }

        if ($nodes > self::MAX_RECURSION_NODES) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \RuntimeException(
                // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
                sprintf('DLP node budget exceeded (nodes %d > %d); failing closed.', $nodes, self::MAX_RECURSION_NODES),
                1002
            );
        }

        if (is_string($data)) {
            $check = self::inspect_and_redact($data, true);
            if (!empty($check['leaked'])) {
                $has_leak = true;
                if (empty($matched_pattern)) {
                    $matched_pattern = $check['pattern'];
                }
                return $check['safe_body'];
            }
            return $data;
        }

        if (is_array($data)) {
            $cleaned = [];
            foreach ($data as $key => $val) {
                $cleaned[$key] = self::redact_data_recursive($val, $has_leak, $matched_pattern, $depth + 1, $nodes, $visited, $max_depth_seen);
            }
            return $cleaned;
        }

        if (is_object($data)) {
            $oid = spl_object_id($data);
            if (isset($visited[$oid])) {
                throw new \RuntimeException('Circular reference detected during DLP inspection; failing closed.', 1003);
            }
            $visited[$oid] = true;

            $vars = get_object_vars($data);
            $cleaned_obj = [];
            foreach ($vars as $prop => $val) {
                $cleaned_obj[$prop] = self::redact_data_recursive($val, $has_leak, $matched_pattern, $depth + 1, $nodes, $visited, $max_depth_seen);
            }
            unset($visited[$oid]);
            return $cleaned_obj;
        }

        return $data;
    }

    /**
     * Start output buffer on guest public requests.
     */
    public static function start_guest_output_buffer(): void {
        if (
            (defined('WP_CLI') && WP_CLI)
            || (function_exists('wp_doing_cron') && wp_doing_cron())
            || is_admin()
            || (function_exists('is_user_logged_in') && is_user_logged_in())
        ) {
            return;
        }

        // Never buffer file download endpoints (WooCommerce, EDD, attachments)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['download_file']) || !empty($_GET['eddfile']) || !empty($_GET['wc-api'])) {
            return;
        }

        // Skip buffering if standard file download/attachment headers were already sent
        if (headers_sent()) {
            return;
        }

        ob_start([__CLASS__, 'filter_guest_output_buffer']);
    }

    /**
     * Output buffer callback inspecting HTML/text guest responses.
     * Inlines redaction without serving 403s or banning visitors.
     */
    public static function filter_guest_output_buffer(string $buffer): string {
        // Fast-path bypass for binary, attachment, SSE, or compressed streams
        if (function_exists('headers_list')) {
            foreach (headers_list() as $header_line) {
                $hl = strtolower($header_line);
                if (
                    str_contains($hl, 'content-disposition:') && str_contains($hl, 'attachment')
                    || str_contains($hl, 'content-type: text/event-stream')
                    || str_contains($hl, 'content-type: application/octet-stream')
                    || str_contains($hl, 'content-type: video/')
                    || str_contains($hl, 'content-type: audio/')
                    || str_contains($hl, 'content-encoding: gzip')
                    || str_contains($hl, 'content-encoding: br')
                ) {
                    return $buffer;
                }
            }
        }

        $result = self::inspect_and_redact($buffer, true);
        if (empty($result['leaked'])) {
            return $buffer;
        }

        self::handle_dlp_breach($result['pattern']);
        return $result['safe_body'];
    }

    /**
     * Filter REST API responses for unauthenticated callers.
     * Scans and redacts object properties recursively while preserving JSON response format.
     *
     * @param mixed            $result
     * @param \WP_REST_Server  $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function filter_rest_response($result, $server, $request) {
        if (is_user_logged_in() || (defined('WP_CLI') && WP_CLI)) {
            return $result;
        }
        if ($result instanceof \WP_REST_Response) {
            $route = method_exists($request, 'get_route') ? (string) $request->get_route() : '';
            if (strpos($route, '/webcare-pro-security/') === 0) {
                return $result;
            }
            $data            = $result->get_data();
            $has_leak        = false;
            $matched_pattern = '';
            $nodes           = 0;
            $visited         = [];
            $max_depth_seen  = 0;

            try {
                $clean_data = self::redact_data_recursive($data, $has_leak, $matched_pattern, 0, $nodes, $visited, $max_depth_seen);
                if ($has_leak) {
                    self::handle_dlp_breach($matched_pattern);
                    $result->set_data($clean_data);
                }
            } catch (\Throwable $e) {
                $code = $e->getCode();
                $failure_type = match ($code) {
                    1001    => 'depth_limit',
                    1002    => 'node_budget',
                    1003    => 'circular_reference',
                    default => 'unexpected_error',
                };

                // Fallback string matching if exception code wasn't set or custom throw
                if ($failure_type === 'unexpected_error') {
                    $msg = $e->getMessage();
                    if (str_contains($msg, 'depth')) {
                        $failure_type = 'depth_limit';
                    } elseif (str_contains($msg, 'nodes') || str_contains($msg, 'node budget')) {
                        $failure_type = 'node_budget';
                    } elseif (str_contains($msg, 'Circular reference')) {
                        $failure_type = 'circular_reference';
                    }
                }

                $sanitized_route = sanitize_text_field(substr($route, 0, 160));

                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    try {
                        \WebCareProScanner\System\AuditLogger::log_operational('dlp_inspection_limit_exceeded', [
                            'failure_type'   => $failure_type,
                            'route'          => $sanitized_route,
                            'nodes_visited'  => $nodes,
                            'max_depth_seen' => $max_depth_seen,
                        ]);
                    } catch (\Throwable $logging_error) {
                        // Never allow diagnostic logging failure to abort the fail-closed 503 response.
                    }
                }

                return new \WP_REST_Response([
                    'code'    => 'webcare_dlp_inspection_unavailable',
                    'message' => 'The response could not be safely inspected.',
                ], 503);
            }
        }
        return $result;
    }

    /**
     * Log redacted DLP incident without viewer IP auto-banning.
     */
    private static function handle_dlp_breach(string $pattern): void {
        $ip     = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : '127.0.0.1';
        $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $reason = sprintf('Outbound DLP neutralized secret exfiltration (%s) on response [INLINE REDACTED].', $pattern);

        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }
        array_unshift($events, [
            'timestamp' => time(),
            'ip'        => sanitize_text_field($ip),
            'pattern'   => sanitize_key($pattern),
            'uri'       => sanitize_text_field(substr($uri, 0, 160)),
        ]);
        if (count($events) > 50) {
            $events = array_slice($events, 0, 50);
        }
        update_option(self::OPTION_EVENTS, $events, false);

        if (class_exists(FirewallEngine::class)) {
            FirewallEngine::log_incident([
                'id'          => 'WAF-DLP-EXFILTRATION-BLOCKED',
                'name'        => 'Outbound Response DLP Sentinel',
                'category'    => 'Next-Gen Response DLP',
                'description' => $reason,
                'match_type'  => $pattern,
                'match_value' => $pattern,
                'payload'     => 'URI: ' . $uri . ' | Token neutralized via inline redaction.',
            ], 'detected');
        }
    }
}
