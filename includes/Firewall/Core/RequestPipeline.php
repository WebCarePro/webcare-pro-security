<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Core\RouteClassifier;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RequestPipeline
 *
 * Lightweight request pipeline orchestrator.
 * Evaluates the Always-On Mandatory Core first, followed by conditional evaluators
 * from the CompiledStackManifest. Short-circuits on the first terminal WafVerdict.
 *
 * Fail-closed design: Exceptions caught within pipeline log the anomaly and terminate
 * with safe error status rather than allowing uninspected request execution.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RequestPipeline {

    /**
     * Static re-entrancy guard to prevent recursive pipeline evaluation.
     */
    private static bool $is_processing = false;

    /**
     * Optional test hook: captures terminal HTTP status code and throws RuntimeException instead of exit().
     */
    public static bool $throw_on_exit_in_tests = false;
    public static ?int $last_terminated_status = null;

    private const ALLOWED_RESCUE_PAGES = [
        'webcare-pro-security',
        'webcare-pro-firewall',
        'webcare-pro-settings',
    ];

    private const ALLOWED_RESCUE_QUERY_KEYS = [
        'page',
        'tab',
        'subtab',
        'view',
        'section',
    ];

    /**
     * Inspect incoming request through the firewall pipeline.
     * Evaluates Always-On Mandatory Core, conditional manifest evaluators,
     * and pluggable module SDK. Short-circuits on terminal verdicts and profiles
     * benign traffic.
     */
    public static function process_incoming_request(): void {
        if (self::$is_processing) {
            return;
        }

        // Global disable / killswitch pre-checks: return immediately before pipeline evaluation
        if ((defined('WEBCAREPROSCAN_DISABLE_WAF') && WEBCAREPROSCAN_DISABLE_WAF)
            || (defined('WEBCAREPROSCAN_DISABLE_FIREWALL') && WEBCAREPROSCAN_DISABLE_FIREWALL)
            || (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD)
        ) {
            return;
        }

        // Killswitch file presence in upload directory
        $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        if (!empty($upload_dir['basedir'])) {
            $uploads_base = rtrim($upload_dir['basedir'], '/\\');
            if (file_exists($uploads_base . '/webcare-pro-security/.killswitch') || file_exists($uploads_base . '/webcare-vault/.killswitch')) {
                return;
            }
        }

        // Skip CLI execution (unless running in synthetic test runner)
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) {
            $in_synthetic_test = self::$throw_on_exit_in_tests
                || (class_exists('\\WebCareProScanner\\Firewall\\DeclarativePatchVerifier')
                    && \WebCareProScanner\Firewall\DeclarativePatchVerifier::is_test_context());
            if (!$in_synthetic_test) {
                return;
            }
        }

        // Internal DOING_CRON pre-check: skip unless this is an external HTTP trigger to wp-cron.php
        if (defined('DOING_CRON') && DOING_CRON) {
            $raw_cron_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash((string) $_SERVER['REQUEST_URI'])) : '';
            $clean_cron_check = strtolower(wp_parse_url($raw_cron_uri, PHP_URL_PATH) ?: $raw_cron_uri);
            if (!str_contains($clean_cron_check, 'wp-cron.php')) {
                return;
            }
        }

        // Settings check: global WAF enabled / disabled mode
        if (class_exists(SettingsManager::class)) {
            $early_settings = SettingsManager::get_settings();
            if (empty($early_settings['waf_enabled']) || ($early_settings['waf_mode'] ?? 'enabled') === 'disabled') {
                return;
            }
        }

        self::$is_processing = true;

        try {
            // 0. Safe Mode check: if active, switch heuristic evaluators to observe-only
            $is_safe_mode = false;
            if (class_exists(RescueAssistantManager::class)) {
                $pause_status = RescueAssistantManager::get_pause_status();
                $is_safe_mode = !empty($pause_status['paused']);
            }

            // 1. Evaluate Always-On Core & Conditional Pipeline via RequestContext
            if (class_exists(RequestContext::class) && class_exists(SettingsManager::class)) {
                $ctx = RequestContext::from_globals();
                $settings = SettingsManager::get_settings();

                $verdict = self::evaluate_pipeline($ctx, $settings);

                // 2. Pluggable Module SDK: If pipeline returned null, evaluate registered module extensions
                if ($verdict === null && class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
                    $verdict = \WebCareProScanner\Core\ModuleRegistry::evaluate_runtime_waf($ctx, $settings);
                }

                if ($verdict !== null && $verdict->get_action_value() !== 'allow') {
                    $action_val = $verdict->get_action_value();

                    // If Safe Mode is active, downgrade heuristic/conditional blocks to observe-only ('detected')
                    // while retaining zero-tolerance exploit blocks (RCE/SQLi/LFI/XXE/SSRF/Object Injection)
                    $is_critical_exploit = in_array($verdict->ruleId, [
                        'WAF-RCE-PHP-INJECTION',
                        'WAF-SQLI-INJECTION',
                        'WAF-LFI-TRAVERSAL',
                        'WAF-OBJECT-STREAM-INJECTION',
                        'WAF-XXE-INJECTION',
                        'WAF-SSRF-METADATA',
                        'WAF-AJAX-SHORTCODE-GADGET',
                        'WAF-ARBITRARY-FILE-WRITE',
                    ], true)
                        || str_contains($verdict->category, 'SQL Injection')
                        || str_contains($verdict->category, 'Command Injection')
                        || str_contains($verdict->category, 'PHP Code Injection');

                    if ($is_safe_mode && !$is_critical_exploit) {
                        FirewallEngine::log_incident([
                            'id'              => $verdict->ruleId,
                            'name'            => $verdict->category . ' [Safe Mode Observed]',
                            'category'        => $verdict->category,
                            'description'     => $verdict->reason,
                            'match_type'      => 'Safe Mode Observe',
                            'match_value'     => $verdict->ruleId,
                            'payload'         => "Client IP: {$ctx->ip} URI: {$ctx->uri}",
                            'sync_cloudflare' => false,
                            'ban_ttl'         => 0,
                        ], 'detected');
                    } else {
                        // Terminal or challenging action triggered
                        $rule = [
                            'id'              => $verdict->ruleId,
                            'name'            => $verdict->category,
                            'category'        => $verdict->category,
                            'description'     => $verdict->reason,
                            'match_type'      => $action_val,
                            'match_value'     => $verdict->ruleId,
                            'payload'         => "Client IP: {$ctx->ip} URI: {$ctx->uri}",
                            'sync_cloudflare' => $verdict->syncCloudflare,
                            'ban_ttl'         => $action_val === 'block_and_ban' ? max(60, $verdict->banTtl) : $verdict->banTtl,
                        ];

                        if ($action_val === 'challenge_pow' && class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                            if (!\WebCareProScanner\Firewall\BotReconDefense::has_valid_clearance_cookie($ctx->ip, $ctx->userAgent)) {
                                FirewallEngine::log_incident($rule, 'challenged');
                                \WebCareProScanner\Firewall\BotReconDefense::render_pow_challenge($ctx->ip, $verdict->reason);
                            }
                        } elseif (in_array($action_val, ['block', 'block_and_ban', 'rate_limit'], true) || $verdict->is_terminal()) {
                            ViolationResponder::handle_rule_violation($rule, $settings, $ctx->ip, $verdict->statusCode);
                            return;
                        } else {
                            FirewallEngine::log_incident($rule, 'detected');
                        }
                    }
                } else {
                    // Clean request passed all firewall filters: profile route parameters
                    if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                        \WebCareProScanner\Firewall\LearningModeEngine::profile_benign_request();
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fail-closed invariant with 4-tier exception classification:
            // Log critical failure
            try {
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-PIPELINE-EXCEPTION',
                        'name'        => 'Pipeline Exception Fail-Closed',
                        'category'    => 'System Integrity',
                        'description' => 'Firewall pipeline caught unhandled exception: ' . $e->getMessage(),
                        'match_type'  => 'Exception Guard',
                        'match_value' => $e->getCode(),
                        'payload'     => $e->getFile() . ':' . $e->getLine(),
                    ], 'blocked');
                }
            } catch (\Throwable) {
                // Tier 3: Telemetry/logging failures must never abort request execution
            }

            // Tier 4: Outer exception boundary - strictly permit read-only admin console rescue to prevent permanent admin lockout
            $ctx_for_rescue = isset($ctx) && $ctx instanceof RequestContext ? $ctx : RequestContext::from_globals();
            if (self::is_read_only_rescue_request($ctx_for_rescue)) {
                self::$last_terminated_status = 200;
                try {
                    if (class_exists(\WebCareProScanner\System\AuditLogger::class)) {
                        $rescue_path = (string) (wp_parse_url($ctx_for_rescue->uri, PHP_URL_PATH) ?? '/wp-admin/admin.php');
                        \WebCareProScanner\System\AuditLogger::log_operational('waf_pipeline_rescue_boundary_invoked', [
                            'exception_class' => sanitize_text_field(get_class($e)),
                            'exception_code'  => (int) $e->getCode(),
                            'rescue_method'   => sanitize_key($ctx_for_rescue->method),
                            'rescue_path'     => sanitize_text_field($rescue_path),
                            'timestamp_utc'   => gmdate('Y-m-d H:i:s'),
                        ]);
                    }
                } catch (\Throwable) {
                    // Rescue access and fail-safe diagnostics must never abort admin recovery
                }
                return;
            }

            self::$last_terminated_status = 503;
            if (function_exists('status_header')) {
                status_header(503);
            } elseif (!headers_sent()) {
                header('HTTP/1.1 503 Service Unavailable');
            }
            if (self::$throw_on_exit_in_tests && defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING) {
                // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Previous Throwable passed internally to RuntimeException
                throw new \RuntimeException('RequestPipeline terminated fail-closed with HTTP 503.', 503, $e);
            }
            exit;
        } finally {
            self::$is_processing = false;
        }
    }

    /**
     * Strict read-only rescue validation.
     * Never permits POST, PUT, PATCH, DELETE, mutating/login endpoints (admin-ajax.php,
     * admin-post.php, options.php, wp-login.php), or unapproved query parameters on admin.php.
     *
     * @param RequestContext $ctx
     * @return bool
     */
    public static function is_read_only_rescue_request(RequestContext $ctx): bool {
        // 1. Strict HTTP method: GET or HEAD only
        $method = strtoupper($ctx->method);
        if ($method !== 'GET' && $method !== 'HEAD') {
            return false;
        }

        $uri = $ctx->uri;
        $path = (string) (wp_parse_url($uri, PHP_URL_PATH) ?? $uri);

        // 2. Explicitly reject mutating scripts and login endpoints
        $forbidden_endpoints = [
            'admin-ajax.php',
            'admin-post.php',
            'options.php',
            'wp-login.php',
            'async-upload.php',
            'plugins.php',
            'plugin-install.php',
            'update.php',
            'update-core.php',
        ];
        foreach ($forbidden_endpoints as $forbidden) {
            if (str_contains($path, $forbidden)) {
                return false;
            }
        }

        // 3. Must be an authenticated administrator
        $is_admin = class_exists(FirewallEngine::class)
            ? FirewallEngine::is_authenticated_administrator()
            : (function_exists('current_user_can') && current_user_can('manage_options'));

        if (!$is_admin) {
            return false;
        }

        // 4. Allowed rescue endpoints:
        // A. Canonical admin console: /wp-admin/admin.php with strict query-parameter allowlist
        if (str_ends_with($path, '/wp-admin/admin.php')) {
            $raw_query = (string) (wp_parse_url($uri, PHP_URL_QUERY) ?? '');
            if (
                str_contains($raw_query, ';')
                || str_contains($raw_query, "\0")
                || stripos($raw_query, '%00') !== false
                || str_contains($raw_query, '[')
                || str_contains($raw_query, ']')
                || stripos($raw_query, '%5b') !== false
                || stripos($raw_query, '%5d') !== false
            ) {
                return false;
            }

            $uri_params = [];
            if ($raw_query !== '') {
                foreach (explode('&', $raw_query) as $pair) {
                    if ($pair === '') {
                        continue;
                    }
                    $parts = explode('=', $pair, 2);
                    $raw_key = rawurldecode($parts[0]);
                    if (!in_array($raw_key, self::ALLOWED_RESCUE_QUERY_KEYS, true)) {
                        return false;
                    }
                }
                parse_str($raw_query, $uri_params);
            }

            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Strict read-only rescue boundary parameter inspection
            $get_superglobal = is_array($_GET) ? $_GET : [];
            $combined_params = [];
            foreach ([$uri_params, $get_superglobal] as $source) {
                foreach ($source as $q_key => $q_val) {
                    if (!is_string($q_key) || !in_array($q_key, self::ALLOWED_RESCUE_QUERY_KEYS, true)) {
                        return false;
                    }
                    if (!is_string($q_val) || preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $q_val) !== 1) {
                        return false;
                    }
                    if (isset($combined_params[$q_key]) && $combined_params[$q_key] !== $q_val) {
                        return false;
                    }
                    $combined_params[$q_key] = $q_val;
                }
            }

            $page = $combined_params['page'] ?? '';
            return in_array($page, self::ALLOWED_RESCUE_PAGES, true);
        }

        // B. Canonical read-only REST rescue routes
        if (str_ends_with($path, '/wp-json/webcare-pro-security/v1/rescue/status')
            || str_ends_with($path, '/wp-json/webcare-pro-security/v1/system/doctor')
        ) {
            $raw_query = (string) (wp_parse_url($uri, PHP_URL_QUERY) ?? '');
            if ($raw_query !== '') {
                parse_str($raw_query, $rest_params);
                foreach ($rest_params as $rk => $rv) {
                    if (!is_string($rk) || !in_array($rk, ['_locale'], true) || !is_string($rv)) {
                        return false;
                    }
                }
            }
            return true;
        }

        return false;
    }

    /**
     * Mandatory evaluators that must always be present in the runtime.
     */
    private const MANDATORY_EVALUATORS = [
        'WebCareProScanner\\Firewall\\Core\\AlwaysOnCoreGuard',
        'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
    ];

    /**
     * Evaluate pipeline across active route class and compiled evaluators.
     *
     * @param RequestContext $ctx
     * @param array<string, mixed> $settings
     * @return WafVerdict|null First terminal verdict or null if passed.
     */
    public static function evaluate_pipeline(RequestContext $ctx, array $settings): ?WafVerdict {
        $route_class = RouteClassifier::classify([
            'REQUEST_URI'    => $ctx->uri,
            'REQUEST_METHOD' => $ctx->method,
        ]);
        $manifest = CompiledStackManifest::load();
        $route_evaluators = $manifest['routes'][$route_class->value] ?? [];

        // Verify mandatory evaluators are present in runtime and in the active route stack
        foreach (self::MANDATORY_EVALUATORS as $mand_class) {
            if (!class_exists($mand_class)) {
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-REQUIRED-EVALUATOR-MISSING',
                        'name'        => 'Required Evaluator Missing Fail-Closed',
                        'category'    => 'System Integrity',
                        'description' => sprintf('Mandatory firewall evaluator "%s" is unavailable in runtime; route failed closed.', $mand_class),
                        'match_type'  => 'Missing Evaluator Guard',
                        'match_value' => $mand_class,
                        'payload'     => 'Route: ' . $route_class->value,
                    ], 'blocked');
                }
                return new WafVerdict(
                    'block',
                    'WAF-REQUIRED-EVALUATOR-MISSING',
                    sprintf('Mandatory firewall evaluator "%s" is unavailable in runtime.', $mand_class),
                    [
                        'category'    => 'System Integrity',
                        'status_code' => 503,
                    ]
                );
            }
            if (!is_array($route_evaluators) || !in_array($mand_class, $route_evaluators, true)) {
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-REQUIRED-EVALUATOR-MISSING',
                        'name'        => 'Required Evaluator Missing Fail-Closed',
                        'category'    => 'System Integrity',
                        'description' => sprintf('Mandatory firewall evaluator "%s" missing from route stack; route failed closed.', $mand_class),
                        'match_type'  => 'Missing Evaluator Guard',
                        'match_value' => $mand_class,
                        'payload'     => 'Route: ' . $route_class->value,
                    ], 'blocked');
                }
                return new WafVerdict(
                    'block',
                    'WAF-REQUIRED-EVALUATOR-MISSING',
                    sprintf('Mandatory firewall evaluator "%s" missing from route stack; route failed closed.', $mand_class),
                    [
                        'category'    => 'System Integrity',
                        'status_code' => 503,
                    ]
                );
            }
        }

        if (empty($route_evaluators) || !is_array($route_evaluators)) {
            return null;
        }

        $ecosystems = is_array($manifest['ecosystems'] ?? null) ? $manifest['ecosystems'] : [];

        foreach ($route_evaluators as $evaluator_class) {
            $meta = $manifest['evaluators'][$evaluator_class] ?? null;
            $failure_policy = $meta['failure_policy'] ?? \WebCareProScanner\Contracts\EvaluatorFailurePolicy::DegradedLog->value;
            $is_req = !empty($meta['required']) || in_array($evaluator_class, self::MANDATORY_EVALUATORS, true);

            // Dual-Axis Evaluator Selection:
            // Optional evaluators run ONLY when:
            // 1. Stack capability matches (if declared in capabilities)
            // 2. Canonical route class matches (if declared in route_classes)
            if (!$is_req && is_array($meta)) {
                $required_caps = $meta['capabilities'] ?? [];
                if (!empty($required_caps) && is_array($required_caps)) {
                    $has_all_caps = true;
                    foreach ($required_caps as $cap) {
                        if (empty($ecosystems[$cap])) {
                            $has_all_caps = false;
                            break;
                        }
                    }
                    if (!$has_all_caps) {
                        // Ecosystem capability missing on this site; skip without error
                        continue;
                    }
                }

                $target_routes = $meta['route_classes'] ?? [];
                if (!empty($target_routes) && is_array($target_routes)) {
                    if (!in_array($route_class->value, $target_routes, true)) {
                        // Current route class does not match evaluator scope; skip
                        continue;
                    }
                }
            }

            if (!class_exists($evaluator_class) || !empty($meta['missing'])) {
                if ($is_req || $failure_policy === \WebCareProScanner\Contracts\EvaluatorFailurePolicy::FailClosedRoute->value) {
                    if (class_exists(FirewallEngine::class)) {
                        FirewallEngine::log_incident([
                            'id'          => 'WAF-REQUIRED-EVALUATOR-MISSING',
                            'name'        => 'Required Evaluator Missing Fail-Closed',
                            'category'    => 'System Integrity',
                            'description' => sprintf('Required firewall evaluator "%s" is missing from runtime; route failed closed.', $evaluator_class),
                            'match_type'  => 'Missing Evaluator Guard',
                            'match_value' => $evaluator_class,
                            'payload'     => 'Route: ' . $route_class->value,
                        ], 'blocked');
                    }
                    return new WafVerdict(
                        'block',
                        'WAF-REQUIRED-EVALUATOR-MISSING',
                        sprintf('Required firewall evaluator "%s" is missing from runtime.', $evaluator_class),
                        [
                            'category'    => 'System Integrity',
                            'status_code' => 503,
                        ]
                    );
                }
                // Optional heuristic evaluator missing: record degraded log and continue safely
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-EVALUATOR-DEGRADED',
                        'name'        => 'Optional Evaluator Degraded',
                        'category'    => 'System Integrity',
                        'description' => sprintf('Optional evaluator class "%s" unavailable; degraded gracefully.', $evaluator_class),
                        'match_type'  => 'Degraded Log',
                        'match_value' => $evaluator_class,
                        'payload'     => 'Route: ' . $route_class->value,
                    ], 'detected');
                }
                continue;
            }

            // ExploitSignatureEngine evaluation branch
            if ($evaluator_class === ExploitSignatureEngine::class) {
                $match = ExploitSignatureEngine::evaluate_rules($settings, false, $ctx);
                if (is_array($match)) {
                    return new WafVerdict(
                        'block',
                        (string) ($match['id'] ?? 'WAF-EXPLOIT-SIG'),
                        (string) ($match['description'] ?? 'Exploit signature matched.'),
                        [
                            'category'    => (string) ($match['category'] ?? 'Exploit Signature'),
                            'status_code' => 403,
                        ]
                    );
                }
                continue;
            }

            // Instantiate or call evaluator if it implements WafEvaluatorInterface
            if (is_subclass_of($evaluator_class, WafEvaluatorInterface::class)) {
                try {
                    $evaluator = new $evaluator_class();
                    $verdict = $evaluator->evaluate_runtime_request($ctx);
                    if ($verdict instanceof WafVerdict) {
                        if ($verdict->get_action_value() === 'log_only') {
                            if (class_exists(FirewallEngine::class)) {
                                FirewallEngine::log_incident([
                                    'id'          => $verdict->ruleId,
                                    'name'        => $verdict->category . ' [Log Only]',
                                    'category'    => $verdict->category,
                                    'description' => $verdict->reason,
                                    'match_type'  => 'Virtual Patch Log Only',
                                    'match_value' => $verdict->ruleId,
                                    'payload'     => "Client IP: {$ctx->ip} URI: {$ctx->uri}",
                                    'sync_cloudflare' => false,
                                    'ban_ttl'         => 0,
                                ], 'detected');
                            }
                        } elseif (self::is_terminal_verdict($verdict)) {
                            return $verdict;
                        }
                    }
                } catch (\Throwable $eval_err) {
                    // Check if evaluator failure occurred with active enforced custom rules
                    if (str_contains($evaluator_class, 'CustomRules') || str_contains($evaluator_class, 'AlwaysOnCoreGuard') || str_contains($evaluator_class, 'ModularFirewall')) {
                        if (class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')
                            && \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::has_active_blocking_rules()
                        ) {
                            try {
                                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                                    \WebCareProScanner\System\AuditLogger::log_operational('custom_rules_evaluator_degraded', [
                                        'evaluator' => $evaluator_class,
                                        'error'     => $eval_err->getMessage(),
                                        'file'      => $eval_err->getFile() . ':' . $eval_err->getLine(),
                                    ]);
                                }
                            } catch (\Throwable $ignore) {}
                            if (function_exists('set_transient')) {
                                set_transient('webcareproscan_custom_rules_degraded', [
                                    'time'      => time(),
                                    'evaluator' => $evaluator_class,
                                    'error'     => $eval_err->getMessage(),
                                ], 15 * 60);
                            }
                        }
                    }

                    if ($is_req || $failure_policy === \WebCareProScanner\Contracts\EvaluatorFailurePolicy::FailClosedRoute->value) {
                        throw $eval_err;
                    }
                    if (class_exists(FirewallEngine::class)) {
                        FirewallEngine::log_incident([
                            'id'          => 'WAF-EVALUATOR-ERROR',
                            'name'        => 'Evaluator Runtime Degradation',
                            'category'    => 'System Integrity',
                            'description' => sprintf('Evaluator "%s" threw error: %s', $evaluator_class, $eval_err->getMessage()),
                            'match_type'  => 'Degraded Log',
                            'match_value' => $evaluator_class,
                            'payload'     => $eval_err->getFile() . ':' . $eval_err->getLine(),
                        ], 'detected');
                    }
                }
            }
        }

        return null;
    }

    /**
     * Check if a WafVerdict represents a terminal action.
     */
    private static function is_terminal_verdict(WafVerdict $verdict): bool {
        return $verdict->is_terminal();
    }

    /**
     * Evaluate rules against active settings.
     *
     * @param array<string, mixed> $settings
     * @return array<string, mixed>|null
     */
    public static function evaluate_rules(array $settings, bool $is_complementary = false): ?array {
        return FirewallEngine::evaluate_rules($settings, $is_complementary);
    }
}
