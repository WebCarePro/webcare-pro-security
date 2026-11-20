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
     * Inspect incoming request through the firewall pipeline.
     * Evaluates Always-On Mandatory Core, then conditional manifest evaluators,
     * and delegates to FirewallEngine::inspect_incoming_request().
     */
    public static function process_incoming_request(): void {
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
                if ($verdict !== null && $verdict->get_action_value() !== 'allow') {
                    $action_val = $verdict->get_action_value();

                    // If Safe Mode is active, downgrade heuristic/conditional blocks to observe-only ('detected')
                    // while retaining zero-tolerance exploit blocks (RCE/SQLi)
                    $is_critical_exploit = in_array($verdict->ruleId, ['WAF-RCE', 'WAF-SQLI', 'WAF-FILE-INCLUSION', 'WAF-ARBITRARY-FILE-WRITE'], true)
                        || str_contains($verdict->category, 'SQL Injection')
                        || str_contains($verdict->category, 'Command Injection');

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
                }
            }

            // 2. Delegate to comprehensive engine inspection
            FirewallEngine::inspect_incoming_request();
        } catch (\Throwable $e) {
            // Fail-closed invariant: Log critical failure
            if (class_exists(FirewallEngine::class)) {
                FirewallEngine::log_incident([
                    'id'          => 'WAF-PIPELINE-EXCEPTION',
                    'name'        => 'Pipeline Exception Fail-Closed',
                    'category'    => 'System Integrity',
                    'description' => 'Firewall pipeline caught unhandled exception; failing closed: ' . $e->getMessage(),
                    'match_type'  => 'Exception Guard',
                    'match_value' => $e->getCode(),
                    'payload'     => $e->getFile() . ':' . $e->getLine(),
                ], 'blocked');
            }
            status_header(403);
            exit;
        }
    }

    /**
     * Mandatory evaluators that must always be present in the runtime.
     */
    private const MANDATORY_EVALUATORS = [
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
                throw new \RuntimeException(sprintf('Mandatory firewall evaluator unavailable: %s', $mand_class));
            }
            if (!is_array($route_evaluators) || !in_array($mand_class, $route_evaluators, true)) {
                throw new \RuntimeException(sprintf('Mandatory firewall evaluator missing from route stack: %s', $mand_class));
            }
        }

        if (empty($route_evaluators) || !is_array($route_evaluators)) {
            return null;
        }

        foreach ($route_evaluators as $evaluator_class) {
            if (!class_exists($evaluator_class)) {
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
                $evaluator = new $evaluator_class();
                $verdict = $evaluator->evaluate_runtime_request($ctx);
                if ($verdict instanceof WafVerdict) {
                    if (self::is_terminal_verdict($verdict)) {
                        return $verdict;
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
