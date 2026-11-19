<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Core\RouteClassifier;
use WebCareProScanner\Firewall\FirewallEngine;

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
 * Author: Mir Alamin (WebCare Pro)
 */
final class RequestPipeline {

    /**
     * Inspect incoming request through the firewall pipeline.
     */
    public static function process_incoming_request(): void {
        FirewallEngine::inspect_incoming_request();
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
