<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Evaluator pipeline contract implemented by security modules capable of pre-boot
 * Micro-WAF compilation and/or plugins_loaded runtime request evaluation.
 *
 * Each evaluator declares typed metadata governing its module ID, required status,
 * target route classes, required stack capabilities, and failure policy.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
interface WafEvaluatorInterface {

    /**
     * Unique module identifier (e.g. 'exploit-signature-engine', 'ai-agent-behavior').
     */
    public function get_module_id(): string;

    /**
     * Whether this evaluator is mandatory for core system security integrity.
     */
    public function is_required(): bool;

    /**
     * Target route classes where this evaluator is applicable.
     *
     * @return array<RouteClass>
     */
    public function get_route_classes(): array;

    /**
     * Capabilities required in the stack manifest for this evaluator to be active.
     *
     * @return array<string> e.g. ['woocommerce', 'graphql'] or empty array for universal.
     */
    public function get_required_capabilities(): array;

    /**
     * Granular failure policy governing behavior if this evaluator fails or is missing.
     */
    public function get_failure_policy(): EvaluatorFailurePolicy;

    /**
     * Export stateless rules compilable into micro-waf-compiled.php for pre-boot execution.
     *
     * @return array<string, mixed>
     */
    public function compile_preload_ast(): array;

    /**
     * Evaluate an incoming request at plugins_loaded runtime.
     *
     * @param RequestContext $ctx
     * @return WafVerdict|null Return null if request does not violate or match module policy.
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict;
}

