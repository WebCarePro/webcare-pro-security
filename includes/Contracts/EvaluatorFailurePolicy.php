<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Failure handling policy for WAF evaluators.
 *
 * fail_closed_route: If the evaluator cannot be instantiated or fails unexpectedly,
 * reject the affected request (403/503) and log a critical integrity incident.
 *
 * degraded_log: If the evaluator is unavailable, log a degraded incident and allow
 * request processing to proceed without crashing or bricking the site.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
enum EvaluatorFailurePolicy: string {
    case FailClosedRoute = 'fail_closed_route';
    case DegradedLog     = 'degraded_log';
}
