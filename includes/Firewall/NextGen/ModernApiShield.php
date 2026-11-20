<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ModernApiShield
 *
 * Defends WPGraphQL, Headless REST, and WordPress Interactivity / Batch API surfaces against:
 * - Unauthenticated GraphQL __schema / __type introspection harvesting
 * - Deeply nested GraphQL query amplification DoS & alias flooding
 * - Batched GraphQL mutation brute-force attacks
 */
class ModernApiShield implements SecurityModuleInterface, WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'modern-api-shield';
    }

    public function is_required(): bool {
        return false;
    }

    public function get_route_classes(): array {
        return [
            RouteClass::GraphQL,
            RouteClass::RestApi,
        ];
    }

    public function get_required_capabilities(): array {
        return ['graphql'];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::DegradedLog;
    }

    public function get_id(): string {
        return 'modern-api-shield';
    }

    public function get_enable_key(): string {
        return 'waf_nextgen_modern_api_enabled';
    }

    public function get_manifest(): array {
        return [
            'title'       => did_action('init') ? __('GraphQL, Headless & Interactivity API Shield', 'webcare-pro-security') : 'GraphQL, Headless & Interactivity API Shield',
            'description' => did_action('init') ? __('Blocks unauthenticated GraphQL schema introspection, deep nested query DoS, alias amplification, and batched mutation floods.', 'webcare-pro-security') : 'Blocks unauthenticated GraphQL schema introspection, deep nested query DoS, alias amplification, and batched mutation floods.',
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_modern_api_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'API & GraphQL',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        // Evaluated cleanly in early plugins_loaded WAF runtime via WafEvaluatorInterface.
    }

    public function get_settings_defaults(): array {
        return [
            'waf_nextgen_modern_api_enabled'          => true,
            'waf_nextgen_graphql_block_introspection' => true,
            'waf_nextgen_graphql_max_depth'           => 7,
            'waf_nextgen_graphql_max_batch'           => 10,
        ];
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_modern_api_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('GraphQL & Modern API Shield', 'webcare-pro-security') : 'GraphQL & Modern API Shield',
            ],
            'waf_nextgen_graphql_block_introspection' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => did_action('init') ? __('Block Unauthenticated GraphQL Introspection', 'webcare-pro-security') : 'Block Unauthenticated GraphQL Introspection',
            ],
            'waf_nextgen_graphql_max_depth' => [
                'default' => 7,
                'type'    => 'int',
                'min'     => 2,
                'max'     => 20,
                'label'   => did_action('init') ? __('GraphQL Maximum AST Nesting Depth', 'webcare-pro-security') : 'GraphQL Maximum AST Nesting Depth',
            ],
            'waf_nextgen_graphql_max_batch' => [
                'default' => 10,
                'type'    => 'int',
                'min'     => 1,
                'max'     => 50,
                'label'   => did_action('init') ? __('GraphQL Maximum Batched Operations', 'webcare-pro-security') : 'GraphQL Maximum Batched Operations',
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [];
    }

    public function compile_preload_ast(): array {
        return [];
    }

    /**
     * Evaluate incoming GraphQL / batched API requests at plugins_loaded:0.
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        if ($ctx->isAdmin) {
            return null;
        }

        // Fast-path check for GraphQL surface
        $is_graphql = (strpos($ctx->cleanUri, '/graphql') !== false)
            || array_key_exists('graphql', $ctx->params)
            || (!empty($ctx->params['query']) && is_string($ctx->params['query']) && preg_match('/^\s*(?:query|mutation|subscription|\{)/i', $ctx->params['query']));

        if (!$is_graphql) {
            return null;
        }

        $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];

        $block_intro = !empty($settings['waf_nextgen_graphql_block_introspection']);
        $max_depth   = max(2, min(20, intval($settings['waf_nextgen_graphql_max_depth'] ?? 7)));
        $max_batch   = max(1, min(50, intval($settings['waf_nextgen_graphql_max_batch'] ?? 10)));

        $queries = self::extract_graphql_queries($ctx);
        if ($queries === false) {
            // Oversized GraphQL payload exceeding inspection limit: fail-closed with 413 Payload Too Large
            return new WafVerdict(
                'block',
                'WAF-GRAPHQL-PAYLOAD-TOO-LARGE',
                'GraphQL request body exceeds maximum safe inspection limit (256 KB).',
                [
                    'category'    => 'Modern API & GraphQL Shield',
                    'severity'    => 'high',
                    'status_code' => 413,
                ]
            );
        }
        if (empty($queries)) {
            return null;
        }

        if (count($queries) > $max_batch) {
            return new WafVerdict(
                'rate_limit',
                'WAF-GRAPHQL-BATCH-ABUSE',
                sprintf('Batched GraphQL request exceeded limit (%d operations > max %d).', count($queries), $max_batch),
                [
                    'category'    => 'Modern API & GraphQL Shield',
                    'severity'    => 'high',
                    'status_code' => 429,
                ]
            );
        }

        foreach ($queries as $q) {
            if ($block_intro && !$ctx->isLoggedIn && self::contains_introspection($q)) {
                return new WafVerdict(
                    'block',
                    'WAF-GRAPHQL-INTROSPECTION',
                    'Unauthenticated GraphQL __schema / __type introspection query blocked by Modern API Shield.',
                    [
                        'category'    => 'Modern API & GraphQL Shield',
                        'severity'    => 'medium',
                        'status_code' => 403,
                    ]
                );
            }

            $metrics = self::measure_query_complexity($q);
            if ($metrics['max_depth'] > $max_depth || $metrics['alias_count'] > 25) {
                return new WafVerdict(
                    'block',
                    'WAF-GRAPHQL-DEPTH-DOS',
                    sprintf(
                        'GraphQL amplification DoS neutralized (depth %d > max %d, aliases %d).',
                        $metrics['max_depth'],
                        $max_depth,
                        $metrics['alias_count']
                    ),
                    [
                        'category'    => 'Modern API & GraphQL Shield',
                        'severity'    => 'high',
                        'status_code' => 429,
                    ]
                );
            }
        }

        return null;
    }

    /**
     * Extract single or batched GraphQL query strings from RequestContext or php://input JSON/GraphQL body.
     *
     * @return string[]|false Array of queries, or false if payload exceeded 256 KB safety limit.
     */
    public static function extract_graphql_queries(RequestContext $ctx): array|false {
        $queries = [];
        if (!empty($ctx->params['query']) && is_string($ctx->params['query'])) {
            $queries[] = $ctx->params['query'];
        }
        $ct = $ctx->headers['content-type'] ?? '';

        // Handle application/graphql raw text bodies
        $body_reader_class = '\\WebCareProScanner\\Firewall\\Core\\RequestBodyReader';
        if (stripos($ct, 'application/graphql') !== false) {
            $raw = class_exists($body_reader_class)
                ? $body_reader_class::get_bounded_body()
                : (string) @file_get_contents('php://input', false, null, 0, 262145);
            $is_trunc = class_exists($body_reader_class)
                ? $body_reader_class::is_truncated()
                : (strlen($raw) > 262144);

            if ($is_trunc) {
                return false; // Fail closed on oversized payload
            }
            if (trim($raw) !== '') {
                $queries[] = trim($raw);
            }
        } elseif (stripos($ct, 'application/json') !== false) {
            $raw = class_exists($body_reader_class)
                ? $body_reader_class::get_bounded_body()
                : (string) @file_get_contents('php://input', false, null, 0, 262145);
            $is_trunc = class_exists($body_reader_class)
                ? $body_reader_class::is_truncated()
                : (strlen($raw) > 262144);

            if ($is_trunc) {
                return false; // Fail closed on oversized payload
            }
            if ($raw !== '') {
                $decoded = !json_validate($raw) ? null : json_decode($raw, true);
                if (is_array($decoded)) {
                    if (isset($decoded['query']) && is_string($decoded['query']) && !in_array($decoded['query'], $queries, true)) {
                        $queries[] = $decoded['query'];
                    } elseif (isset($decoded[0]) && is_array($decoded[0])) {
                        foreach ($decoded as $item) {
                            if (is_array($item) && !empty($item['query']) && is_string($item['query'])) {
                                $queries[] = $item['query'];
                            }
                        }
                    }
                }
            }
        }
        return $queries;
    }

    /**
     * Lex a GraphQL query string into a stream of non-string, non-comment tokens in a single pass.
     * State machine transitions cleanly through:
     * - NORMAL: unquoted syntax
     * - STRING: double-quoted strings "..." (respecting \" and \\ escapes)
     * - BLOCK_STRING: triple-quoted block strings """...""" (respecting \""" escapes)
     * - COMMENT: single-line comments # ...
     *
     * Invariants guaranteed:
     * - # inside a string literal is strictly string data (never treated as comment start)
     * - " inside a comment is strictly comment data (never starts a string)
     * - Replaces all string literals and comments with safe placeholders, leaving syntax/keywords intact.
     *
     * @param string $query Raw GraphQL query
     * @return string Stripped query containing only executable syntax and identifiers
     */
    public static function lex_graphql_syntax(string $query): string {
        $len = strlen($query);
        $out = '';
        $state = 'NORMAL'; // 'NORMAL' | 'STRING' | 'BLOCK_STRING' | 'COMMENT'
        $i = 0;

        while ($i < $len) {
            $ch = $query[$i];

            if ($state === 'NORMAL') {
                if ($ch === '"') {
                    // Check for block string """
                    if ($i + 2 < $len && $query[$i + 1] === '"' && $query[$i + 2] === '"') {
                        $state = 'BLOCK_STRING';
                        $out .= '""';
                        $i += 3;
                        continue;
                    }
                    $state = 'STRING';
                    $out .= '""';
                    $i++;
                    continue;
                }
                if ($ch === '#') {
                    $state = 'COMMENT';
                    $i++;
                    continue;
                }
                $out .= $ch;
                $i++;
                continue;
            }

            if ($state === 'STRING') {
                if ($ch === '\\') {
                    // Skip escaped character in string
                    $i += 2;
                    continue;
                }
                if ($ch === '"') {
                    $state = 'NORMAL';
                    $i++;
                    continue;
                }
                $i++;
                continue;
            }

            if ($state === 'BLOCK_STRING') {
                if ($ch === '\\' && $i + 3 < $len && $query[$i + 1] === '"' && $query[$i + 2] === '"' && $query[$i + 3] === '"') {
                    // Escaped triple quotes \"""
                    $i += 4;
                    continue;
                }
                if ($ch === '"' && $i + 2 < $len && $query[$i + 1] === '"' && $query[$i + 2] === '"') {
                    $state = 'NORMAL';
                    $i += 3;
                    continue;
                }
                $i++;
                continue;
            }

            if ($state === 'COMMENT') {
                if ($ch === "\r" || $ch === "\n") {
                    $state = 'NORMAL';
                    $out .= $ch;
                }
                $i++;
                continue;
            }
        }

        return $out;
    }

    /**
     * Detect unauthenticated introspection keywords outside quoted strings, block strings, and comments.
     */
    public static function contains_introspection(string $query): bool {
        $stripped = self::lex_graphql_syntax($query);
        return preg_match('/\b__(?:schema|type)\b/', $stripped) === 1;
    }

    /**
     * Measure GraphQL brace nesting depth and alias count safely outside strings/comments.
     *
     * @return array{max_depth: int, alias_count: int}
     */
    public static function measure_query_complexity(string $query): array {
        $stripped = self::lex_graphql_syntax($query);

        $depth     = 0;
        $max_depth = 0;
        $len       = strlen($stripped);

        for ($i = 0; $i < $len; $i++) {
            $ch = $stripped[$i];
            if ($ch === '{') {
                $depth++;
                if ($depth > $max_depth) {
                    $max_depth = $depth;
                }
            } elseif ($ch === '}') {
                $depth = max(0, $depth - 1);
            }
        }

        $alias_count = preg_match_all('/[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*[a-zA-Z_]/', $stripped);

        return [
            'max_depth'   => $max_depth,
            'alias_count' => is_int($alias_count) ? $alias_count : 0,
        ];
    }
}
