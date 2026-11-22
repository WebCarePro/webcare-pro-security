<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\Core\RequestPipeline;
use WebCareProScanner\Firewall\FirewallEngine;

class MockGraphQLOnlyEvaluator implements WafEvaluatorInterface {
    public static int $invocation_count = 0;

    public function get_module_id(): string {
        return 'mock-graphql-evaluator';
    }

    public function is_required(): bool {
        return false;
    }

    public function get_route_classes(): array {
        return [RouteClass::GraphQL];
    }

    public function get_required_capabilities(): array {
        return ['graphql'];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::DegradedLog;
    }

    public function compile_preload_ast(): array {
        return [];
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        self::$invocation_count++;
        return null;
    }
}

final class DualAxisAdaptiveLoadingTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        MockGraphQLOnlyEvaluator::$invocation_count = 0;
        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, null);
    }

    protected function tearDown(): void {
        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, null);
        parent::tearDown();
    }

    public function test_evaluator_skipped_when_capability_missing(): void {
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'POST',
            uri: '/graphql'
        );

        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'ecosystems' => [
                'graphql'     => false,
                'woocommerce' => false,
            ],
            'routes' => [
                RouteClass::GraphQL->value => [
                    \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class,
                    ExploitSignatureEngine::class,
                    MockGraphQLOnlyEvaluator::class,
                ],
            ],
            'evaluators' => [
                \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class => [
                    'module_id'      => 'always-on-core-guard',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                ExploitSignatureEngine::class => [
                    'module_id'      => 'exploit-signature-engine',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                MockGraphQLOnlyEvaluator::class => [
                    'module_id'      => 'mock-graphql-evaluator',
                    'required'       => false,
                    'failure_policy' => 'degraded_log',
                    'capabilities'   => ['graphql'],
                    'route_classes'  => [RouteClass::GraphQL->value],
                ],
            ],
        ]);

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertNull($verdict);
        $this->assertSame(0, MockGraphQLOnlyEvaluator::$invocation_count, 'Evaluator must be skipped when ecosystem capability is missing.');
    }

    public function test_evaluator_skipped_when_route_class_mismatches(): void {
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/public-post/'
        );

        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'ecosystems' => [
                'graphql' => true,
            ],
            'routes' => [
                RouteClass::PublicGet->value => [
                    \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class,
                    ExploitSignatureEngine::class,
                    MockGraphQLOnlyEvaluator::class,
                ],
            ],
            'evaluators' => [
                \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class => [
                    'module_id'      => 'always-on-core-guard',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                ExploitSignatureEngine::class => [
                    'module_id'      => 'exploit-signature-engine',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                MockGraphQLOnlyEvaluator::class => [
                    'module_id'      => 'mock-graphql-evaluator',
                    'required'       => false,
                    'failure_policy' => 'degraded_log',
                    'capabilities'   => ['graphql'],
                    'route_classes'  => [RouteClass::GraphQL->value],
                ],
            ],
        ]);

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertNull($verdict);
        $this->assertSame(0, MockGraphQLOnlyEvaluator::$invocation_count, 'Evaluator must be skipped when route class does not match.');
    }

    public function test_evaluator_runs_when_both_capability_and_route_match(): void {
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'POST',
            uri: '/graphql'
        );

        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'ecosystems' => [
                'graphql' => true,
            ],
            'routes' => [
                RouteClass::GraphQL->value => [
                    \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class,
                    ExploitSignatureEngine::class,
                    MockGraphQLOnlyEvaluator::class,
                ],
            ],
            'evaluators' => [
                \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class => [
                    'module_id'      => 'always-on-core-guard',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                ExploitSignatureEngine::class => [
                    'module_id'      => 'exploit-signature-engine',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'route_classes'  => [],
                ],
                MockGraphQLOnlyEvaluator::class => [
                    'module_id'      => 'mock-graphql-evaluator',
                    'required'       => false,
                    'failure_policy' => 'degraded_log',
                    'capabilities'   => ['graphql'],
                    'route_classes'  => [RouteClass::GraphQL->value],
                ],
            ],
        ]);

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertNull($verdict);
        $this->assertSame(1, MockGraphQLOnlyEvaluator::$invocation_count, 'Evaluator must execute when both capability and route match.');
    }

    public function test_plain_blog_route_excludes_specialized_evaluators(): void {
        $manifest = CompiledStackManifest::load();
        $this->assertIsArray($manifest);
        $this->assertArrayHasKey('routes', $manifest);

        $public_get_evaluators = $manifest['routes'][RouteClass::PublicGet->value] ?? [];

        // Required and core evaluators MUST run on PublicGet
        $this->assertContains(\WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class, $public_get_evaluators);
        $this->assertContains(ExploitSignatureEngine::class, $public_get_evaluators);

        // Specialized domain evaluators MUST NOT be included on PublicGet
        $this->assertNotContains(
            \WebCareProScanner\Firewall\Evaluators\AuthAndAjaxSurfaceEvaluator::class,
            $public_get_evaluators,
            'AuthAndAjaxSurfaceEvaluator must NOT run on plain blog GET routes.'
        );
        $this->assertNotContains(
            \WebCareProScanner\Firewall\Evaluators\CommerceAndUploadEvaluator::class,
            $public_get_evaluators,
            'CommerceAndUploadEvaluator must NOT run on plain blog GET routes.'
        );
        $this->assertNotContains(
            \WebCareProScanner\Firewall\NextGen\ModernApiShield::class,
            $public_get_evaluators,
            'ModernApiShield must NOT run on plain blog GET routes.'
        );
    }
}
