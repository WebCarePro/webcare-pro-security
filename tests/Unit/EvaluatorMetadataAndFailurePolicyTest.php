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
use WebCareProScanner\System\SystemDoctor;

final class EvaluatorMetadataAndFailurePolicyTest extends TestCase {

    protected function tearDown(): void {
        parent::tearDown();
        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, null);
    }

    public function test_evaluator_metadata_contract_types(): void {
        $engine = new ExploitSignatureEngine();
        $this->assertInstanceOf(WafEvaluatorInterface::class, $engine);
        $this->assertSame('exploit-signature-engine', $engine->get_module_id());
        $this->assertTrue($engine->is_required());
        $this->assertSame(EvaluatorFailurePolicy::FailClosedRoute, $engine->get_failure_policy());
        $this->assertNotEmpty($engine->get_route_classes());
    }

    public function test_compiled_stack_manifest_includes_evaluator_metadata(): void {
        $routes = [
            RouteClass::PublicGet->value => [
                ExploitSignatureEngine::class,
                'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator',
            ],
        ];

        $metadata = CompiledStackManifest::compile_evaluator_metadata($routes);

        $this->assertArrayHasKey(ExploitSignatureEngine::class, $metadata);
        $this->assertSame('exploit-signature-engine', $metadata[ExploitSignatureEngine::class]['module_id']);
        $this->assertTrue($metadata[ExploitSignatureEngine::class]['required']);
        $this->assertSame('fail_closed_route', $metadata[ExploitSignatureEngine::class]['failure_policy']);

        $ai_class = 'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator';
        $this->assertArrayHasKey($ai_class, $metadata);
        $this->assertSame('ai-agent-behavior', $metadata[$ai_class]['module_id']);
        $this->assertFalse($metadata[$ai_class]['required']);
        $this->assertSame('degraded_log', $metadata[$ai_class]['failure_policy']);
    }

    public function test_missing_mandatory_evaluator_fails_closed(): void {
        $ctx = RequestContext::from_globals([
            'REQUEST_URI'    => '/test-page',
            'REQUEST_METHOD' => 'GET',
        ]);

        // Mock manifest that maliciously omits ExploitSignatureEngine
        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'routes' => [
                RouteClass::PublicGet->value => [
                    'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator',
                ],
            ],
            'evaluators' => [],
        ]);

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-REQUIRED-EVALUATOR-MISSING', $verdict->ruleId);
        $this->assertSame(503, $verdict->statusCode);
    }

    public function test_missing_optional_evaluator_logs_degraded_and_does_not_throw(): void {
        $_SERVER['REQUEST_URI'] = '/test-page';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/test-page'
        );

        // Mock manifest with mandatory AlwaysOnCoreGuard & ExploitSignatureEngine PLUS a non-existent optional evaluator
        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'routes' => [
                RouteClass::PublicGet->value => [
                    \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class,
                    ExploitSignatureEngine::class,
                    'NonExistentOptionalEvaluatorClass',
                ],
            ],
            'evaluators' => [
                \WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard::class => [
                    'module_id'      => 'always-on-core-guard',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                ],
                ExploitSignatureEngine::class => [
                    'module_id'      => 'exploit-signature-engine',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                ],
                'NonExistentOptionalEvaluatorClass' => [
                    'module_id'      => 'non-existent',
                    'required'       => false,
                    'failure_policy' => 'degraded_log',
                    'capabilities'   => [],
                ],
            ],
        ]);

        // Should NOT throw an exception; should return null (clean pass)
        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertNull($verdict);
    }

    public function test_declared_required_evaluator_missing_from_runtime_fails_closed(): void {
        $_SERVER['REQUEST_URI'] = '/test-page';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/test-page'
        );

        $ref = new \ReflectionClass(CompiledStackManifest::class);
        $prop = $ref->getProperty('request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, [
            'routes' => [
                RouteClass::PublicGet->value => [
                    ExploitSignatureEngine::class,
                    'NonExistentRequiredEvaluatorClass',
                ],
            ],
            'evaluators' => [
                ExploitSignatureEngine::class => [
                    'module_id'      => 'exploit-signature-engine',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                ],
                'NonExistentRequiredEvaluatorClass' => [
                    'module_id'      => 'non-existent-req',
                    'required'       => true,
                    'failure_policy' => 'fail_closed_route',
                    'capabilities'   => [],
                    'missing'        => true,
                ],
            ],
        ]);

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-REQUIRED-EVALUATOR-MISSING', $verdict->ruleId);
        $this->assertSame(503, $verdict->statusCode);
    }

    public function test_system_doctor_evaluator_pipeline_check(): void {
        $report = SystemDoctor::run_diagnostics();
        $this->assertIsArray($report['checks']);
        $found = false;
        foreach ($report['checks'] as $c) {
            if ($c['id'] === 'evaluator_pipeline') {
                $found = true;
                $this->assertSame('pass', $c['status']);
                break;
            }
        }
        $this->assertTrue($found, 'evaluator_pipeline check must be present in SystemDoctor diagnostics.');
    }
}
