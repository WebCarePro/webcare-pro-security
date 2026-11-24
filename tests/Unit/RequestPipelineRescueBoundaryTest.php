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
use WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\Core\RequestPipeline;

final class ThrowingMandatoryRescueEvaluator implements WafEvaluatorInterface
{
    public function get_module_id(): string
    {
        return 'throwing-mandatory-rescue-evaluator';
    }

    public function is_required(): bool
    {
        return true;
    }

    public function get_route_classes(): array
    {
        return [RouteClass::AdminUi];
    }

    public function get_required_capabilities(): array
    {
        return [];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy
    {
        return EvaluatorFailurePolicy::FailClosedRoute;
    }

    public function compile_preload_ast(): array
    {
        return [];
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict
    {
        throw new \RuntimeException('Simulated mandatory evaluator crash');
    }
}

/**
 * RequestPipelineRescueBoundaryTest
 *
 * Verifies that the outer pipeline rescue boundary strictly allows ONLY read-only
 * admin console rescue requests with whitelisted query keys, and never fails open
 * for POST, login, mutating endpoints, or action query parameters.
 */
final class RequestPipelineRescueBoundaryTest extends TestCase
{
    private array $origServer;
    private array $origGet;

    private static function setManifestCache(?array $manifest): void
    {
        $prop = new \ReflectionProperty(CompiledStackManifest::class, 'request_cache');
        $prop->setAccessible(true);
        $prop->setValue(null, $manifest);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $_GET = [];
        $GLOBALS['wp_mock_current_user_can'] = false;
        RequestPipeline::$throw_on_exit_in_tests = false;
        RequestPipeline::$last_terminated_status = null;
        self::setManifestCache(null);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $GLOBALS['wp_mock_current_user_can'] = false;
        RequestPipeline::$throw_on_exit_in_tests = false;
        RequestPipeline::$last_terminated_status = null;
        self::setManifestCache(null);
        parent::tearDown();
    }

    private function authenticateAdminUser(): void
    {
        $GLOBALS['wp_mock_current_user_can'] = true;
        if (function_exists('wp_set_current_user')) {
            $user = wp_set_current_user(1, 'administrator');
            $user->roles = ['administrator'];
            $user->allcaps = ['manage_options' => true, 'administrator' => true];
        }
    }

    public function test_rejects_post_requests_even_if_admin(): void
    {
        $this->authenticateAdminUser();
        $_GET = ['page' => 'webcare-pro-security'];
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'POST',
            uri: '/wp-admin/admin.php?page=webcare-pro-security',
            userAgent: 'Mozilla/5.0'
        );

        $this->assertFalse(
            RequestPipeline::is_read_only_rescue_request($ctx),
            'Rescue boundary must reject POST requests even with an admin session.'
        );
    }

    public function test_rejects_wp_login_even_if_get(): void
    {
        $this->authenticateAdminUser();
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-login.php',
            userAgent: 'Mozilla/5.0'
        );

        $this->assertFalse(
            RequestPipeline::is_read_only_rescue_request($ctx),
            'wp-login.php must never be treated as a rescue endpoint.'
        );
    }

    public function test_rejects_admin_ajax_and_options(): void
    {
        $this->authenticateAdminUser();

        $ajaxCtx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-admin/admin-ajax.php?action=something',
            userAgent: 'Mozilla/5.0'
        );
        $this->assertFalse(RequestPipeline::is_read_only_rescue_request($ajaxCtx));

        $optionsCtx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-admin/options.php',
            userAgent: 'Mozilla/5.0'
        );
        $this->assertFalse(RequestPipeline::is_read_only_rescue_request($optionsCtx));
    }

    public function test_rejects_unauthenticated_requests(): void
    {
        $GLOBALS['wp_mock_current_user_can'] = false;
        $GLOBALS['wp_mock_current_user'] = null;
        $_GET = ['page' => 'webcare-pro-security'];

        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-admin/admin.php?page=webcare-pro-security',
            userAgent: 'Mozilla/5.0'
        );

        $this->assertFalse(
            RequestPipeline::is_read_only_rescue_request($ctx),
            'Unauthenticated requests must be rejected from rescue boundary.'
        );
    }

    public function test_permits_authenticated_admin_console_rescue(): void
    {
        $this->authenticateAdminUser();
        $_GET = ['page' => 'webcare-pro-security', 'tab' => 'rescue'];

        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-admin/admin.php?page=webcare-pro-security&tab=rescue',
            userAgent: 'Mozilla/5.0'
        );

        $this->assertTrue(
            RequestPipeline::is_read_only_rescue_request($ctx),
            'Authenticated admin accessing webcare-pro-security&tab=rescue must be permitted.'
        );
    }

    public function test_rejects_all_mutating_query_parameters_on_admin_php(): void
    {
        $this->authenticateAdminUser();

        $forbiddenKeys = [
            'action', 'action2', 'delete', 'reset', 'restore', 'approve',
            'reject', 'revoke', 'clear', 'purge', 'deactivate', 'activate',
            '_wpnonce', 'nonce', 'webcareproscan_action',
        ];

        foreach ($forbiddenKeys as $forbiddenKey) {
            $_GET = ['page' => 'webcare-pro-settings', $forbiddenKey => '1'];
            $ctx = new RequestContext(
                ip: '127.0.0.1',
                method: 'GET',
                uri: "/wp-admin/admin.php?page=webcare-pro-settings&{$forbiddenKey}=1",
                userAgent: 'Mozilla/5.0'
            );

            $this->assertFalse(
                RequestPipeline::is_read_only_rescue_request($ctx),
                "Rescue boundary must reject forbidden query parameter '{$forbiddenKey}'."
            );
        }
    }

    public function test_mandatory_evaluator_exception_returns_503_on_action_reset_but_permits_tab_rescue(): void
    {
        $this->authenticateAdminUser();

        $manifest = [
            'version'    => 'test',
            'ecosystems' => [],
            'evaluators' => [
                AlwaysOnCoreGuard::class => ['required' => true, 'failure_policy' => EvaluatorFailurePolicy::FailClosedRoute->value],
                ExploitSignatureEngine::class => ['required' => true, 'failure_policy' => EvaluatorFailurePolicy::FailClosedRoute->value],
                ThrowingMandatoryRescueEvaluator::class => ['required' => true, 'failure_policy' => EvaluatorFailurePolicy::FailClosedRoute->value],
            ],
            'routes' => [
                RouteClass::AdminUi->value => [
                    AlwaysOnCoreGuard::class,
                    ExploitSignatureEngine::class,
                    ThrowingMandatoryRescueEvaluator::class,
                ],
            ],
        ];
        self::setManifestCache($manifest);

        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';

        // 1. /wp-admin/admin.php?page=webcare-pro-settings&action=reset MUST fail closed with HTTP 503
        RequestPipeline::$throw_on_exit_in_tests = true;
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin.php?page=webcare-pro-settings&action=reset';
        $_GET = ['page' => 'webcare-pro-settings', 'action' => 'reset'];

        $caughtCode = 0;
        try {
            RequestPipeline::process_incoming_request();
        } catch (\RuntimeException $e) {
            $caughtCode = $e->getCode();
        }

        $this->assertSame(503, $caughtCode, 'Mutating query param action=reset must terminate with HTTP 503 when mandatory evaluator throws.');
        $this->assertSame(503, RequestPipeline::$last_terminated_status);

        // 2. /wp-admin/admin.php?page=webcare-pro-security&tab=rescue MUST succeed for authenticated admin
        //    and record structured AuditLogger::log_operational() diagnostics without raw exception messages or activity ledger bridging
        $capturedOps = [];
        \WebCareProScanner\System\AuditLogger::$operational_log_hook = static function (string $event, $details) use (&$capturedOps): void {
            $capturedOps[] = ['event' => $event, 'details' => $details];
        };

        RequestPipeline::$last_terminated_status = null;
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin.php?page=webcare-pro-security&tab=rescue';
        $_GET = ['page' => 'webcare-pro-security', 'tab' => 'rescue'];

        try {
            RequestPipeline::process_incoming_request();
        } finally {
            \WebCareProScanner\System\AuditLogger::$operational_log_hook = null;
        }
        $this->assertSame(200, RequestPipeline::$last_terminated_status, 'Clean read-only rescue tab must succeed for authenticated admin.');

        $rescueEvents = array_values(array_filter(
            $capturedOps,
            static fn(array $row): bool => $row['event'] === 'waf_pipeline_rescue_boundary_invoked'
        ));
        $this->assertCount(1, $rescueEvents, 'Rescue boundary must emit structured AuditLogger::log_operational() telemetry.');
        $details = $rescueEvents[0]['details'];
        $this->assertIsArray($details);
        $this->assertSame('RuntimeException', $details['exception_class'] ?? '');
        $this->assertSame('/wp-admin/admin.php', $details['rescue_path'] ?? '');
        $this->assertStringNotContainsString(
            'Simulated mandatory evaluator crash',
            (string) json_encode($details),
            'Structured rescue operational telemetry must not expose raw exception messages.'
        );
        $this->assertFalse(
            \WebCareProScanner\System\WebCareActivityLogger::has_action_logged('waf_pipeline_rescue_boundary_invoked'),
            'Operational rescue diagnostic must remain outside WebCareActivityLogger admin ledger.'
        );
    }

    public function test_permits_authenticated_admin_rest_doctor_rescue(): void
    {
        $this->authenticateAdminUser();
        $_GET = [];

        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/wp-json/webcare-pro-security/v1/system/doctor',
            userAgent: 'Mozilla/5.0'
        );

        $this->assertTrue(
            RequestPipeline::is_read_only_rescue_request($ctx),
            'Authenticated admin accessing REST system/doctor must be permitted rescue.'
        );
    }
}
