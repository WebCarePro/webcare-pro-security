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
use WebCareProScanner\Core\RouteClassifier;
use WebCareProScanner\Firewall\Evaluators\AuthAndAjaxSurfaceEvaluator;
use WebCareProScanner\System\SettingsManager;

/**
 * AuthAndAjaxSurfaceEvaluatorTest
 *
 * Unit tests for PR-H3 AuthAndAjaxSurfaceEvaluator extraction asserting:
 * 1. Array type-confusion payload (user_login[]=admin) on /wp-login.php returns 403.
 * 2. Disabled XML-RPC request to /xmlrpc.php is blocked (while verified Jetpack CIDR passes).
 * 3. Unauthenticated admin-ajax.php burst rate-limit returns 429 while legitimate WooCommerce cart/form actions pass.
 * 4. CompiledStackManifest route table for RouteClass::PublicGet does not include AuthAndAjaxSurfaceEvaluator.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AuthAndAjaxSurfaceEvaluatorTest extends TestCase {

    private array $origServer;
    private array $origGet;
    private array $origPost;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $this->origPost = $_POST;
        \wp_set_current_user(0);
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $_POST = $this->origPost;
        \wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_contract_metadata_declarations(): void {
        $evaluator = new AuthAndAjaxSurfaceEvaluator();
        $this->assertInstanceOf(WafEvaluatorInterface::class, $evaluator);
        $this->assertSame('auth-and-ajax-surface-evaluator', $evaluator->get_module_id());
        $this->assertFalse($evaluator->is_required());
        $this->assertSame([
            RouteClass::AuthLogin,
            RouteClass::AdminAjax,
            RouteClass::AdminUi,
        ], $evaluator->get_route_classes());
        $this->assertSame([], $evaluator->get_required_capabilities());
        $this->assertSame(EvaluatorFailurePolicy::DegradedLog, $evaluator->get_failure_policy());
    }

    public function test_auth_array_type_confusion_on_login_endpoint_blocked_with_403(): void {
        $evaluator = new AuthAndAjaxSurfaceEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.80',
            method: 'POST',
            uri: '/wp-login.php',
            formParams: [
                'user_login' => ['admin'],
                'pwd'        => 'password123',
            ]
        );

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-AUTH-TYPE-CONFUSION', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_disabled_xmlrpc_blocked_while_verified_jetpack_passes(): void {
        $evaluator = new AuthAndAjaxSurfaceEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_disable_xmlrpc'] = true;
        $settings['waf_allow_jetpack_xmlrpc'] = true;
        update_option('webcareproscan_settings', $settings);

        // 1. Untrusted attacker IP to /xmlrpc.php -> blocked with 403
        $untrustedCtx = new RequestContext(
            ip: '198.51.100.81',
            method: 'POST',
            uri: '/xmlrpc.php'
        );
        $verdict = $evaluator->evaluate_runtime_request($untrustedCtx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-XMLRPC-DISABLED', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);

        // 2. Official Automattic Jetpack CIDR (e.g. 192.0.64.1) with ?for=jetpack and token -> passes
        $jetpackCtx = new RequestContext(
            ip: '192.0.64.1',
            method: 'POST',
            uri: '/xmlrpc.php?for=jetpack&token=valid_test_token',
            headers: [
                'x-jetpack-signature' => 'mock_valid_signature',
            ]
        );
        $jetpackVerdict = $evaluator->evaluate_runtime_request($jetpackCtx);
        $this->assertNull($jetpackVerdict);
    }

    public function test_unauthenticated_admin_ajax_burst_rate_limit_and_cart_form_pass(): void {
        $evaluator = new AuthAndAjaxSurfaceEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_limit_admin_ajax'] = true;
        $settings['waf_admin_ajax_limit_per_min'] = 3;
        $settings['waf_ecommerce_safe_mode'] = true;
        $settings['waf_forms_safe_mode'] = true;
        update_option('webcareproscan_settings', $settings);

        $burstIp = '198.51.100.82';

        // 1. Legitimate WooCommerce public customer cart action -> passes without triggering rate limit
        $wooCartCtx = new RequestContext(
            ip: $burstIp,
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            formParams: [
                'action' => 'woocommerce_get_refreshed_fragments',
            ]
        );
        $this->assertNull($evaluator->evaluate_runtime_request($wooCartCtx));

        // 2. Legitimate form submission action (WPForms) -> passes without triggering rate limit
        $formCtx = new RequestContext(
            ip: $burstIp,
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            formParams: [
                'action' => 'wpforms_submit',
            ]
        );
        $this->assertNull($evaluator->evaluate_runtime_request($formCtx));

        // 3. Repeated unknown/unexempt guest AJAX hits -> hits rate limit on 4th hit
        $unknownCtx = new RequestContext(
            ip: $burstIp,
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            formParams: [
                'action' => 'heartbeat',
            ]
        );

        // 3 requests allowed within rate limit threshold
        $this->assertNull($evaluator->evaluate_runtime_request($unknownCtx));
        $this->assertNull($evaluator->evaluate_runtime_request($unknownCtx));
        $this->assertNull($evaluator->evaluate_runtime_request($unknownCtx));

        // 4th request must be rate limited (429)
        $burstVerdict = $evaluator->evaluate_runtime_request($unknownCtx);
        $this->assertInstanceOf(WafVerdict::class, $burstVerdict);
        $this->assertSame('rate_limit', $burstVerdict->get_action_value());
        $this->assertSame('WAF-ADMIN-AJAX-BURST', $burstVerdict->ruleId);
        $this->assertSame(429, $burstVerdict->statusCode);
    }

    public function test_prohibited_plugin_installations_blocked(): void {
        $evaluator = new AuthAndAjaxSurfaceEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_disallow_phpmyadmin_plugins'] = true;
        $settings['waf_disallow_filemanager_plugins'] = true;
        update_option('webcareproscan_settings', $settings);

        // 1. phpMyAdmin plugin install attempt
        $pmaCtx = new RequestContext(
            ip: '198.51.100.83',
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            formParams: [
                'action' => 'install-plugin',
                'slug'   => 'wp-phpmyadmin-extension',
            ]
        );
        $pmaVerdict = $evaluator->evaluate_runtime_request($pmaCtx);
        $this->assertInstanceOf(WafVerdict::class, $pmaVerdict);
        $this->assertSame('block', $pmaVerdict->get_action_value());
        $this->assertSame('WAF-DISALLOW-PHPMYADMIN-PLUGIN', $pmaVerdict->ruleId);
        $this->assertSame(403, $pmaVerdict->statusCode);

        // 2. File manager plugin install attempt
        $fmCtx = new RequestContext(
            ip: '198.51.100.83',
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            formParams: [
                'action' => 'install-plugin',
                'slug'   => 'wp-file-manager',
            ]
        );
        $fmVerdict = $evaluator->evaluate_runtime_request($fmCtx);
        $this->assertInstanceOf(WafVerdict::class, $fmVerdict);
        $this->assertSame('block', $fmVerdict->get_action_value());
        $this->assertSame('WAF-DISALLOW-FILEMANAGER-PLUGIN', $fmVerdict->ruleId);
        $this->assertSame(403, $fmVerdict->statusCode);
    }

    public function test_compiled_stack_manifest_excludes_evaluator_from_frontend_routes(): void {
        $compileRes = CompiledStackManifest::compile();
        $this->assertTrue($compileRes['success']);

        $manifest = CompiledStackManifest::load();
        $this->assertIsArray($manifest);
        $this->assertArrayHasKey('routes', $manifest);

        $evaluatorClass = AuthAndAjaxSurfaceEvaluator::class;

        // Must NOT be present in RouteClass::PublicGet or RouteClass::PublicMutation
        $this->assertNotContains(
            $evaluatorClass,
            $manifest['routes'][RouteClass::PublicGet->value] ?? [],
            'AuthAndAjaxSurfaceEvaluator must not be registered for public_get frontend routes'
        );
        $this->assertNotContains(
            $evaluatorClass,
            $manifest['routes'][RouteClass::PublicMutation->value] ?? [],
            'AuthAndAjaxSurfaceEvaluator must not be registered for public_mutation frontend routes'
        );

        // MUST be present in AuthLogin, AdminAjax, and AdminUi
        $this->assertContains(
            $evaluatorClass,
            $manifest['routes'][RouteClass::AuthLogin->value] ?? [],
            'AuthAndAjaxSurfaceEvaluator must be registered for auth_login routes'
        );
        $this->assertContains(
            $evaluatorClass,
            $manifest['routes'][RouteClass::AdminAjax->value] ?? [],
            'AuthAndAjaxSurfaceEvaluator must be registered for admin_ajax routes'
        );
        $this->assertContains(
            $evaluatorClass,
            $manifest['routes'][RouteClass::AdminUi->value] ?? [],
            'AuthAndAjaxSurfaceEvaluator must be registered for admin_ui routes'
        );
    }
}
