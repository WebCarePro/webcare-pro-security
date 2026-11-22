<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\Evaluators\ProtocolAndBotEvaluator;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

/**
 * ProtocolAndBotEvaluatorTest
 *
 * Tests for PR-H2 ProtocolAndBotEvaluator behavioral equivalence, contract adherence,
 * protocol anomalies, dormant attack surface lockdown, blank UA/Referer POST handling,
 * CORS and webhook safe-passing, and early-boot notice-free execution.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ProtocolAndBotEvaluatorTest extends TestCase {

    private array $origServer;
    private array $origGet;
    private array $origPost;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $this->origPost = $_POST;
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $_POST = $this->origPost;
        unset($GLOBALS['wp_mock_options']['webcareproscan_caf_stack_snapshot']);
        unset($GLOBALS['wp_mock_options']['webcare_pow_enforced_ips']);
        \wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_contract_metadata_declarations(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $this->assertInstanceOf(WafEvaluatorInterface::class, $evaluator);
        $this->assertSame('protocol-and-bot-evaluator', $evaluator->get_module_id());
        $this->assertFalse($evaluator->is_required());
        $this->assertSame(RouteClass::cases(), $evaluator->get_route_classes());
        $this->assertSame([], $evaluator->get_required_capabilities());
        $this->assertSame(EvaluatorFailurePolicy::DegradedLog, $evaluator->get_failure_policy());
    }

    public function test_malformed_uppercase_http2_pseudo_header_blocked(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.50',
            method: 'GET',
            uri: '/public-endpoint',
            headers: [
                ':Method' => 'GET',
                ':path'   => '/public-endpoint',
            ],
            server: [
                'SERVER_PROTOCOL' => 'HTTP/2.0',
            ]
        );

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('BOT-H2-HEADER-ANOMALY', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_dormant_inactive_plugin_surface_blocked(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);
        update_option('webcareproscan_caf_lock_dormant_surface', true);

        // Snapshot showing inactive-plugin is deactivated
        $GLOBALS['wp_mock_options']['webcareproscan_caf_stack_snapshot'] = [
            'inactive_plugins' => [
                'revslider' => ['Name' => 'Slider Revolution'],
            ],
            'inactive_themes' => [],
        ];

        $ctx = new RequestContext(
            ip: '198.51.100.51',
            method: 'GET',
            uri: '/wp-content/plugins/revslider/temp/upload.php'
        );

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-CAF-DORMANT-SURFACE', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_blank_ua_and_referer_post_blocked(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_empty_post_ua_referer'] = true;
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.52',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: '',
            server: [
                'HTTP_REFERER' => '',
            ]
        );

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-EMPTY-POST-UA-REFERER', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_cors_options_and_verified_stripe_webhook_pass(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_empty_post_ua_referer'] = true;
        $settings['waf_block_empty_user_agent'] = true;
        update_option('webcareproscan_settings', $settings);

        // 1. CORS Preflight OPTIONS with empty User-Agent
        $corsCtx = new RequestContext(
            ip: '198.51.100.53',
            method: 'OPTIONS',
            uri: '/wp-json/wp/v2/posts',
            userAgent: ''
        );
        $this->assertNull($evaluator->evaluate_runtime_request($corsCtx));

        // 2. Verified Stripe Webhook IP POST with empty User-Agent
        $stripeIp = CommerceSessionGuard::STRIPE_WEBHOOK_IPS[0];
        $stripeCtx = new RequestContext(
            ip: $stripeIp,
            method: 'POST',
            uri: '/wp-json/stripe/webhook',
            userAgent: '',
            server: [
                'HTTP_REFERER' => '',
            ]
        );
        $this->assertNull($evaluator->evaluate_runtime_request($stripeCtx));
    }

    public function test_authenticated_admin_and_builder_bypass_operational_heuristics(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_empty_post_ua_referer'] = true;
        update_option('webcareproscan_settings', $settings);

        // Authenticated admin bypass
        \wp_set_current_user(1);
        $user = \wp_get_current_user();
        $user->roles = ['administrator'];
        $user->allcaps = ['manage_options' => true];

        $ctx = new RequestContext(
            ip: '198.51.100.54',
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            userAgent: '',
            server: [
                'HTTP_REFERER' => '',
            ]
        );

        $this->assertNull($evaluator->evaluate_runtime_request($ctx));
        \wp_set_current_user(0);
    }

    public function test_early_boot_execution_emits_zero_notices(): void {
        $evaluator = new ProtocolAndBotEvaluator();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/safe-page',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        );

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertNull($verdict);
    }
}
