<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

/**
 * AlwaysOnCoreGuardTest
 *
 * Tests for PR-H1 AlwaysOnCoreGuard behavioral equivalence, contract adherence,
 * deduplicated IP blocklist/allowlist, protocol armor, buffer ceilings, and notice-free execution.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AlwaysOnCoreGuardTest extends TestCase {

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
        parent::tearDown();
    }

    public function test_contract_metadata_declarations(): void {
        $guard = new AlwaysOnCoreGuard();
        $this->assertInstanceOf(WafEvaluatorInterface::class, $guard);
        $this->assertSame('always-on-core-guard', $guard->get_module_id());
        $this->assertTrue($guard->is_required());
        $this->assertSame(RouteClass::cases(), $guard->get_route_classes());
        $this->assertSame([], $guard->get_required_capabilities());
        $this->assertSame(\WebCareProScanner\Contracts\EvaluatorFailurePolicy::FailClosedRoute, $guard->get_failure_policy());
    }

    public function test_blocked_ip_returns_403_verdict(): void {
        $guard = new AlwaysOnCoreGuard();
        $bannedIp = '203.0.113.88';

        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_blocked_ips'] = "198.51.100.1\n" . $bannedIp;

        // Mock block metadata
        FirewallEngine::set_ip_block_meta($bannedIp, [
            'reason'    => 'Malicious bot activity',
            'source'    => 'custom_blocklist',
            'rule_name' => 'Custom Block',
        ]);

        $ctx = new RequestContext(
            ip: $bannedIp,
            method: 'GET',
            uri: '/hello-world/'
        );

        // Update settings in memory
        update_option('webcareproscan_settings', $settings);

        $verdict = $guard->evaluate_runtime_request($ctx);

        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('USER-CUSTOM-IP-BLOCK', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);

        // Cleanup
        BlocklistRepository::remove_blocked_ip($bannedIp);
    }

    public function test_expired_ip_ban_auto_heals(): void {
        $guard = new AlwaysOnCoreGuard();
        $expiredIp = '203.0.113.99';

        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_blocked_ips'] = $expiredIp;

        // Mock block metadata with past expiration
        FirewallEngine::set_ip_block_meta($expiredIp, [
            'reason'     => 'Temporary ban',
            'expires_at' => time() - 60, // expired 1 minute ago
        ]);
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: $expiredIp,
            method: 'GET',
            uri: '/hello-world/'
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        // Ban expired; should auto-heal and return null
        $this->assertNull($verdict);
    }

    public function test_verified_shopper_bypasses_operational_ban(): void {
        $guard = new AlwaysOnCoreGuard();
        $shopperIp = '203.0.113.150';

        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_blocked_ips'] = $shopperIp;

        // Rate-limit operational ban
        FirewallEngine::set_ip_block_meta($shopperIp, [
            'reason'  => '404 rate limit exceeded',
            'rule_id' => 'RATE-LIMIT-404-LOCKOUT',
            'source'  => 'rate_limit',
        ]);
        update_option('webcareproscan_settings', $settings);

        // Mock active customer session
        $ref = new \ReflectionClass(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::class);
        $prop = $ref->getProperty('runtime_ecosystems');
        $prop->setAccessible(true);
        $prop->setValue(null, ['commerce', 'woocommerce']);

        \wp_set_current_user(2);
        $user = \wp_get_current_user();
        $user->roles = ['customer'];

        $ctx = new RequestContext(
            ip: $shopperIp,
            method: 'GET',
            uri: '/shop/'
        );

        $this->assertTrue(CommerceSessionGuard::is_exempt_from_operational_ban());

        $verdict = $guard->evaluate_runtime_request($ctx);
        // Operational ban bypassed for active shopper session
        $this->assertNull($verdict);

        \wp_set_current_user(0);
        BlocklistRepository::remove_blocked_ip($shopperIp);
    }

    public function test_unsafe_http_methods_blocked_with_405(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_unsafe_http_methods'] = true;
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.12',
            method: 'TRACE',
            uri: '/some-page'
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-UNSAFE-HTTP-METHOD', $verdict->ruleId);
        $this->assertSame(405, $verdict->statusCode);
    }

    public function test_unauthenticated_put_on_non_rest_route_blocked(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.15',
            method: 'PUT',
            uri: '/uploads/shell.php'
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-UNAUTHORIZED-PUT-UPLOAD', $verdict->ruleId);
        $this->assertSame(405, $verdict->statusCode);
    }

    public function test_method_override_smuggling_blocked(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.18',
            method: 'POST',
            uri: '/wp-json/wp/v2/posts/1',
            headers: ['x-http-method-override' => 'DELETE'],
            params: ['_method' => 'DELETE']
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-REST-METHOD-SMUGGLE', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_oversized_uri_blocked_with_414(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_oversized_requests'] = true;
        update_option('webcareproscan_settings', $settings);

        $longUri = '/test?' . str_repeat('a=1&', 1200); // > 4096 bytes
        $ctx = new RequestContext(
            ip: '198.51.100.22',
            method: 'GET',
            uri: $longUri
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-OVERSIZED-URI', $verdict->ruleId);
        $this->assertSame(414, $verdict->statusCode);
    }

    public function test_uploads_directory_php_execution_blocked(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_uploads_php_exec'] = true;
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.25',
            method: 'GET',
            uri: '/wp-content/uploads/2026/11/malicious.php'
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-UPLOADS-PHP-DENY', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_installer_lockdown_blocks_install_php(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['waf_block_install_php'] = true;
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '198.51.100.30',
            method: 'GET',
            uri: '/wp-admin/install.php'
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertSame('WAF-INSTALL-LOCKDOWN', $verdict->ruleId);
        $this->assertSame(403, $verdict->statusCode);
    }

    public function test_early_boot_execution_emits_zero_notices(): void {
        $guard = new AlwaysOnCoreGuard();
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/safe-test-page'
        );

        // evaluate_runtime_request must complete without any warnings, notices, or exceptions
        $verdict = $guard->evaluate_runtime_request($ctx);
        $this->assertNull($verdict);
    }
}
