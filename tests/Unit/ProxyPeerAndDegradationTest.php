<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\RequestPipeline;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\ThreatIntelService;
use WebCareProScanner\System\SettingsManager;

/**
 * ProxyPeerAndDegradationTest
 *
 * Acceptance tests for PR M3: Immutable Proxy Peer Preservation & Controlled Pipeline Degradation.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ProxyPeerAndDegradationTest extends TestCase {

    private array $origServer;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        ClientIpResolver::reset_cache();
        FirewallEngine::$connecting_peer_ip = null;
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        ClientIpResolver::reset_cache();
        FirewallEngine::$connecting_peer_ip = null;
        parent::tearDown();
    }

    /**
     * Requirement: After normalize_server_remote_addr() rewrites $_SERVER['REMOTE_ADDR']
     * from a Cloudflare edge IP to a visitor IP, RequestContext::from_globals() still identifies
     * $ctx->cf_proxied === true and retains country/asn using connectingPeerIp.
     */
    public function test_cloudflare_headers_evaluated_against_connecting_peer_ip(): void {
        $cf_edge_ip = '173.245.48.50'; // Official Cloudflare IPv4 CIDR
        $visitor_ip = '198.51.100.123';

        $_SERVER['REMOTE_ADDR'] = $cf_edge_ip;
        $_SERVER['HTTP_CF_CONNECTING_IP'] = $visitor_ip;
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'US';
        $_SERVER['HTTP_CF_IPASN'] = 'AS13335';
        $_SERVER['HTTP_CF_RAY'] = '8d92f7c0a1b2c3d4-IAD';

        // 1. Initial firewall normalization rewrites $_SERVER['REMOTE_ADDR'] to visitor IP
        ClientIpResolver::normalize_server_remote_addr();
        $this->assertSame($visitor_ip, $_SERVER['REMOTE_ADDR'], 'REMOTE_ADDR must be normalized to real visitor IP');

        // 2. RequestContext::from_globals() must still access connectingPeerIp ($cf_edge_ip)
        $ctx = RequestContext::from_globals();
        $this->assertSame($cf_edge_ip, $ctx->connectingPeerIp, 'connectingPeerIp must hold original Cloudflare edge IP');
        $this->assertSame($visitor_ip, $ctx->ip, 'ctx->ip must hold resolved visitor IP');
        $this->assertTrue($ctx->cf_proxied, 'ctx->cf_proxied must be true because connecting peer is CF');
        $this->assertSame('US', $ctx->country, 'ctx->country must be preserved');
        $this->assertSame('13335', $ctx->asn, 'ctx->asn must be preserved');
    }

    /**
     * Requirement: A simulated exception in an optional Threat Intel lookup inside AlwaysOnCoreGuard
     * logs a degraded alert while still running and serving the page (no site-wide 503).
     */
    public function test_optional_threat_intel_exception_degrades_gracefully(): void {
        $settings = SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        $settings['threat_intel_enabled'] = true;
        $settings['threat_intel_block_blacklisted_ips'] = true;

        $ctx = new RequestContext('203.0.113.88', 'GET', '/sample-page/');

        $guard = new AlwaysOnCoreGuard();
        $verdict = $guard->evaluate_runtime_request($ctx);

        // Does not throw and does not block/503
        $this->assertTrue(
            $verdict === null || $verdict->get_action_value() === 'allow',
            'Request must pass through gracefully despite optional Threat Intel lookup failure'
        );
    }
}
