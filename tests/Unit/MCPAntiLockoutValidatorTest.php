<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\MCPAntiLockoutValidator;

class MCPAntiLockoutValidatorTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
    }

    public function testVerifyMcpBearerRequestRejectsDisabledAndUnauthenticatedRequests(): void {
        $req = new \WP_REST_Request(['Authorization' => 'Bearer valid-token']);

        // Explicitly disabled
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'mcp_enabled' => false,
        ];
        $resDisabled = MCPAntiLockoutValidator::verify_mcp_bearer_request($req, '192.168.1.10');
        $this->assertFalse($resDisabled['allowed']);
        $this->assertSame('disabled', $resDisabled['reason']);

        // Enabled but missing Authorization header
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'mcp_enabled' => true,
            'mcp_token'   => 'secret-mcp-bearer-token-2026',
        ];
        $reqNoAuth = new \WP_REST_Request([]);
        $resNoAuth = MCPAntiLockoutValidator::verify_mcp_bearer_request($reqNoAuth, '192.168.1.10');
        $this->assertFalse($resNoAuth['allowed']);
        $this->assertSame('invalid_bearer', $resNoAuth['reason']);
    }

    public function testVerifyMcpBearerRequestValidatesTokenTtlAndCidr(): void {
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'mcp_enabled'          => true,
            'mcp_token'            => 'secret-mcp-bearer-token-2026',
            'mcp_token_ttl_days'   => 30,
            'mcp_token_created_at' => time() - 3600,
            'mcp_allowed_cidrs'    => '192.168.1.0/24, 10.0.0.1',
        ];

        $reqValid = new \WP_REST_Request(['Authorization' => 'Bearer secret-mcp-bearer-token-2026']);
        $resOk = MCPAntiLockoutValidator::verify_mcp_bearer_request($reqValid, '192.168.1.50');
        $this->assertTrue($resOk['allowed'], 'Valid bearer token and matching CIDR must pass.');

        // Wrong token
        $reqBadToken = new \WP_REST_Request(['Authorization' => 'Bearer wrong-token']);
        $resBadToken = MCPAntiLockoutValidator::verify_mcp_bearer_request($reqBadToken, '192.168.1.50');
        $this->assertFalse($resBadToken['allowed']);
        $this->assertSame('invalid_token', $resBadToken['reason']);

        // Disallowed IP outside CIDR
        $resBadIp = MCPAntiLockoutValidator::verify_mcp_bearer_request($reqValid, '8.8.8.8');
        $this->assertFalse($resBadIp['allowed']);
        $this->assertSame('cidr_denied', $resBadIp['reason']);
    }

    public function testVerifyMcpBearerRequestFailsClosedOnWhitespaceOnlyCidr(): void {
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'mcp_enabled'       => true,
            'mcp_token'         => 'secret-mcp-bearer-token-2026',
            'mcp_allowed_cidrs' => '   ',
        ];

        $req = new \WP_REST_Request(['Authorization' => 'Bearer secret-mcp-bearer-token-2026']);
        $res = MCPAntiLockoutValidator::verify_mcp_bearer_request($req, '127.0.0.1');
        $this->assertFalse($res['allowed']);
        $this->assertSame('cidr_denied', $res['reason'], 'Whitespace-only CIDR config must fail closed.');
    }

    public function testValidateMcpTokenLifetimeDetectsExpirationAndInvalidInputs(): void {
        $now = 1770000000;
        $expiredCreatedAt = $now - (400 * 86400);

        $expired = MCPAntiLockoutValidator::validate_mcp_token_lifetime(30, $expiredCreatedAt, $now);
        $this->assertFalse($expired['valid']);
        $this->assertSame('expired', $expired['reason']);

        $valid = MCPAntiLockoutValidator::validate_mcp_token_lifetime(30, $now - 3600, $now);
        $this->assertTrue($valid['valid']);

        // Non-expiring (TTL = 0)
        $nonExpiring = MCPAntiLockoutValidator::validate_mcp_token_lifetime(0, 0, $now);
        $this->assertTrue($nonExpiring['valid']);
    }

    public function testCidrMatchingAndAntiLockoutGuards(): void {
        $allowedList = ['192.168.1.0/24', '10.0.0.1'];

        $this->assertTrue(MCPAntiLockoutValidator::ip_matches_cidr_list('192.168.1.100', $allowedList));
        $this->assertTrue(MCPAntiLockoutValidator::ip_matches_cidr_list('10.0.0.1', $allowedList));
        $this->assertFalse(MCPAntiLockoutValidator::ip_matches_cidr_list('8.8.8.8', $allowedList));

        // Reject /0 wildcard CIDR and non-canonical prefixes
        $this->assertFalse(MCPAntiLockoutValidator::is_valid_cidr_list(['0.0.0.0/0']));
        $this->assertFalse(MCPAntiLockoutValidator::is_valid_cidr_list(['192.168.1.0/024']));

        // Anti-lockout guard prevents banning loopback IP
        $banLoopback = MCPAntiLockoutValidator::validate_ip_ban('127.0.0.1');
        $this->assertFalse($banLoopback['allowed']);

        // Custom rule anti-lockout blocks rules targeting MCP endpoints
        $ruleCheck = MCPAntiLockoutValidator::validate_custom_rule([
            'action_type'     => 'block',
            'wirefilter_expr' => 'http.request.uri.path contains "/wp-json/webcare-pro-security/v1/mcp"',
        ]);
        $this->assertFalse($ruleCheck['allowed']);
    }
}
