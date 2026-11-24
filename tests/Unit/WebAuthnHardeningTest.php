<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\Controllers\AuthController;
use WebCareProScanner\Auth\StrictCborDecoder;
use WebCareProScanner\Auth\WebAuthnManager;
use WebCareProScanner\System\SettingsManager;

final class WebAuthnHardeningTest extends TestCase
{
    private array $origServer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->origServer = $_SERVER;
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->origServer;
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        parent::tearDown();
    }

    public function testStrictCborDecoderRejectsInvalidUtf8(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CBOR text string contains invalid UTF-8 sequence.');
        // Major type 3 (text string) with length 2, invalid byte \xFF\xFF
        StrictCborDecoder::decode("\x62\xFF\xFF");
    }

    public function testSettingsManagerDefaultsWebAuthnRememberSessionToFalse(): void
    {
        $defaults = SettingsManager::get_defaults();
        $this->assertArrayHasKey('webauthn_remember_session', $defaults);
        $this->assertFalse($defaults['webauthn_remember_session']);
    }

    public function testWebAuthnIpRateLimitSingleIncrement(): void
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.42';

        // Options rate limit is 25 per 300s
        for ($i = 0; $i < 25; $i++) {
            $this->assertTrue(WebAuthnManager::check_ip_rate_limit('options', 25, 300));
        }

        // 26th should fail rate limit
        $this->assertFalse(WebAuthnManager::check_ip_rate_limit('options', 25, 300));
    }

    public function testLoginOptionsAndLoginVerifyPassExplicit300sTtlToSetTransient(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.55';
        $resolvedIp = class_exists(\WebCareProScanner\Firewall\FirewallEngine::class)
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : '203.0.113.55';

        // 1. login-options permission + handler
        $optionsReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/webauthn/login-options');
        $optionsReq->set_body((string) json_encode(['username' => 'admin_passkey_user']));

        $permOptions = AuthController::check_webauthn_public_rate_limit($optionsReq);
        $this->assertTrue($permOptions);

        $optionsRes = AuthController::webauthn_login_options($optionsReq);
        $this->assertIsArray($optionsRes);
        $this->assertTrue($optionsRes['success']);

        $accKey = 'webcareproscan_wa_acc_' . md5('admin_passkey_user|' . $resolvedIp);
        $optionsIpKey = 'webcareproscan_wa_rl_' . md5('options_' . $resolvedIp);

        $this->assertSame(300, $GLOBALS['wp_mock_transient_ttls'][$accKey] ?? null, 'Account+IP rate-limit on login-options must set 300s TTL.');
        $this->assertSame(300, $GLOBALS['wp_mock_transient_ttls'][$optionsIpKey] ?? null, 'IP rate-limit on login-options must set 300s TTL.');
        $this->assertSame(1, get_transient($accKey));
        $this->assertSame(1, get_transient($optionsIpKey));

        // 2. login-verify permission + handler (uses session_id login_hint or username)
        $verifyReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/webauthn/login-verify');
        $verifyReq->set_body((string) json_encode([
            'session_id' => $optionsRes['session_id'],
            'payload'    => [
                'id'       => 'dGVzdF9jcmVkX2lk',
                'response' => ['clientDataJSON' => 'e30'],
            ],
        ]));

        $permVerify = AuthController::check_webauthn_public_rate_limit($verifyReq);
        $this->assertTrue($permVerify);

        AuthController::webauthn_login_verify($verifyReq);

        $verifyIpKey = 'webcareproscan_wa_rl_' . md5('verify_' . $resolvedIp);
        $this->assertSame(300, $GLOBALS['wp_mock_transient_ttls'][$accKey] ?? null, 'Account+IP rate-limit on login-verify must set 300s TTL.');
        $this->assertSame(300, $GLOBALS['wp_mock_transient_ttls'][$verifyIpKey] ?? null, 'IP rate-limit on login-verify must set 300s TTL.');
        $this->assertSame(2, get_transient($accKey));
        $this->assertSame(1, get_transient($verifyIpKey));
    }

    public function testAccountIpRateLimitResetsAfter300SecondWindowExpires(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.88';
        $resolvedIp = class_exists(\WebCareProScanner\Firewall\FirewallEngine::class)
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : '203.0.113.88';

        $req = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/webauthn/login-options');
        $req->set_body((string) json_encode(['username' => 'mir_owner']));

        for ($i = 0; $i < 15; $i++) {
            $this->assertTrue(AuthController::check_webauthn_public_rate_limit($req));
        }

        // 16th attempt within 300s window is blocked with 429
        $blocked = AuthController::check_webauthn_public_rate_limit($req);
        $this->assertInstanceOf(\WP_Error::class, $blocked);
        $this->assertSame('rest_account_rate_limited', $blocked->get_error_code());

        // Simulate expiration of the 300-second window
        $accKey = 'webcareproscan_wa_acc_' . md5('mir_owner|' . $resolvedIp);
        $this->assertGreaterThan(time(), $GLOBALS['wp_mock_transient_expires'][$accKey]);
        $GLOBALS['wp_mock_transient_expires'][$accKey] = time() - 1;

        // Next request after window expiry succeeds cleanly and resets counter to 1 with fresh 300s TTL
        $afterExpiry = AuthController::check_webauthn_public_rate_limit($req);
        $this->assertTrue($afterExpiry, 'Account+IP counter must reset after 300s window expires.');
        $this->assertSame(1, get_transient($accKey));
        $this->assertSame(300, $GLOBALS['wp_mock_transient_ttls'][$accKey]);
    }
}
