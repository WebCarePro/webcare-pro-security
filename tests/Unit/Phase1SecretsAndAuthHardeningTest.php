<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\Controllers\AuthController;
use WebCareProScanner\Api\Controllers\SystemController;
use WebCareProScanner\Auth\ApplicationPasswordSentinel;
use WebCareProScanner\Auth\SessionSentinel;
use WebCareProScanner\Auth\TwoFactorAuth;
use WebCareProScanner\Auth\WebAuthnManager;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Identity\HIBPBreachAuditor;
use WebCareProScanner\Security\SecretVault;
use WebCareProScanner\System\SettingsManager;

final class Phase1SecretsAndAuthHardeningTest extends TestCase
{
    private array $origServer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->origServer = $_SERVER;
        $GLOBALS['wp_mock_options'] = [];
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        ClientIpResolver::reset_client_ip_cache();
        SettingsManager::reset_settings_cache();
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->origServer;
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        ClientIpResolver::reset_client_ip_cache();
        SettingsManager::reset_settings_cache();
        parent::tearDown();
    }

    public function testDefaultsEnableXmlrpcDisableAndVirtualPatchesAutoEnforce(): void
    {
        $defaults = SettingsManager::get_defaults();
        $this->assertTrue($defaults['waf_disable_xmlrpc']);
        $this->assertTrue($defaults['waf_auto_enforce_virtual_patches']);
    }

    public function testUiSettingsMaskSecretsAndExportStripsThemCompletely(): void
    {
        SettingsManager::save_settings([
            'openai_api_key'               => 'sk-live-secret-9999',
            'deepseek_api_key'             => 'ds-live-secret-8888',
            'cloudflare_api_token'         => 'cf-token-secret-7777',
            'cloudflare_zone_id'           => 'zone-secret-6666',
            'waf_cloudflare_origin_secret' => 'edge%20secret+!@#555',
            'slack_webhook_url'            => 'https://hooks.slack.com/services/T00/B00/XXXX',
            'mcp_token'                    => 'webcareproscan_mcp_abcdef1234567890',
        ]);

        // Internal caller keeps decrypted plaintext (preserving % and symbols in origin secret)
        $internal = SettingsManager::get_settings();
        $this->assertSame('sk-live-secret-9999', $internal['openai_api_key']);
        $this->assertSame('edge%20secret+!@#555', $internal['waf_cloudflare_origin_secret']);
        $this->assertSame('webcareproscan_mcp_abcdef1234567890', $internal['mcp_token']);

        // Raw DB storage must encrypt waf_cloudflare_origin_secret
        $rawSaved = get_option(SettingsManager::OPTION_KEY, []);
        $this->assertNotSame('edge%20secret+!@#555', $rawSaved['waf_cloudflare_origin_secret']);
        $this->assertTrue(SecretVault::is_encrypted($rawSaved['waf_cloudflare_origin_secret']));

        // UI helper masks all secrets and exposes accurate presence flags
        $ui = SettingsManager::get_settings_for_ui();
        $this->assertSame('••••••••', $ui['openai_api_key']);
        $this->assertSame('••••••••', $ui['deepseek_api_key']);
        $this->assertSame('••••••••', $ui['cloudflare_api_token']);
        $this->assertSame('••••••••', $ui['cloudflare_zone_id']);
        $this->assertSame('••••••••', $ui['waf_cloudflare_origin_secret']);
        $this->assertSame('••••••••', $ui['slack_webhook_url']);
        $this->assertSame('wcp_mcp_••••••••', $ui['mcp_token']);
        $this->assertTrue($ui['has_openai_key']);
        $this->assertTrue($ui['has_cloudflare_origin_secret']);
        $this->assertTrue($ui['has_mcp_token']);

        // REST SystemController::get_settings must never emit raw credentials
        $resp = SystemController::get_settings(new \WP_REST_Request('GET', '/webcare-pro-security/v1/settings'));
        $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : $resp;
        $this->assertSame('••••••••', $data['settings']['openai_api_key']);
        $this->assertSame('wcp_mcp_••••••••', $data['settings']['mcp_token']);
        $this->assertSame('••••••••', $data['settings']['waf_cloudflare_origin_secret']);

        // Settings export strips all secrets completely
        $exported = SettingsManager::export_settings();
        $this->assertArrayHasKey('settings', $exported);
        foreach (SettingsManager::SECRET_KEYS as $secretKey) {
            $this->assertArrayNotHasKey($secretKey, $exported['settings'], "Exported settings leaked secret key {$secretKey}.");
        }
    }

    public function testForcePasswordResetDoesNotReturnResetUrl(): void
    {
        $target = new \WP_User(42, 'victim_admin');
        $target->user_email = 'victim@example.com';
        $target->display_name = 'Victim Admin';
        $GLOBALS['wp_mock_users'][42] = $target;

        $res = HIBPBreachAuditor::force_password_reset(42);
        $this->assertTrue($res['success']);
        $this->assertArrayNotHasKey('reset_url', $res);
        $this->assertCount(1, $GLOBALS['wp_mock_mails']);
        $this->assertStringContainsString('action=rp&key=', $GLOBALS['wp_mock_mails'][0]['message']);
    }

    public function testAuthControllerRejectsUnauthorizedOrCrossBlogUserActions(): void
    {
        $actor = new \WP_User(10, 'site_admin_a');
        $actor->roles = ['administrator'];
        $GLOBALS['wp_mock_current_user'] = $actor;
        $GLOBALS['wp_mock_users'][10] = $actor;

        $target = new \WP_User(99, 'other_blog_admin');
        $target->roles = ['administrator'];
        $GLOBALS['wp_mock_users'][99] = $target;

        // Case 1: Caller lacks edit_user capability
        $GLOBALS['wp_mock_current_user_can_callback'] = static fn(string $cap, ...$args): bool => $cap === 'manage_options';
        $req = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/2fa/admin-disable');
        $req->set_body((string) wp_json_encode(['user_id' => 99]));
        $err = AuthController::admin_disable_user_2fa($req);
        $this->assertInstanceOf(\WP_Error::class, $err);
        $this->assertSame('forbidden_user_action', $err->get_error_code());

        // Case 2: Multisite cross-blog target rejected when not Super Admin or member
        $GLOBALS['wp_mock_is_multisite'] = true;
        $GLOBALS['wp_mock_current_blog_id'] = 2;
        $GLOBALS['wp_mock_blog_memberships'] = [2 => [10 => true]]; // user 99 not a member of blog 2
        $GLOBALS['wp_mock_current_user_can_callback'] = static fn(string $cap): bool => in_array($cap, ['manage_options', 'edit_user'], true);

        $resetReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/identity/force-reset');
        $resetReq->set_body((string) wp_json_encode(['user_id' => 99]));
        $msErr = AuthController::force_identity_password_reset($resetReq);
        $this->assertInstanceOf(\WP_Error::class, $msErr);
        $this->assertSame('multisite_user_out_of_scope', $msErr->get_error_code());
    }

    public function testTwoFactorRestOnboardingBlocksNonSetupRoutesAndCapsPendingKeys(): void
    {
        $admin = new \WP_User(7, 'forced_admin');
        $admin->roles = ['administrator'];
        $admin->allcaps = ['administrator' => true, 'manage_options' => true];
        $GLOBALS['wp_mock_current_user'] = $admin;
        $GLOBALS['wp_mock_users'][7] = $admin;
        update_user_meta(7, 'webcareproscan_force_2fa_setup', 1);

        // Must block arbitrary core/plugin REST calls until 2FA enrolled
        $usersReq = new \WP_REST_Request('POST', '/wp/v2/users');
        $blocked = TwoFactorAuth::enforce_rest_2fa_onboarding(null, null, $usersReq);
        $this->assertInstanceOf(\WP_Error::class, $blocked);
        $this->assertSame('webcare_2fa_onboarding_required', $blocked->get_error_code());

        // Must allow 2FA onboarding REST route
        $setupReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/auth/2fa/verify');
        $allowed = TwoFactorAuth::enforce_rest_2fa_onboarding(null, null, $setupReq);
        $this->assertNull($allowed);

        // Pending 2FA challenge key creation is bounded at 5 active challenges per (user_id, IP)
        $_SERVER['REMOTE_ADDR'] = '198.51.100.77';
        $enrolled = new \WP_User(8, 'totp_admin');
        $enrolled->roles = ['administrator'];
        $GLOBALS['wp_mock_users'][8] = $enrolled;
        update_user_meta(8, TwoFactorAuth::META_ENABLED, 1);

        $cntKey = 'webcareproscan_2fa_pending_cnt_' . hash('sha256', '8|198.51.100.77');
        set_transient($cntKey, 5, 300);

        $limited = TwoFactorAuth::filter_authenticate($enrolled, 'totp_admin', 'valid-pass');
        $this->assertInstanceOf(\WP_Error::class, $limited);
        $this->assertSame('webcareproscan_2fa_rate_limited', $limited->get_error_code());
    }

    public function testWebAuthnRejectsUnverifiedClientPublicKeyAndSupportsCoseRsa(): void
    {
        $regTransientKey = WebAuthnManager::TRANSIENT_REG_PREFIX . 15;
        $challengeB64 = WebAuthnManager::base64url_encode(str_repeat("\x41", 32));
        set_transient($regTransientKey, ['challenge' => $challengeB64, 'created_at' => time()], 300);

        $clientData = WebAuthnManager::base64url_encode((string) wp_json_encode([
            'type'      => 'webauthn.create',
            'challenge' => $challengeB64,
            'origin'    => 'http://example.com',
        ]));

        $rpHash = hash('sha256', 'example.com', true);
        $credIdRaw = random_bytes(16);
        $credIdB64 = WebAuthnManager::base64url_encode($credIdRaw);
        // Attested credential authData with NO COSE EC2/RSA public key map (invalid CBOR tail \x00)
        $authData = $rpHash . chr(0x45) . "\x00\x00\x00\x01" . str_repeat("\x00", 16) . pack('n', 16) . $credIdRaw . "\x00";

        // Build minimal CBOR map {"fmt":"none","authData":bstr}
        $attBin = "\xa2"
            . "\x63fmt" . "\x64none"
            . "\x68authData" . "\x58" . chr(strlen($authData)) . $authData;

        // Attacker tries injecting an arbitrary EC key via response.publicKey (valid P-256 uncompressed point DER)
        $ecSpki = hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004') . str_repeat("\x11", 32) . str_repeat("\x22", 32);
        $forgedPubB64 = WebAuthnManager::base64url_encode($ecSpki);

        $res = WebAuthnManager::verify_registration(15, [
            'id'       => $credIdB64,
            'response' => [
                'clientDataJSON'    => $clientData,
                'attestationObject' => WebAuthnManager::base64url_encode($attBin),
                'publicKey'         => $forgedPubB64,
            ],
        ]);
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('Could not extract a valid cryptographic public key', $res['message']);

        // Also verify COSE RSA helper produces valid OpenSSL-parseable SubjectPublicKeyInfo PEM
        $rsaModulus = "\x9a" . random_bytes(255);
        $rsaExp     = "\x01\x00\x01";
        $rm = new \ReflectionMethod(WebAuthnManager::class, 'cose_rsa_to_pem');
        $rm->setAccessible(true);
        $pem = $rm->invoke(null, $rsaModulus, $rsaExp);
        $this->assertIsString($pem);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $pem);
        $this->assertNotFalse(openssl_pkey_get_public($pem));
    }

    public function testApplicationPasswordHostTrustRejectsDangerousSchemes(): void
    {
        $this->assertFalse(ApplicationPasswordSentinel::is_host_trusted('', 'javascript'));
        $this->assertFalse(ApplicationPasswordSentinel::is_host_trusted('', 'data'));
        $this->assertFalse(ApplicationPasswordSentinel::is_host_trusted('', 'vbscript'));
        $this->assertFalse(ApplicationPasswordSentinel::is_host_trusted('', 'http'));
        $this->assertFalse(ApplicationPasswordSentinel::is_host_trusted('example.com', 'http'));
        $this->assertTrue(ApplicationPasswordSentinel::is_host_trusted('example.com', 'https'));
        $this->assertTrue(ApplicationPasswordSentinel::is_host_trusted('localhost', 'http'));
        $this->assertTrue(ApplicationPasswordSentinel::is_host_trusted('', 'myapp-cli'));
    }

    public function testSessionAndProxyTrustRejectSpoofedCloudflareHeadersAndUaBypass(): void
    {
        // Spoofed CF headers from untrusted client IP must NOT be trusted
        $_SERVER['REMOTE_ADDR'] = '198.51.100.99';
        $_SERVER['HTTP_CF_RAY'] = 'fake-ray-123';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'US';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '1.1.1.1';
        $this->assertFalse(ClientIpResolver::is_trusted_cloudflare_request());

        // Official Cloudflare edge IP must be trusted
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1';
        $this->assertTrue(ClientIpResolver::is_trusted_cloudflare_request());

        // Matching User-Agent + CF headers must NEVER grant IPv4 /16 or dual-stack session hijack bypass
        $meta = ['user_agent' => 'Mozilla/5.0 SameAgent'];
        $this->assertFalse(SessionSentinel::is_ip_match_or_subnet('198.51.10.5', '198.51.20.9', $meta, 'Mozilla/5.0 SameAgent'));
        $this->assertFalse(SessionSentinel::is_ip_match_or_subnet('198.51.10.5', '2001:4860:4860::8888', $meta, 'Mozilla/5.0 SameAgent'));
        $this->assertTrue(SessionSentinel::is_ip_match_or_subnet('198.51.10.5', '198.51.10.99', $meta, 'Mozilla/5.0 SameAgent'));
    }
}
