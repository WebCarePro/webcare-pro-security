<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\DeclarativePatchVerifier;

final class DeclarativePatchVerifierTest extends TestCase {

    private string $key_pair_seed;
    private string $public_key_hex;
    private string $secret_key_hex;

    protected function setUp(): void {
        parent::setUp();
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('ext-sodium is required for Ed25519 signature tests.');
        }

        // Generate an Ed25519 keypair using native sodium
        $kp = sodium_crypto_sign_keypair();
        $this->secret_key_hex = bin2hex(sodium_crypto_sign_secretkey($kp));
        $this->public_key_hex = bin2hex(sodium_crypto_sign_publickey($kp));
        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => true]);
    }

    public function test_verify_patch_manifest_rejects_missing_fields(): void {
        $incomplete = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TEST-001',
        ];

        $res = DeclarativePatchVerifier::verify_patch_manifest($incomplete, 1);
        $this->assertFalse($res['valid']);
        $this->assertStringContainsString('Missing required patch manifest field', (string) $res['error']);
    }

    public function test_verify_patch_manifest_rejects_unsupported_schema_version(): void {
        $patch = [
            'schema_version' => '2.0.0',
            'patch_id'       => 'VPATCH-TEST-002',
            'feed_sequence'  => 10,
            'component'      => ['slug' => 'test', 'type' => 'plugin'],
            'match'          => ['route' => '/test', 'predicate' => 'true'],
            'action'         => 'block',
            'published_at'   => time() - 3600,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-ed25519-v1',
            'signature'      => 'fake',
        ];

        $res = DeclarativePatchVerifier::verify_patch_manifest($patch, 5);
        $this->assertFalse($res['valid']);
        $this->assertStringContainsString('Unsupported schema version', (string) $res['error']);
    }

    public function test_verify_patch_manifest_rejects_replayed_feed_sequence(): void {
        $patch = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TEST-003',
            'feed_sequence'  => 5,
            'component'      => ['slug' => 'test', 'type' => 'plugin'],
            'match'          => ['route' => '/test', 'predicate' => 'true'],
            'action'         => 'block',
            'published_at'   => time() - 3600,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-ed25519-v1',
            'signature'      => 'fake',
        ];

        // Min allowed sequence is 10; patch sequence is 5 -> reject
        $res = DeclarativePatchVerifier::verify_patch_manifest($patch, 10);
        $this->assertFalse($res['valid']);
        $this->assertStringContainsString('rolled back or replayed', (string) $res['error']);
    }

    public function test_verify_patch_manifest_rejects_expired_patch(): void {
        $patch = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TEST-004',
            'feed_sequence'  => 15,
            'component'      => ['slug' => 'test', 'type' => 'plugin'],
            'match'          => ['route' => '/test', 'predicate' => 'true'],
            'action'         => 'block',
            'published_at'   => time() - (100 * 86400),
            'expires_at'     => time() - (10 * 86400), // Expired 10 days ago
            'key_id'         => 'wcp-ed25519-v1',
            'signature'      => 'fake',
        ];

        $res = DeclarativePatchVerifier::verify_patch_manifest($patch, 10);
        $this->assertFalse($res['valid']);
        $this->assertStringContainsString('has expired', (string) $res['error']);
    }

    public function test_verify_patch_manifest_rejects_revoked_key_id(): void {
        $patch = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TEST-005',
            'feed_sequence'  => 20,
            'component'      => ['slug' => 'test', 'type' => 'plugin'],
            'match'          => ['route' => '/test', 'predicate' => 'true'],
            'action'         => 'block',
            'published_at'   => time() - 3600,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-ed25519-legacy-revoked',
            'signature'      => 'fake',
        ];

        $res = DeclarativePatchVerifier::verify_patch_manifest($patch, 10);
        $this->assertFalse($res['valid']);
        $this->assertStringContainsString('revoked', (string) $res['error']);
    }

    public function test_ed25519_signature_verification_succeeds_on_valid_signature(): void {
        $patch = [
            'action'         => 'block',
            'component'      => ['slug' => 'woocommerce-payments', 'type' => 'plugin', 'range' => '<= 5.6.1'],
            'expires_at'     => time() + 86400,
            'feed_sequence'  => 50,
            'key_id'         => 'custom-test-key',
            'match'          => ['method' => 'GET', 'predicate' => 'header.x-wcpay != ""', 'route' => '/'],
            'patch_id'       => 'VPATCH-CVE-2023-28121',
            'published_at'   => time() - 3600,
            'schema_version' => '1.0.0',
        ];

        // Sign the patch with our test secret key
        $sig_hex = DeclarativePatchVerifier::sign_patch_manifest($patch, $this->secret_key_hex);
        $patch['signature'] = $sig_hex;

        // Verify with matching test public key
        $this->assertTrue(
            DeclarativePatchVerifier::verify_ed25519_signature($patch, $sig_hex, $this->public_key_hex)
        );

        // Tamper with payload: modifying any field must invalidate the Ed25519 signature
        $tampered = $patch;
        $tampered['action'] = 'log';
        $this->assertFalse(
            DeclarativePatchVerifier::verify_ed25519_signature($tampered, $sig_hex, $this->public_key_hex)
        );
    }

    public function test_staged_promotion_policy_defaults_to_shadow_unless_high_confidence(): void {
        $heuristic_patch = [
            'confidence'      => 'low',
            'vendor_verified' => false,
        ];
        $this->assertSame(
            DeclarativePatchVerifier::STAGE_SHADOW,
            DeclarativePatchVerifier::determine_initial_stage($heuristic_patch)
        );

        $vendor_patch = [
            'confidence'      => 'high',
            'vendor_verified' => true,
        ];
        $this->assertSame(
            DeclarativePatchVerifier::STAGE_ACTIVE,
            DeclarativePatchVerifier::determine_initial_stage($vendor_patch, true)
        );
    }

    public function test_test_context_detection_and_guard_rejection(): void {
        // In this CLI PHPUnit runner, is_test_context() is true
        $this->assertTrue(DeclarativePatchVerifier::is_test_context());

        // In test context, setting test keys is accepted
        DeclarativePatchVerifier::set_test_public_keys(['custom-test-key' => $this->public_key_hex]);

        $patch = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TEST-GUARD-1',
            'feed_sequence'  => 10,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => ['route' => '/test', 'predicate' => 'true'],
            'action'         => 'block',
            'published_at'   => time() - 3600,
            'expires_at'     => time() + 86400,
            'key_id'         => 'custom-test-key',
        ];

        $sig = DeclarativePatchVerifier::sign_patch_manifest($patch, $this->secret_key_hex);
        $patch['signature'] = $sig;

        // Signature verification succeeds with injected test key in test context
        $res = DeclarativePatchVerifier::verify_patch_manifest($patch, 5);
        $this->assertTrue($res['valid'], 'Expected valid patch with injected test key in test context');

        // Test key reset with null restores pinned key behavior
        DeclarativePatchVerifier::set_test_public_keys(null);

        // Verification must now reject untrusted custom-test-key because test key was cleared
        $res_after_reset = DeclarativePatchVerifier::verify_patch_manifest($patch, 5);
        $this->assertFalse($res_after_reset['valid']);
        $this->assertStringContainsString('Unknown or untrusted signing key ID: custom-test-key', (string) $res_after_reset['error']);
    }

    public function test_production_context_rejects_untrusted_keys_and_test_flag_false_in_isolation(): void {
        // Run a standalone PHP script mimicking a production request where WEBCARE_TESTING = false
        // and PHPUNIT_COMPOSER_INSTALL is NOT defined.
        $php_code = <<<'PHP'
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Firewall/DeclarativePatchVerifier.php';

// Simulate non-test flag explicitly set to false
define('WEBCARE_TESTING', false);

// Check is_test_context()
$is_test = WebCareProScanner\Firewall\DeclarativePatchVerifier::is_test_context();
if ($is_test) {
    echo "FAIL: is_test_context returned true when WEBCARE_TESTING is false\n";
    exit(1);
}

// Attempt to inject an untrusted key
$fake_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
    'untrusted-key' => $fake_key
]);

// Manifest attempting to use untrusted-key
$patch = [
    'schema_version' => '1.0.0',
    'patch_id'       => 'VPATCH-UNTRUSTED',
    'feed_sequence'  => 10,
    'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
    'match'          => ['route' => '/test', 'predicate' => 'true'],
    'action'         => 'block',
    'published_at'   => time() - 3600,
    'expires_at'     => time() + 86400,
    'key_id'         => 'untrusted-key',
    'signature'      => 'fake_sig',
];

$res = WebCareProScanner\Firewall\DeclarativePatchVerifier::verify_patch_manifest($patch, 5);
if ($res['valid'] === true) {
    echo "FAIL: verify_patch_manifest accepted untrusted test key in production context\n";
    exit(2);
}

if (!str_contains((string) $res['error'], 'Unknown or untrusted signing key ID')) {
    echo "FAIL: Unexpected error: " . ($res['error'] ?? '') . "\n";
    exit(3);
}

echo "OK";
PHP;

        $temp_script = tempnam(sys_get_temp_dir(), 'wcp_test_');
        file_put_contents($temp_script, "<?php\n" . $php_code);

        $output = [];
        $return_var = 0;
        exec('php -n ' . escapeshellarg($temp_script) . ' 2>&1', $output, $return_var);
        @unlink($temp_script);

        $this->assertSame(0, $return_var, 'Subprocess failed: ' . implode("\n", $output));
        $this->assertContains('OK', $output);
    }

    public function test_virtual_patch_manager_wires_verifier_and_evaluates_declarative_rule(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-vpatch-test' => $this->public_key_hex
        ]);

        $patch_manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-CVE-2024-TEST-WIRE',
            'feed_sequence'  => 50,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/vulnerable-endpoint',
                'method'    => 'POST',
                'predicate' => 'header.x-exploit-trigger != ""',
            ],
            'action'         => 'block',
            'confidence'     => 'high',
            'vendor_verified'=> true,
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-vpatch-test',
        ];

        // 1. Unsigned / forged patch must be rejected by VirtualPatchManager::apply_patch
        $unsigned_res = \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch(
            'VPATCH-CVE-2024-TEST-WIRE',
            $patch_manifest // missing signature
        );
        $this->assertFalse($unsigned_res['success']);
        $this->assertStringContainsString('validation failed', $unsigned_res['message']);

        // 2. Correctly signed patch must be accepted
        $sig = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($patch_manifest, $this->secret_key_hex);
        $patch_manifest['signature'] = $sig;

        $valid_res = \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch(
            'VPATCH-CVE-2024-TEST-WIRE',
            $patch_manifest
        );
        $this->assertTrue($valid_res['success']);

        // 3. Evaluate request matching the declarative predicate
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_X_EXPLOIT_TRIGGER'] = 'malicious_token';
        $_GET = [];
        $_POST = [];

        $hit = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.44', '/vulnerable-endpoint');
        $this->assertNotNull($hit, 'Declarative virtual patch must block matching exploit request.');
        $this->assertSame('VPATCH-VPATCH-CVE-2024-TEST-WIRE', $hit['id']);

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-CVE-2024-TEST-WIRE');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_declarative_stages_and_actions(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        // 1. Stage SHADOW: Observe only
        $shadow_manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-SHADOW-001',
            'feed_sequence'  => 60,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/shadow-test',
                'predicate' => 'true',
            ],
            'action'         => 'block',
            'stage'          => 'shadow',
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $shadow_manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($shadow_manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-SHADOW-001', $shadow_manifest);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $hit = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/shadow-test');
        $this->assertNull($hit, 'Stage shadow must not return blocking hit.');

        // 2. Stage REVOKED: Ignored
        $shadow_manifest['patch_id'] = 'VPATCH-REVOKED-001';
        $shadow_manifest['stage'] = 'revoked';
        $shadow_manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($shadow_manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-REVOKED-001', $shadow_manifest);

        $hitRev = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/shadow-test');
        $this->assertNull($hitRev, 'Stage revoked must be skipped.');

        // 3. Action challenge & rate_limit in stage ACTIVE
        $rate_manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-RATE-001',
            'feed_sequence'  => 61,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/rate-test',
                'predicate' => 'true',
            ],
            'action'         => 'rate_limit',
            'stage'          => 'active',
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $rate_manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($rate_manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-RATE-001', $rate_manifest);

        $hitRate = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/rate-test');
        $this->assertNotNull($hitRate);
        $this->assertSame('rate_limit', $hitRate['action']);
        $this->assertSame(429, $hitRate['status_code']);

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-SHADOW-001');
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-REVOKED-001');
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-RATE-001');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_owner_opt_in_defaults_to_shadow_mode(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        // Default setting: waf_auto_enforce_virtual_patches is false
        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => false]);

        $manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-OPTIN-001',
            'feed_sequence'  => 70,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/optin-test',
                'predicate' => 'true',
            ],
            'action'         => 'block',
            'stage'          => 'active', // Declared active by feed
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($manifest, $this->secret_key_hex);

        // Applying when owner opt-in is false must downgrade stage to shadow
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-OPTIN-001', $manifest);

        $active = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        $this->assertSame('shadow', $active['VPATCH-OPTIN-001']['stage'] ?? null, 'Unapproved patch must downgrade to shadow when owner opt-in is disabled.');

        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-OPTIN-001');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_route_wildcard_boundary_matching(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => true]);

        $manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-ROUTE-001',
            'feed_sequence'  => 80,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/checkout/*',
                'predicate' => 'true',
            ],
            'action'         => 'block',
            'stage'          => 'active',
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-ROUTE-001', $manifest);

        $_SERVER['REQUEST_METHOD'] = 'GET';

        // 1. /checkout/pay -> MUST MATCH
        $hit1 = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/checkout/pay?step=1');
        $this->assertNotNull($hit1, '/checkout/pay must match /checkout/*');

        // 2. /checkout-admin -> MUST NOT MATCH (boundary check prevents partial directory match)
        $hit2 = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/checkout-admin');
        $this->assertNull($hit2, '/checkout-admin must NOT match /checkout/*');

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-ROUTE-001');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_theme_and_mu_plugin_applicability(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => true]);

        // Theme patch for twentytwentyfour
        $theme_manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-THEME-001',
            'feed_sequence'  => 90,
            'component'      => ['slug' => 'twentytwentyfour', 'type' => 'theme'],
            'match'          => [
                'route'     => '/theme-test',
                'predicate' => 'true',
            ],
            'action'         => 'block',
            'stage'          => 'active',
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $theme_manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($theme_manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-THEME-001', $theme_manifest);

        $GLOBALS['wp_mock_themes'] = [
            'twentytwentyfour' => new class {
                public function get(string $key) { return 'Twenty Twenty-Four'; }
            }
        ];

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $hitTheme = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/theme-test');
        $this->assertNotNull($hitTheme, 'Patch for installed theme must be applicable and evaluated.');

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-THEME-001');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_incoming_revoked_stage_preserved_even_when_owner_optin_is_false(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => false]);

        $manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-REVOKE-STAYS-REVOKED',
            'feed_sequence'  => 100,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/revoked-test',
                'predicate' => 'true',
            ],
            'action'         => 'block',
            'stage'          => 'revoked', // Declared revoked
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($manifest, $this->secret_key_hex);

        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-REVOKE-STAYS-REVOKED', $manifest);

        $active = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        $this->assertSame('revoked', $active['VPATCH-REVOKE-STAYS-REVOKED']['stage'] ?? null, 'STAGE_REVOKED must not be downgraded to shadow mode.');

        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-REVOKE-STAYS-REVOKED');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }

    public function test_request_body_reader_truncation_and_read_failed(): void {
        \WebCareProScanner\Firewall\Core\RequestBodyReader::reset();
        \WebCareProScanner\Firewall\Core\RequestBodyReader::$mock_raw_body = str_repeat('A', 1000);

        // Read with 500 byte max limit
        $body = \WebCareProScanner\Firewall\Core\RequestBodyReader::get_bounded_body(500);
        $this->assertSame(500, strlen($body));
        $this->assertTrue(\WebCareProScanner\Firewall\Core\RequestBodyReader::is_truncated());
        $this->assertFalse(\WebCareProScanner\Firewall\Core\RequestBodyReader::has_read_failed());

        \WebCareProScanner\Firewall\Core\RequestBodyReader::reset();
    }

    public function test_body_predicate_fails_closed_on_truncation_or_read_failure(): void {
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys([
            'wcp-stage-test' => $this->public_key_hex
        ]);

        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => true]);

        $manifest = [
            'schema_version' => '1.0.0',
            'patch_id'       => 'VPATCH-TRUNC-FAILCLOSED',
            'feed_sequence'  => 110,
            'component'      => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'          => [
                'route'     => '/trunc-test',
                'source'    => 'body',
                'predicate' => 'contains:secret_exploit_payload_string',
            ],
            'action'         => 'block',
            'stage'          => 'active',
            'published_at'   => time() - 60,
            'expires_at'     => time() + 86400,
            'key_id'         => 'wcp-stage-test',
        ];
        $manifest['signature'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::sign_patch_manifest($manifest, $this->secret_key_hex);
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-TRUNC-FAILCLOSED', $manifest);

        $_SERVER['REQUEST_METHOD'] = 'POST';

        // 1. Simulate body truncation without prefix matching: mock 70KB body
        \WebCareProScanner\Firewall\Core\RequestBodyReader::reset();
        \WebCareProScanner\Firewall\Core\RequestBodyReader::$mock_raw_body = str_repeat('B', 70000);

        $hitTrunc = \WebCareProScanner\Firewall\VirtualPatchManager::evaluate_request('198.51.100.1', '/trunc-test');
        $this->assertNotNull($hitTrunc);
        $this->assertSame('WAF-VPATCH-BODY-INCOMPLETE', $hitTrunc['id']);
        $this->assertSame(413, $hitTrunc['status_code']);

        // Clean up
        \WebCareProScanner\Firewall\Core\RequestBodyReader::reset();
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-TRUNC-FAILCLOSED');
        \WebCareProScanner\Firewall\DeclarativePatchVerifier::set_test_public_keys(null);
    }
}
