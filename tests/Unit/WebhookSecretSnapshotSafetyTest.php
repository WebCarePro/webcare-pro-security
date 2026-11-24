<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\Core\AllowlistManager;
use WebCareProScanner\Firewall\Core\RequestBodyReader;
use WebCareProScanner\System\SettingsManager;

/**
 * WebhookSecretSnapshotSafetyTest
 *
 * Verifies that:
 * 1. Targeted allowlist rules with webhook secrets move secrets to SecretVault
 * 2. Raw secrets never persist inside waf_targeted_allowlist_rules or snapshots
 * 3. Recursive secret scrubbing strips nested credentials in JSON strings
 * 4. Bounded body HMAC verification with replay window enforcement functions properly
 */
final class WebhookSecretSnapshotSafetyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        delete_option('webcareproscan_vault_webhook_secrets');
        RequestBodyReader::reset();
        unset($_SERVER['HTTP_STRIPE_SIGNATURE']);
    }

    protected function tearDown(): void
    {
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        delete_option('webcareproscan_vault_webhook_secrets');
        RequestBodyReader::reset();
        unset($_SERVER['HTTP_STRIPE_SIGNATURE']);
        parent::tearDown();
    }

    public function testTargetedRuleMovesSecretToVaultAndStripsPlaintext(): void
    {
        $rawRules = [
            [
                'id'                        => 'rule_stripe_1',
                'name'                      => 'Stripe Ingestion',
                'endpoints'                 => ['/wp-json/stripe/v1/webhook'],
                'webhook_hmac_provider'     => 'stripe',
                'webhook_secret'            => 'whsec_test_secret_abc123',
                'webhook_replay_window_sec' => 300,
            ]
        ];

        $cleaned = SettingsManager::sanitize_targeted_allowlist_rules($rawRules);
        $this->assertNotEmpty($cleaned);

        $rule = $cleaned[0];
        $this->assertSame('wcp_wh_sec_rule_stripe_1', $rule['webhook_secret_ref']);
        $this->assertSame('signed_timestamp_and_nonce', $rule['replay_protection']);
        $this->assertArrayNotHasKey('webhook_secret', $rule, 'Plaintext webhook_secret must not exist in sanitized rule.');

        // Verify stored encrypted in dedicated vault option and decrypts cleanly
        $storedSecret = AllowlistManager::get_webhook_secret_by_ref('wcp_wh_sec_rule_stripe_1');
        $this->assertSame('whsec_test_secret_abc123', $storedSecret, 'SecretVault must store and decrypt secret.');
    }

    public function testSnapshotRecursivelyScrubsNestedSecretsInJson(): void
    {
        $settings = [
            'waf_mode' => 'learning',
            'openai_api_key' => 'sk-test-secret',
            'waf_enforce_strong_passwords' => true,
            'waf_targeted_allowlist_rules' => wp_json_encode([
                [
                    'id' => 'rule_1',
                    'webhook_secret' => 'leak_secret_value',
                    'nested_data' => [
                        'api_token' => 'nested_token_value',
                        'safe_ref' => 'ref_123',
                    ]
                ]
            ]),
        ];

        $stripped = SettingsManager::strip_secrets($settings);

        $this->assertArrayNotHasKey('openai_api_key', $stripped);
        $this->assertTrue($stripped['waf_enforce_strong_passwords']);
        $decodedTargeted = json_decode($stripped['waf_targeted_allowlist_rules'], true);

        $this->assertArrayNotHasKey('webhook_secret', $decodedTargeted[0]);
        $this->assertArrayNotHasKey('api_token', $decodedTargeted[0]['nested_data']);
        $this->assertSame('ref_123', $decodedTargeted[0]['nested_data']['safe_ref']);
    }

    public function testBoundedBodyHmacVerificationThroughAllowlistManager(): void
    {
        $secret = 'whsec_replay_test';
        $this->assertTrue(AllowlistManager::store_webhook_secret('wcp_wh_sec_test', $secret));

        $rules = [[
            'id'                        => 'rule_stripe_wh',
            'enabled'                   => true,
            'endpoints'                 => ['/stripe-wh'],
            'methods'                   => ['POST'],
            'webhook_hmac_provider'     => 'stripe',
            'webhook_secret_ref'        => 'wcp_wh_sec_test',
            'webhook_replay_window_sec' => 300,
        ]];

        $body = '{"event":"charge.captured","nonce":"' . bin2hex(random_bytes(6)) . '"}';
        RequestBodyReader::$mock_raw_body = $body;

        $now = time();
        $sig = hash_hmac('sha256', "{$now}.{$body}", $secret);
        $_SERVER['HTTP_STRIPE_SIGNATURE'] = "t={$now},v1={$sig}";

        $matched = AllowlistManager::match_targeted_allowlist_rule('/stripe-wh', 'Stripe/1.0', '198.51.100.20', 'POST', $rules);
        $this->assertIsArray($matched, 'Valid Stripe HMAC through match_targeted_allowlist_rule must match.');
        $this->assertSame('signed_timestamp_and_nonce', $matched['replay_protection']);

        // Truncated body (> max_bytes) must fail closed even with a valid signature over bounded prefix
        RequestBodyReader::reset();
        $oversized = str_repeat('A', RequestBodyReader::DEFAULT_MAX_BYTES + 128);
        RequestBodyReader::$mock_raw_body = $oversized;
        $truncSig = hash_hmac('sha256', "{$now}." . substr($oversized, 0, RequestBodyReader::DEFAULT_MAX_BYTES), $secret);
        $_SERVER['HTTP_STRIPE_SIGNATURE'] = "t={$now},v1={$truncSig}";

        $this->assertNull(
            AllowlistManager::match_targeted_allowlist_rule('/stripe-wh', 'Stripe/1.0', '198.51.100.20', 'POST', $rules),
            'Truncated request body must fail closed on HMAC verification.'
        );
    }
}
