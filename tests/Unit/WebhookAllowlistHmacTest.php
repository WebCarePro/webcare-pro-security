<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\Core\AllowlistManager;
use WebCareProScanner\Firewall\Core\RequestBodyReader;
use WebCareProScanner\System\SettingsManager;

final class WebhookAllowlistHmacTest extends TestCase
{
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        delete_option('webcareproscan_vault_webhook_secrets');
        RequestBodyReader::reset();
        unset(
            $_SERVER['HTTP_STRIPE_SIGNATURE'],
            $_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'],
            $_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'],
            $_SERVER['HTTP_X_HUB_SIGNATURE_256'],
            $_SERVER['HTTP_X_GITHUB_DELIVERY'],
            $_SERVER['HTTP_X_SIGNATURE_SHA256'],
            $GLOBALS['wp_mock_update_option_failures']['webcareproscan_vault_webhook_secrets']
        );
    }

    #[\Override]
    protected function tearDown(): void
    {
        delete_option('webcareproscan_vault_webhook_secrets');
        RequestBodyReader::reset();
        unset(
            $_SERVER['HTTP_STRIPE_SIGNATURE'],
            $_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'],
            $_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'],
            $_SERVER['HTTP_X_HUB_SIGNATURE_256'],
            $_SERVER['HTTP_X_GITHUB_DELIVERY'],
            $_SERVER['HTTP_X_SIGNATURE_SHA256'],
            $GLOBALS['wp_mock_update_option_failures']['webcareproscan_vault_webhook_secrets']
        );
        parent::tearDown();
    }

    public function testStripeWebhookHmacVerificationWithToleranceAndReplayRejection(): void
    {
        $secret = 'whsec_test_secret_123';
        $body = '{"id":"evt_123_' . bin2hex(random_bytes(4)) . '","type":"payment_intent.succeeded"}';
        $now = time();

        $signature = hash_hmac('sha256', "{$now}.{$body}", $secret);
        $_SERVER['HTTP_STRIPE_SIGNATURE'] = "t={$now},v1={$signature}";

        $this->assertTrue(
            AllowlistManager::verify_webhook_hmac('stripe', $secret, $body, 300),
            'First Stripe webhook delivery within tolerance must verify successfully.'
        );

        // Duplicate delivery replay with exact same t= and v1= must be rejected by AtomicNonceStore
        $this->assertFalse(
            AllowlistManager::verify_webhook_hmac('stripe', $secret, $body, 300),
            'Replayed Stripe webhook signature must fail closed.'
        );

        // Expired timestamp (> 300s drift)
        $oldTime = $now - 301;
        $oldSig = hash_hmac('sha256', "{$oldTime}.{$body}", $secret);
        $_SERVER['HTTP_STRIPE_SIGNATURE'] = "t={$oldTime},v1={$oldSig}";

        $this->assertFalse(
            AllowlistManager::verify_webhook_hmac('stripe', $secret, $body, 300),
            'Expired Stripe webhook timestamp must fail verification.'
        );
    }

    public function testShopifyWebhookHmacAndEventIdReplayProtection(): void
    {
        $secret = 'shpss_test_secret_456';
        $body = '{"order_id":998877,"total_price":"49.99"}';
        $signature = base64_encode(hash_hmac('sha256', $body, $secret, true));

        $this->assertTrue(AllowlistManager::store_webhook_secret('wcp_wh_shopify', $secret));
        RequestBodyReader::$mock_raw_body = $body;

        $rules = [[
            'id'                        => 'rule_shopify',
            'enabled'                   => true,
            'endpoints'                 => ['/wp-json/shopify/webhook'],
            'methods'                   => ['POST'],
            'webhook_hmac_provider'     => 'shopify',
            'webhook_secret_ref'        => 'wcp_wh_shopify',
            'webhook_replay_window_sec' => 300,
        ]];

        // 1. With X-Shopify-Webhook-Id present: first succeeds with event_id_nonce, second (replay) fails closed
        $_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'] = $signature;
        $_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID'] = 'shopify-wh-' . bin2hex(random_bytes(8));

        $matched = AllowlistManager::match_targeted_allowlist_rule('/wp-json/shopify/webhook', 'Shopify/1.0', '203.0.113.10', 'POST', $rules);
        $this->assertIsArray($matched);
        $this->assertSame('event_id_nonce', $matched['replay_protection']);

        $replayed = AllowlistManager::match_targeted_allowlist_rule('/wp-json/shopify/webhook', 'Shopify/1.0', '203.0.113.10', 'POST', $rules);
        $this->assertNull($replayed, 'Replayed X-Shopify-Webhook-Id must fail closed.');

        // 2. Without X-Shopify-Webhook-Id: valid HMAC marks replay_protection = signature_only
        unset($_SERVER['HTTP_X_SHOPIFY_WEBHOOK_ID']);
        $matchedNoId = AllowlistManager::match_targeted_allowlist_rule('/wp-json/shopify/webhook', 'Shopify/1.0', '203.0.113.10', 'POST', $rules);
        $this->assertIsArray($matchedNoId);
        $this->assertSame('signature_only', $matchedNoId['replay_protection']);

        // 3. Invalid signature fails
        $_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'] = 'invalid_sig';
        $this->assertFalse(AllowlistManager::verify_webhook_hmac('shopify', $secret, $body));
    }

    public function testGithubWebhookHmacRequiresAndConsumesDeliveryUuid(): void
    {
        $secret = 'gh_webhook_secret_789';
        $body = '{"action":"push","ref":"refs/heads/main"}';
        $signature = 'sha256=' . hash_hmac('sha256', $body, $secret);

        $_SERVER['HTTP_X_HUB_SIGNATURE_256'] = $signature;

        // Missing X-GitHub-Delivery must fail closed
        unset($_SERVER['HTTP_X_GITHUB_DELIVERY']);
        $this->assertFalse(
            AllowlistManager::verify_webhook_hmac('github', $secret, $body, 300),
            'GitHub webhook without X-GitHub-Delivery header must fail closed.'
        );

        // Fresh X-GitHub-Delivery succeeds once
        $_SERVER['HTTP_X_GITHUB_DELIVERY'] = '72d3162e-cc78-11e3-81ab-' . bin2hex(random_bytes(6));
        $this->assertTrue(
            AllowlistManager::verify_webhook_hmac('github', $secret, $body, 300),
            'GitHub sha256= hex signature with unique delivery ID must verify successfully.'
        );

        // Replayed X-GitHub-Delivery fails closed
        $this->assertFalse(
            AllowlistManager::verify_webhook_hmac('github', $secret, $body, 300),
            'Replayed X-GitHub-Delivery UUID must fail closed.'
        );
    }

    public function testRuleMatchFailsClosedOnMissingCorruptedOrMismatchedVaultConfig(): void
    {
        $body = '{"ping":true}';
        RequestBodyReader::$mock_raw_body = $body;

        // Case A: Missing SecretVault reference -> fail closed
        $missingRefRule = [[
            'id'                    => 'r_missing_ref',
            'enabled'               => true,
            'endpoints'             => ['/wh/test'],
            'methods'               => ['POST'],
            'webhook_hmac_provider' => 'generic_sha256',
            'webhook_secret_ref'    => 'wcp_wh_nonexistent_ref',
        ]];
        $_SERVER['HTTP_X_SIGNATURE_SHA256'] = hash_hmac('sha256', $body, 'any');
        $this->assertNull(
            AllowlistManager::match_targeted_allowlist_rule('/wh/test', 'Bot/1.0', '198.51.100.9', 'POST', $missingRefRule),
            'Missing SecretVault reference must fail closed.'
        );

        // Case B: Corrupted / undecryptable ciphertext in vault -> fail closed
        update_option('webcareproscan_vault_webhook_secrets', [
            'wcp_wh_corrupt_gcm'   => 'webcare_gcm:' . base64_encode(random_bytes(48)),
            'wcp_wh_unencrypted'   => 'plaintext_should_never_be_trusted',
        ], false);

        $corruptRule = [[
            'id'                    => 'r_corrupt',
            'enabled'               => true,
            'endpoints'             => ['/wh/test'],
            'methods'               => ['POST'],
            'webhook_hmac_provider' => 'generic_sha256',
            'webhook_secret_ref'    => 'wcp_wh_corrupt_gcm',
        ]];
        $this->assertNull(
            AllowlistManager::match_targeted_allowlist_rule('/wh/test', 'Bot/1.0', '198.51.100.9', 'POST', $corruptRule),
            'Undecryptable GCM ciphertext in SecretVault must fail closed.'
        );

        $unencryptedVaultRule = [[
            'id'                    => 'r_unenc',
            'enabled'               => true,
            'endpoints'             => ['/wh/test'],
            'methods'               => ['POST'],
            'webhook_hmac_provider' => 'generic_sha256',
            'webhook_secret_ref'    => 'wcp_wh_unencrypted',
        ]];
        $_SERVER['HTTP_X_SIGNATURE_SHA256'] = hash_hmac('sha256', $body, 'plaintext_should_never_be_trusted');
        $this->assertNull(
            AllowlistManager::match_targeted_allowlist_rule('/wh/test', 'Bot/1.0', '198.51.100.9', 'POST', $unencryptedVaultRule),
            'Unencrypted plaintext entry inside vault option must fail closed.'
        );

        // Case C: webhook_hmac_provider === 'none' with non-empty webhook_secret_ref -> fail closed
        $this->assertTrue(AllowlistManager::store_webhook_secret('wcp_wh_valid', 'real_secret_xyz'));
        $noneWithRefRule = [[
            'id'                    => 'r_none_with_ref',
            'enabled'               => true,
            'endpoints'             => ['/wh/test'],
            'methods'               => ['POST'],
            'webhook_hmac_provider' => 'none',
            'webhook_secret_ref'    => 'wcp_wh_valid',
        ]];
        $this->assertNull(
            AllowlistManager::match_targeted_allowlist_rule('/wh/test', 'Bot/1.0', '198.51.100.9', 'POST', $noneWithRefRule),
            'Provider "none" paired with a non-empty webhook_secret_ref must fail closed.'
        );
    }

    public function testStoreWebhookSecretPersistenceFailurePreventsRuleSave(): void
    {
        $GLOBALS['wp_mock_update_option_failures']['webcareproscan_vault_webhook_secrets'] = true;

        $this->assertFalse(
            AllowlistManager::store_webhook_secret('wcp_wh_fail_ref', 'whsec_cannot_persist'),
            'store_webhook_secret() must return false when option persistence fails.'
        );

        $rawRules = [[
            'id'                    => 'rule_fail_persist',
            'name'                  => 'Stripe Fail Rule',
            'endpoints'             => ['/wp-json/stripe/v1/webhook'],
            'webhook_hmac_provider' => 'stripe',
            'webhook_secret'        => 'whsec_cannot_persist',
        ]];

        $sanitized = SettingsManager::sanitize_targeted_allowlist_rules($rawRules);
        $this->assertSame([], $sanitized, 'Rule must not be sanitized into saved list if secret persistence fails.');

        $saveResult = SettingsManager::save_settings([
            'waf_targeted_allowlist_rules' => $rawRules,
        ]);
        $this->assertFalse($saveResult, 'SettingsManager::save_settings() must abort and return false when SecretVault persistence fails.');
    }

    public function testUnavailableRequestBodyReaderFailsClosedWithoutUnboundedInputFallback(): void
    {
        $secret = 'whsec_bounded_reader_required';
        $ref = 'wcp_wh_sec_reader_req';
        $this->assertTrue(AllowlistManager::store_webhook_secret($ref, $secret));

        $body = '{"id":"evt_reader_check","type":"charge.succeeded"}';
        RequestBodyReader::$mock_raw_body = $body;

        $now = time();
        $sig = hash_hmac('sha256', "{$now}.{$body}", $secret);
        $_SERVER['HTTP_STRIPE_SIGNATURE'] = "t={$now},v1={$sig}";

        $rules = [[
            'id'                        => 'rule_stripe_reader_unavailable',
            'name'                      => 'Stripe Bounded Reader Guard',
            'enabled'                   => true,
            'endpoints'                 => ['/wp-json/stripe/v1/webhook'],
            'methods'                   => ['POST'],
            'webhook_hmac_provider'     => 'stripe',
            'webhook_secret_ref'        => $ref,
            'webhook_replay_window_sec' => 300,
        ]];

        AllowlistManager::$force_body_reader_unavailable_for_tests = true;
        try {
            $matched = AllowlistManager::match_targeted_allowlist_rule(
                '/wp-json/stripe/v1/webhook',
                'Stripe/1.0',
                '198.51.100.25',
                'POST',
                $rules
            );
            $this->assertNull(
                $matched,
                'HMAC allowlist verification must fail closed when RequestBodyReader is unavailable rather than reading php://input directly.'
            );
        } finally {
            AllowlistManager::$force_body_reader_unavailable_for_tests = false;
        }

        // Confirm the exact same signed request succeeds once RequestBodyReader is available again
        $matchedAfterRestore = AllowlistManager::match_targeted_allowlist_rule(
            '/wp-json/stripe/v1/webhook',
            'Stripe/1.0',
            '198.51.100.25',
            'POST',
            $rules
        );
        $this->assertIsArray($matchedAfterRestore, 'Rule must match normally when bounded RequestBodyReader is available.');
    }
}
