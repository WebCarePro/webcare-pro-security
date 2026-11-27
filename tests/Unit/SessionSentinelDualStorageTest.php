<?php

declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Auth\SessionSentinel;

class SessionSentinelDualStorageTest extends TestCase
{
    private int $testUserId = 9901;

    protected function setUp(): void
    {
        parent::setUp();
        SessionSentinel::reset_reconcile_cache();
        delete_user_meta($this->testUserId, 'webcareproscan_session_meta');
        $vaultFile = rtrim(SessionSentinel::get_vault_dir(), '/\\') . '/' . SessionSentinel::VAULT_FILE;
        if (is_file($vaultFile)) {
            @unlink($vaultFile);
        }
    }

    protected function tearDown(): void
    {
        SessionSentinel::reset_reconcile_cache();
        delete_user_meta($this->testUserId, 'webcareproscan_session_meta');
        $vaultFile = rtrim(SessionSentinel::get_vault_dir(), '/\\') . '/' . SessionSentinel::VAULT_FILE;
        if (is_file($vaultFile)) {
            @unlink($vaultFile);
        }
        parent::tearDown();
    }

    public function testSaveEncryptsBothDatabaseAndVaultWithoutPlaintextLeak(): void
    {
        $now = time();
        $payload = [
            'tok_alpha' => [
                'login_ip'   => '198.51.100.42',
                'current_ip' => '198.51.100.42',
                'login_time' => $now,
                'last_seen'  => $now,
                'status'     => 'active',
            ],
        ];

        SessionSentinel::save_stored_session_meta($this->testUserId, $payload);

        // 1. Verify raw DB meta is encrypted ciphertext, NOT plaintext IP
        $rawDb = get_user_meta($this->testUserId, 'webcareproscan_session_meta', true);
        self::assertIsString($rawDb);
        self::assertNotEmpty($rawDb);
        self::assertStringNotContainsString('198.51.100.42', $rawDb);

        // 2. Verify raw Vault file on disk is encrypted + HMAC-signed, NOT plaintext IP
        $vaultFile = rtrim(SessionSentinel::get_vault_dir(), '/\\') . '/' . SessionSentinel::VAULT_FILE;
        self::assertFileExists($vaultFile);
        $rawVault = (string) file_get_contents($vaultFile);
        self::assertStringNotContainsString('198.51.100.42', $rawVault);
        self::assertStringContainsString('V2_AUTH_SENTINEL_AEAD', $rawVault);
        self::assertStringContainsString('"retention_days": 30', $rawVault);
    }

    public function testMissingVaultAutoHealsFromEncryptedDatabase(): void
    {
        $now = time();
        $payload = [
            'tok_db_only' => [
                'login_ip'   => '203.0.113.10',
                'login_time' => $now,
                'last_seen'  => $now,
                'status'     => 'active',
            ],
        ];

        SessionSentinel::save_stored_session_meta($this->testUserId, $payload);

        // Simulate vault file deletion
        $vaultFile = rtrim(SessionSentinel::get_vault_dir(), '/\\') . '/' . SessionSentinel::VAULT_FILE;
        @unlink($vaultFile);
        self::assertFileDoesNotExist($vaultFile);

        // Reading session meta must recover from DB and recreate encrypted vault file
        SessionSentinel::reset_reconcile_cache($this->testUserId);
        $restored = SessionSentinel::get_stored_session_meta($this->testUserId);

        self::assertArrayHasKey('tok_db_only', $restored);
        self::assertSame('203.0.113.10', $restored['tok_db_only']['login_ip']);
        self::assertFileExists($vaultFile);

        $vaultData = SessionSentinel::read_from_auth_vault();
        self::assertArrayHasKey($this->testUserId, $vaultData);
        self::assertArrayHasKey('tok_db_only', $vaultData[$this->testUserId]);
    }

    public function testMissingDatabaseAutoHealsFromEncryptedVault(): void
    {
        $now = time();
        $payload = [
            'tok_vault_only' => [
                'login_ip'   => '203.0.113.25',
                'login_time' => $now,
                'last_seen'  => $now,
                'status'     => 'logged_out',
                'revoked_at' => $now,
            ],
        ];

        SessionSentinel::save_stored_session_meta($this->testUserId, $payload);

        // Simulate DB user_meta loss
        delete_user_meta($this->testUserId, 'webcareproscan_session_meta');
        self::assertEmpty(get_user_meta($this->testUserId, 'webcareproscan_session_meta', true));

        // Reading session meta must recover from Vault and restore encrypted DB meta
        SessionSentinel::reset_reconcile_cache($this->testUserId);
        $restored = SessionSentinel::get_stored_session_meta($this->testUserId);

        self::assertArrayHasKey('tok_vault_only', $restored);
        self::assertSame('203.0.113.25', $restored['tok_vault_only']['login_ip']);

        $rawDbAfter = get_user_meta($this->testUserId, 'webcareproscan_session_meta', true);
        self::assertIsString($rawDbAfter);
        self::assertNotEmpty($rawDbAfter);
        self::assertStringNotContainsString('203.0.113.25', $rawDbAfter);
    }

    public function testDivergedDatabaseAndVaultUnionMergeBothSides(): void
    {
        $now = time();
        SessionSentinel::save_stored_session_meta($this->testUserId, [
            'tok_vault_record' => [
                'login_ip'   => '198.51.100.11',
                'login_time' => $now - 3600,
                'last_seen'  => $now - 3600,
                'status'     => 'logged_out',
            ],
        ]);

        // Overwrite DB directly with a different encrypted record to simulate partial DB rollback/drift
        $dbOnlyEncrypted = \WebCareProScanner\Security\SecretVault::encrypt((string) wp_json_encode([
            'tok_db_record' => [
                'login_ip'   => '198.51.100.22',
                'login_time' => $now,
                'last_seen'  => $now,
                'status'     => 'active',
            ],
        ]));
        update_user_meta($this->testUserId, 'webcareproscan_session_meta', $dbOnlyEncrypted);

        SessionSentinel::reset_reconcile_cache($this->testUserId);
        $merged = SessionSentinel::get_stored_session_meta($this->testUserId);

        self::assertArrayHasKey('tok_vault_record', $merged);
        self::assertArrayHasKey('tok_db_record', $merged);

        // Both DB and Vault must now hold the union of both records
        $vaultData = SessionSentinel::read_from_auth_vault();
        self::assertArrayHasKey('tok_vault_record', $vaultData[$this->testUserId]);
        self::assertArrayHasKey('tok_db_record', $vaultData[$this->testUserId]);
    }
}
