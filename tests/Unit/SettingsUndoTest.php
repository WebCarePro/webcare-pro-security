<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Security\SecretVault;

/**
 * SettingsUndoTest
 *
 * Validates atomic secret-safe settings undo, snapshot capping,
 * and credential non-leakage.
 */
final class SettingsUndoTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        // Clear options before each test
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
    }

    protected function tearDown(): void {
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        parent::tearDown();
    }

    public function test_snapshots_exclude_all_secret_keys(): void {
        $settings_with_secrets = [
            'waf_mode'                     => 'learning',
            'openai_api_key'               => 'sk-test-secret-key-12345',
            'gemini_api_key'               => 'AIzaSy-gemini-secret-token',
            'claude_api_key'               => 'sk-ant-claude-key-999',
            'deepseek_api_key'             => 'sk-deepseek-key-888',
            'openrouter_api_key'           => 'sk-or-key-777',
            'slack_webhook_url'            => 'https://hooks.slack.com/services/T00/B00/SECRET',
            'discord_webhook_url'          => 'https://discord.com/api/webhooks/123/SECRET',
            'cloudflare_api_token'         => 'cf-super-secret-token',
            'waf_cloudflare_origin_secret' => 'origin-pull-secret-xyz',
            'mcp_token'                    => 'mcp-secret-token-abc',
        ];

        $stripped = SettingsManager::strip_secrets($settings_with_secrets);

        foreach (SettingsManager::SECRET_KEYS as $secret_key) {
            $this->assertArrayNotHasKey(
                $secret_key,
                $stripped,
                "Snapshot strip_secrets() must remove secret key: {$secret_key}"
            );
        }

        $this->assertSame('learning', $stripped['waf_mode']);
    }

    public function test_save_settings_records_snapshot_without_secrets(): void {
        // Initial save
        SettingsManager::save_settings([
            'waf_mode'       => 'learning',
            'openai_api_key' => 'sk-initial-secret',
        ]);

        // Second save which triggers diff
        SettingsManager::save_settings([
            'waf_mode'       => 'enforce',
            'openai_api_key' => 'sk-initial-secret',
        ]);

        $snapshots = SettingsManager::get_settings_snapshots();
        $this->assertNotEmpty($snapshots, 'Snapshots list should have recorded the prior state.');
        $this->assertCount(1, $snapshots);

        $first_snap = $snapshots[0]['settings'];
        $this->assertSame('learning', $first_snap['waf_mode']);

        foreach (SettingsManager::SECRET_KEYS as $secret_key) {
            $this->assertArrayNotHasKey(
                $secret_key,
                $first_snap,
                "Stored snapshot must never contain secret key: {$secret_key}"
            );
        }
    }

    public function test_undo_restores_prior_settings_and_preserves_active_secrets(): void {
        // Initial configuration
        SettingsManager::save_settings([
            'waf_mode'       => 'learning',
            'openai_api_key' => 'sk-active-secret-1234',
        ]);

        // Admin modifies setting
        SettingsManager::save_settings([
            'waf_mode'       => 'disabled',
            'openai_api_key' => 'sk-active-secret-1234',
        ]);

        $current_before_undo = SettingsManager::get_settings();
        $this->assertSame('disabled', $current_before_undo['waf_mode']);

        // Execute Undo
        $undo_result = SettingsManager::undo_last_settings();
        $this->assertTrue($undo_result['success'], 'Undo operation should succeed.');
        $this->assertSame(0, $undo_result['snapshots_remaining']);

        // Verify restored setting
        $current_after_undo = SettingsManager::get_settings();
        $this->assertSame('learning', $current_after_undo['waf_mode'], 'waf_mode must revert to learning.');

        // Verify active secret is retained and uncorrupted
        $decrypted_secret = SecretVault::decrypt($current_after_undo['openai_api_key'] ?? '');
        $this->assertSame('sk-active-secret-1234', $decrypted_secret, 'Active secrets must remain intact through Undo.');
    }

    public function test_snapshots_capped_at_max_ten(): void {
        for ($i = 1; $i <= 15; $i++) {
            SettingsManager::record_settings_snapshot([
                'schedule_scan_type' => "type_{$i}",
            ]);
        }

        $snapshots = SettingsManager::get_settings_snapshots();
        $this->assertCount(10, $snapshots, 'Snapshots list must be capped at 10 items.');
        // Most recent snapshot should be type_15
        $this->assertSame('type_15', $snapshots[0]['settings']['schedule_scan_type']);
    }

    public function test_undo_on_empty_snapshots_returns_safe_failure(): void {
        $undo_result = SettingsManager::undo_last_settings();
        $this->assertFalse($undo_result['success']);
        $this->assertSame(0, $undo_result['snapshots_remaining']);
    }
}
