<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\System\SettingsManager;

final class SettingsUndoAtomicityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        delete_option(SettingsManager::OPTION_MUTATION_LOCK);
        delete_option(SettingsManager::OPTION_REVISION_KEY);
        SettingsManager::$interleave_before_undo_pop_hook = null;
        unset(
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_SNAPSHOTS_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_REVISION_KEY]
        );
        remove_all_filters('pre_option_' . SettingsManager::OPTION_KEY);
        remove_all_filters('webcareproscan_settings');
    }

    protected function tearDown(): void
    {
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        delete_option(SettingsManager::OPTION_MUTATION_LOCK);
        delete_option(SettingsManager::OPTION_REVISION_KEY);
        SettingsManager::$interleave_before_undo_pop_hook = null;
        unset(
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_SNAPSHOTS_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_REVISION_KEY]
        );
        remove_all_filters('pre_option_' . SettingsManager::OPTION_KEY);
        remove_all_filters('webcareproscan_settings');
        parent::tearDown();
    }

    public function testUndoPreservesRemainingSnapshotStackWhenTopIsCorrupted(): void
    {
        update_option(SettingsManager::OPTION_SNAPSHOTS_KEY, [
            [
                'id'        => 'corrupted_1',
                'timestamp' => time(),
                'settings'  => [],
            ],
            [
                'id'        => 'valid_2',
                'timestamp' => time() - 100,
                'settings'  => ['waf_mode' => 'learning'],
            ],
        ]);

        $res = SettingsManager::undo_last_settings();
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('Corrupted settings snapshot', $res['message']);

        $snapshots = SettingsManager::get_settings_snapshots();
        $this->assertCount(1, $snapshots);
        $this->assertSame('valid_2', $snapshots[0]['id']);
    }

    public function testUndoPopsSnapshotOnlyAfterCompleteNestedVerification(): void
    {
        // 1. Initial settings including nested array & targeted allowlist JSON
        SettingsManager::save_settings([
            'waf_mode' => 'learning',
            'custom_scan_options' => [
                'scan_known_malware'     => true,
                'scan_password_strength' => true,
            ],
            'waf_targeted_allowlist_rules' => [
                [
                    'id'           => 'rule_klaviyo',
                    'name'         => 'Klaviyo Sync',
                    'endpoints'    => ['/wp-json/wc/v3/orders'],
                    'ip_addresses' => ['198.51.100.10'],
                ],
            ],
        ]);

        // 2. Modify scalar & nested settings
        SettingsManager::save_settings([
            'waf_mode' => 'enabled',
            'custom_scan_options' => [
                'scan_known_malware'     => false,
                'scan_password_strength' => false,
            ],
            'waf_targeted_allowlist_rules' => '[]',
        ]);

        $this->assertCount(1, SettingsManager::get_settings_snapshots());

        // 3. Undo and verify complete nested restoration
        $res = SettingsManager::undo_last_settings();
        $this->assertTrue($res['success']);
        $this->assertCount(0, SettingsManager::get_settings_snapshots());

        $current = SettingsManager::get_settings();
        $this->assertSame('learning', $current['waf_mode']);
        $this->assertTrue($current['custom_scan_options']['scan_known_malware']);
        $this->assertTrue($current['custom_scan_options']['scan_password_strength']);

        $restoredRules = json_decode((string) $current['waf_targeted_allowlist_rules'], true);
        $this->assertIsArray($restoredRules);
        $this->assertCount(1, $restoredRules);
        $this->assertSame('rule_klaviyo', $restoredRules[0]['id']);
    }

    public function testSaveSettingsFailurePreservesSnapshotUntouched(): void
    {
        SettingsManager::save_settings(['waf_mode' => 'learning']);
        SettingsManager::save_settings(['waf_mode' => 'enabled']);

        $this->assertCount(1, SettingsManager::get_settings_snapshots());

        // Inject option write failure during save_settings() inside undo_last_settings()
        $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_KEY] = true;

        $res = SettingsManager::undo_last_settings();
        $this->assertFalse($res['success']);
        $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Snapshot must remain untouched when save_settings() fails.');
        $this->assertSame('learning', SettingsManager::get_settings_snapshots()[0]['settings']['waf_mode']);
    }

    public function testNestedArrayMismatchOnReadBackFailsVerificationAndPreservesSnapshot(): void
    {
        SettingsManager::save_settings([
            'waf_mode' => 'learning',
            'waf_targeted_allowlist_rules' => [
                [
                    'id'           => 'rule_intact',
                    'name'         => 'Intact Rule',
                    'endpoints'    => ['/wp-json/wc/v3/products'],
                    'ip_addresses' => ['203.0.113.5'],
                ],
            ],
        ]);
        SettingsManager::save_settings([
            'waf_mode' => 'enabled',
            'waf_targeted_allowlist_rules' => '[]',
        ]);

        // Corrupt nested array during read-back via filter
        add_filter('webcareproscan_settings', static function (array $settings): array {
            $settings['custom_scan_options']['scan_known_malware'] = false;
            return $settings;
        });

        $res = SettingsManager::undo_last_settings();
        $this->assertFalse($res['success'], 'Nested array mismatch on read-back must fail undo verification.');
        $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Snapshot must be preserved when nested verification fails.');
    }

    public function testMissingKeyOnReadBackFailsVerificationAndPreservesSnapshot(): void
    {
        SettingsManager::save_settings(['waf_mode' => 'learning']);
        SettingsManager::save_settings(['waf_mode' => 'enabled']);

        // Simulate missing expected key in read-back settings
        add_filter('webcareproscan_settings', static function (array $settings): array {
            unset($settings['waf_targeted_allowlist_rules']);
            return $settings;
        });

        $res = SettingsManager::undo_last_settings();
        $this->assertFalse($res['success'], 'Missing expected non-secret key must fail undo verification.');
        $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Snapshot must be preserved when expected key is missing.');
    }

    public function testSnapshotStackUpdateOptionFailureIsSurfacedExplicitly(): void
    {
        SettingsManager::save_settings(['waf_mode' => 'learning']);
        SettingsManager::save_settings(['waf_mode' => 'enabled']);

        // Allow OPTION_KEY restore to succeed, but fail popping OPTION_SNAPSHOTS_KEY
        $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_SNAPSHOTS_KEY] = true;

        $res = SettingsManager::undo_last_settings();
        $this->assertFalse($res['success'], 'Failure to persist popped snapshot stack must not return silent success: true.');
        $this->assertArrayHasKey('warning', $res);
        $this->assertSame('Settings restored, but snapshot history could not be updated.', $res['warning']);
        $this->assertSame('learning', SettingsManager::get_settings()['waf_mode']);
    }

    public function testMutationLockPreventsConcurrentSaveAndUndoContention(): void
    {
        SettingsManager::save_settings(['waf_mode' => 'learning']);
        SettingsManager::save_settings(['waf_mode' => 'enabled']);

        // Simulate active unexpired lock held by another administrator process
        add_option(SettingsManager::OPTION_MUTATION_LOCK, 'other_admin_holder|' . (time() + 15), '', 'no');

        $concurrentSave = SettingsManager::save_settings(['waf_mode' => 'disabled']);
        $this->assertFalse($concurrentSave, 'save_settings() must fail closed when another admin holds the active mutation lock.');

        $concurrentUndo = SettingsManager::undo_last_settings();
        $this->assertFalse($concurrentUndo['success'], 'undo_last_settings() must abort when another admin holds the active mutation lock.');
        $this->assertSame('lock_contention', $concurrentUndo['code'] ?? '');
        $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Snapshot stack must remain untouched under lock contention.');
        $this->assertSame('enabled', SettingsManager::get_settings()['waf_mode']);

        // Expired stale lock must be automatically reclaimed on next undo
        update_option(SettingsManager::OPTION_MUTATION_LOCK, 'stale_holder|' . (time() - 5), false);
        $reclaimedUndo = SettingsManager::undo_last_settings();
        $this->assertTrue($reclaimedUndo['success'], 'Expired mutation lock must be reclaimed cleanly.');
        $this->assertSame('learning', SettingsManager::get_settings()['waf_mode']);
    }

    public function testConcurrentInterleavingBeforeSnapshotPopAbortsOverwriteAndPreservesNewerHistory(): void
    {
        // Step 1: Save state A ('learning'), then state A2 ('enabled') -> Snapshot stack has [A ('learning')]
        SettingsManager::save_settings(['waf_mode' => 'learning', 'login_max_retries' => 5]);
        SettingsManager::save_settings(['waf_mode' => 'enabled', 'login_max_retries' => 5]);
        $this->assertCount(1, SettingsManager::get_settings_snapshots());

        // Step 2: Simulate an interleaved concurrent admin save (settings B: 'disabled', login_max_retries: 3)
        // occurring right after undo restores & verifies A, before undo attempts to write its popped snapshot stack.
        SettingsManager::$interleave_before_undo_pop_hook = static function (): void {
            // Simulate lock expiration/external concurrent write saving settings B and recording a new snapshot
            SettingsManager::save_settings(
                ['waf_mode' => 'disabled', 'login_max_retries' => 3],
                true,
                $ignored,
                true
            );
        };

        $res = SettingsManager::undo_last_settings();

        $this->assertFalse($res['success'], 'Undo must detect concurrent revision/head modification and refuse to overwrite snapshot stack.');
        $this->assertSame('concurrent_modification', $res['code'] ?? '');

        // Active settings B MUST remain intact
        $liveSettings = SettingsManager::get_settings();
        $this->assertSame('disabled', $liveSettings['waf_mode']);
        $this->assertSame(3, $liveSettings['login_max_retries']);

        // Newer snapshot recorded by Admin B + earlier snapshot A MUST both remain preserved in order!
        $snapshotsAfter = SettingsManager::get_settings_snapshots();
        $this->assertCount(2, $snapshotsAfter, 'Undo must NOT overwrite newer snapshot history recorded by concurrent admin save.');
        $this->assertGreaterThan(
            (int) ($snapshotsAfter[1]['revision'] ?? 0),
            (int) ($snapshotsAfter[0]['revision'] ?? 0),
            'Newest snapshot head must retain the higher monotonic revision from the concurrent save.'
        );
        $this->assertNotSame($snapshotsAfter[0]['id'] ?? '', $snapshotsAfter[1]['id'] ?? '');
        $this->assertSame('learning', $snapshotsAfter[0]['settings']['waf_mode']);
        $this->assertSame('learning', $snapshotsAfter[1]['settings']['waf_mode']);
    }
}
