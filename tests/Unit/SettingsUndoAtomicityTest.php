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
        delete_option('webcareproscan_activity_log_settings');
        delete_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION);
        $GLOBALS['wp_mock_cron'] = [];
        SettingsManager::reset_storage_engine_cache();
        SettingsManager::$stale_lock_observed_hook = null;
        SettingsManager::$before_persist_settings_hook = null;
        SettingsManager::$after_renewal_before_write_hook = null;
        SettingsManager::$inside_tx_before_commit_hook = null;
        SettingsManager::$interleave_before_undo_pop_hook = null;
        unset(
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_SNAPSHOTS_KEY],
            $GLOBALS['wp_mock_update_option_failures'][SettingsManager::OPTION_REVISION_KEY]
        );
        remove_all_filters('pre_option_' . SettingsManager::OPTION_KEY);
        remove_all_filters('webcareproscan_settings');
        remove_all_actions('added_option');
        remove_all_actions('updated_option');
        remove_all_actions('add_option_' . SettingsManager::OPTION_KEY);
        remove_all_actions('update_option_' . SettingsManager::OPTION_KEY);
    }

    protected function tearDown(): void
    {
        delete_option(SettingsManager::OPTION_KEY);
        delete_option(SettingsManager::OPTION_SNAPSHOTS_KEY);
        delete_option(SettingsManager::OPTION_MUTATION_LOCK);
        delete_option(SettingsManager::OPTION_REVISION_KEY);
        delete_option('webcareproscan_activity_log_settings');
        delete_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION);
        $GLOBALS['wp_mock_cron'] = [];
        SettingsManager::reset_storage_engine_cache();
        SettingsManager::$stale_lock_observed_hook = null;
        SettingsManager::$before_persist_settings_hook = null;
        SettingsManager::$after_renewal_before_write_hook = null;
        SettingsManager::$inside_tx_before_commit_hook = null;
        SettingsManager::$interleave_before_undo_pop_hook = null;
        remove_all_actions('added_option');
        remove_all_actions('updated_option');
        remove_all_actions('add_option_' . SettingsManager::OPTION_KEY);
        remove_all_actions('update_option_' . SettingsManager::OPTION_KEY);
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
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            // Step 1: Save state A ('learning'), then state A2 ('enabled') -> Snapshot stack has [A ('learning')]
            SettingsManager::save_settings(['waf_mode' => 'learning', 'login_max_retries' => 5]);
            SettingsManager::save_settings(['waf_mode' => 'enabled', 'login_max_retries' => 5]);
            $this->assertCount(1, SettingsManager::get_settings_snapshots());

            // Step 2: Simulate undo's lock expiring right before Phase 3 snapshot pop so Admin B legitimately
            // reclaims the expired lock via public save_settings(), saving settings B ('disabled') and recording a new snapshot.
            SettingsManager::$interleave_before_undo_pop_hook = static function (): void {
                $curLock = (string) get_option(SettingsManager::OPTION_MUTATION_LOCK, '');
                $ownerToken = explode('|', $curLock, 2)[0] ?? 'expired_undo';
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $ownerToken . '|' . (time() - 5), false);

                $concurrentSaved = SettingsManager::save_settings([
                    'waf_mode'          => 'disabled',
                    'login_max_retries' => 3,
                ]);
                self::assertIsArray($concurrentSaved);
            };

            $res = SettingsManager::undo_last_settings();

            $this->assertFalse($res['success'], 'Undo must detect lost lock and concurrent revision/head modification and refuse to overwrite snapshot stack.');
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
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testTwoContenderStaleLockRecoveryRaceAllowsOnlySingleWinner(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $stalePayload = 'crashed_process_token|' . (time() - 20);
            update_option(SettingsManager::OPTION_MUTATION_LOCK, $stalePayload, false);

            $winnerTokenA = null;
            $interleaved = false;

            // Exact 5-step P2-1 race simulation:
            // 1. Contender B reads $stalePayload and determines it is expired.
            // 2. Before Contender B deletes it, Contender A observes the same $stalePayload,
            //    atomically compare-and-deletes it, and acquires its own live lock ($winnerTokenA).
            // 3. Contender B resumes and runs compare_and_delete_mutation_lock($stalePayload),
            //    which MUST match 0 rows and leave Contender A's lock completely untouched.
            SettingsManager::$stale_lock_observed_hook = static function (string $observedPayload) use (&$winnerTokenA, &$interleaved, $stalePayload): void {
                if ($interleaved) {
                    return;
                }
                $interleaved = true;
                self::assertSame($stalePayload, $observedPayload);

                // Contender A enters and wins stale-lock recovery first
                $winnerTokenA = SettingsManager::acquire_mutation_lock();
                self::assertNotNull($winnerTokenA, 'Contender A must win the stale-lock recovery.');
            };

            $loserTokenB = SettingsManager::acquire_mutation_lock();

            $this->assertTrue($interleaved, 'Two-contender stale-lock interleaving hook must have fired.');
            $this->assertNotNull($winnerTokenA);
            $this->assertNull($loserTokenB, 'Contender B must NOT delete Contender A\'s newly acquired lock or acquire a second lock.');

            $liveLock = (string) get_option(SettingsManager::OPTION_MUTATION_LOCK, '');
            $this->assertStringStartsWith(
                $winnerTokenA . '|',
                $liveLock,
                'Contender A\'s newly acquired lock must remain intact in wp_options.'
            );
            $this->assertTrue(SettingsManager::verify_mutation_lock_owner($winnerTokenA));

            SettingsManager::release_mutation_lock($winnerTokenA);
            $this->assertSame('', (string) get_option(SettingsManager::OPTION_MUTATION_LOCK, ''));
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testPublicSaveSettingsHasNoLockBypassParameter(): void
    {
        $refSave = new \ReflectionMethod(SettingsManager::class, 'save_settings');
        $this->assertTrue($refSave->isPublic());
        $this->assertLessThanOrEqual(
            2,
            $refSave->getNumberOfParameters(),
            'Public save_settings() must only accept ($input, $record_snapshot) with zero lock-bypass arguments.'
        );
        foreach ($refSave->getParameters() as $param) {
            $this->assertNotSame('caller_holds_lock', $param->getName());
            $this->assertFalse($param->isPassedByReference());
        }

        $refLocked = new \ReflectionMethod(SettingsManager::class, 'save_settings_locked');
        $this->assertTrue($refLocked->isPrivate(), 'Internal lock-aware save_settings_locked() must remain strictly private.');
    }

    public function testOwnerCheckedLeaseRenewalExtendsValidLockAndRejectsExpiredOrStolenLock(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $tokenA = SettingsManager::acquire_mutation_lock(10);
            $this->assertNotNull($tokenA);

            // Simulate lock nearing expiry (2 seconds left — still valid & owned by $tokenA)
            update_option(SettingsManager::OPTION_MUTATION_LOCK, $tokenA . '|' . (time() + 2), false);

            // Non-owner cannot renew $tokenA's lock
            $this->assertFalse(
                SettingsManager::renew_mutation_lock('attacker_or_other_token', 60),
                'Non-owner token must never be permitted to renew an active mutation lock.'
            );

            // Valid owner renews lease cleanly via atomic compare-and-swap
            $this->assertTrue(SettingsManager::renew_mutation_lock($tokenA, 60));
            $renewedLock = (string) get_option(SettingsManager::OPTION_MUTATION_LOCK, '');
            $renewedExpiry = (int) (explode('|', $renewedLock, 2)[1] ?? 0);
            $this->assertGreaterThanOrEqual(time() + 58, $renewedExpiry);

            // Once lease has ALREADY expired, renew_mutation_lock() MUST refuse silent resurrection
            update_option(SettingsManager::OPTION_MUTATION_LOCK, $tokenA . '|' . (time() - 3), false);
            $this->assertFalse(
                SettingsManager::renew_mutation_lock($tokenA, 60),
                'An already-expired lock lease must fail renewal closed so stale owners abort.'
            );
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testLockExpiryDuringLongRunningSavePreventsStaleOwnerFromOverwritingNewerSettingsOrSnapshots(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            // Baseline state: 'enabled', login_max_retries = 5
            $initial = SettingsManager::save_settings([
                'waf_mode'          => 'enabled',
                'login_max_retries' => 5,
            ]);
            $this->assertIsArray($initial);
            $this->assertCount(0, SettingsManager::get_settings_snapshots());

            $adminCToken = null;
            $adminBRevision = 0;

            // Admin A starts a slow save ('learning', login_max_retries = 12) and stalls past lease TTL before persistence
            SettingsManager::$before_persist_settings_hook = static function (string $stalledTokenA) use (&$adminCToken, &$adminBRevision): void {
                // Temporarily disarm hook so Admin B's legitimate save does not re-enter the stall simulation
                SettingsManager::$before_persist_settings_hook = null;

                // Simulate Admin A stalling past its lease TTL
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $stalledTokenA . '|' . (time() - 10), false);

                // Admin B reclaims the expired lock via compare-and-delete, writes 'disabled' (retries = 3), and records snapshot
                $savedB = SettingsManager::save_settings([
                    'waf_mode'          => 'disabled',
                    'login_max_retries' => 3,
                ]);
                self::assertIsArray($savedB, 'Admin B must cleanly reclaim the expired lock and persist newer settings.');
                $adminBRevision = SettingsManager::get_settings_revision();

                // Admin C now acquires an active lock so we also verify Admin A's finally block cannot delete Admin C's lock
                $adminCToken = SettingsManager::acquire_mutation_lock();
                self::assertNotNull($adminCToken);
            };

            $staleResultA = SettingsManager::save_settings([
                'waf_mode'          => 'learning',
                'login_max_retries' => 12,
            ]);

            $this->assertFalse(
                $staleResultA,
                'Stalled Admin A whose lock expired before persistence must fail closed and return false.'
            );

            // Admin B's newer settings, revision, and snapshot history MUST remain 100% untouched
            $live = SettingsManager::get_settings();
            $this->assertSame('disabled', $live['waf_mode']);
            $this->assertSame(3, $live['login_max_retries']);
            $this->assertSame($adminBRevision, SettingsManager::get_settings_revision());

            $snapshots = SettingsManager::get_settings_snapshots();
            $this->assertCount(1, $snapshots, 'Stalled Admin A must not append or corrupt snapshot history.');
            $this->assertSame('enabled', $snapshots[0]['settings']['waf_mode']);
            $this->assertSame(5, $snapshots[0]['settings']['login_max_retries']);

            // Admin C's active lock MUST still be held after Admin A's finally block executed release_mutation_lock()
            $this->assertNotNull($adminCToken);
            $this->assertTrue(
                SettingsManager::verify_mutation_lock_owner($adminCToken),
                'Expired Admin A\'s finally block must not delete Admin C\'s active mutation lock.'
            );
            SettingsManager::release_mutation_lock($adminCToken);
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testLockLossAloneDuringUndoAbortsSnapshotPopAndPreservesNewOwnerLock(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            SettingsManager::save_settings(['waf_mode' => 'learning']);
            SettingsManager::save_settings(['waf_mode' => 'enabled']);
            $this->assertCount(1, SettingsManager::get_settings_snapshots());

            $contenderToken = null;
            SettingsManager::$interleave_before_undo_pop_hook = static function () use (&$contenderToken): void {
                $curLock = (string) get_option(SettingsManager::OPTION_MUTATION_LOCK, '');
                $undoToken = explode('|', $curLock, 2)[0] ?? 'undo_tok';
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $undoToken . '|' . (time() - 5), false);

                // Contender reclaims the expired lock before undo reaches Phase 3 snapshot pop (even before contender writes revision)
                $contenderToken = SettingsManager::acquire_mutation_lock();
                self::assertNotNull($contenderToken);
            };

            $res = SettingsManager::undo_last_settings();
            $this->assertFalse($res['success']);
            $this->assertSame('lock_lost', $res['code'] ?? '');
            $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Snapshot stack must not be popped after losing lock ownership.');
            $this->assertNotNull($contenderToken);
            $this->assertTrue(
                SettingsManager::verify_mutation_lock_owner($contenderToken),
                'Undo finally block must not delete contender\'s reclaimed lock.'
            );
            SettingsManager::release_mutation_lock($contenderToken);
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testPostRenewalSuspensionBeforeProtectedWriteAbortsViaTransactionalForUpdateFence(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            // Baseline firewall settings
            SettingsManager::save_settings([
                'waf_mode'       => 'enabled',
                'waf_block_sqli' => true,
            ]);

            $adminBRevision = 0;

            // Exact P1 race simulation:
            // 1. Process A completes sanitization and SUCCEEDS in renew_mutation_lock().
            // 2. Process A is suspended AFTER renew_mutation_lock() and BEFORE writing OPTION_KEY.
            // 3. Process A's renewed 60s lease expires while suspended.
            // 4. Process B reclaims the lock and commits newer firewall settings ('enabled', waf_block_sqli = true, login_max_retries = 2).
            // 5. Process A resumes into execute_fenced_transaction() -> SELECT ... FOR UPDATE rejects Process A,
            //    executes ROLLBACK, and leaves Process B's firewall settings, revision, and snapshots 100% intact.
            SettingsManager::$after_renewal_before_write_hook = static function (string $renewedTokenA) use (&$adminBRevision): void {
                SettingsManager::$after_renewal_before_write_hook = null;

                // Verify Process A's renewal had genuinely succeeded right before suspension
                self::assertTrue(SettingsManager::verify_mutation_lock_owner($renewedTokenA));

                // Simulate OS/PHP-FPM suspension exceeding the 60s lease
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $renewedTokenA . '|' . (time() - 5), false);

                // Process B reclaims the lock and commits newer security-policy settings
                $savedB = SettingsManager::save_settings([
                    'waf_mode'          => 'enabled',
                    'waf_block_sqli'    => true,
                    'login_max_retries' => 2,
                ]);
                self::assertIsArray($savedB);
                $adminBRevision = SettingsManager::get_settings_revision();
            };

            // Process A was attempting to weaken WAF ('disabled', waf_block_sqli = false)
            $staleSaveA = SettingsManager::save_settings([
                'waf_mode'          => 'disabled',
                'waf_block_sqli'    => false,
                'login_max_retries' => 15,
            ]);

            $this->assertFalse(
                $staleSaveA,
                'Process A suspended after lease renewal must be blocked by transactional SELECT ... FOR UPDATE fence.'
            );

            // Process B's active firewall configuration MUST NOT be overwritten by stale Process A
            $live = SettingsManager::get_settings();
            $this->assertSame('enabled', $live['waf_mode']);
            $this->assertTrue($live['waf_block_sqli']);
            $this->assertSame(2, $live['login_max_retries']);
            $this->assertSame($adminBRevision, SettingsManager::get_settings_revision());
            $this->assertCount(1, SettingsManager::get_settings_snapshots());
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testMidTransactionLeaseExpiryBeforeCommitRollsBackAllUncommittedWrites(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            SettingsManager::save_settings([
                'waf_mode'          => 'enabled',
                'login_max_retries' => 4,
            ]);
            $baselineRev = SettingsManager::get_settings_revision();

            // Simulate Process A stalling INSIDE the open transaction AFTER executing uncommitted SQL upserts
            // and immediately BEFORE pre-COMMIT lease verification & COMMIT.
            SettingsManager::$inside_tx_before_commit_hook = static function (string $txToken): void {
                SettingsManager::$inside_tx_before_commit_hook = null;
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $txToken . '|' . (time() - 2), false);
            };

            $txExpiredResult = SettingsManager::save_settings([
                'waf_mode'          => 'disabled',
                'login_max_retries' => 20,
            ]);

            $this->assertFalse(
                $txExpiredResult,
                'Pre-COMMIT SQL lease check must ROLLBACK uncommitted settings, revision, and snapshot writes when lease expired mid-transaction.'
            );

            $live = SettingsManager::get_settings();
            $this->assertSame('enabled', $live['waf_mode']);
            $this->assertSame(4, $live['login_max_retries']);
            $this->assertSame($baselineRev, SettingsManager::get_settings_revision());
            $this->assertCount(0, SettingsManager::get_settings_snapshots());
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testResetDefaultsIsProtectedByTransactionalForUpdateFenceAgainstPostRenewalExpiry(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            SettingsManager::save_settings([
                'waf_mode'          => 'learning',
                'login_max_retries' => 3,
            ]);

            // Process A starts reset_defaults(), renews its lease, then stalls past lease expiry while Process B saves custom settings
            SettingsManager::$after_renewal_before_write_hook = static function (string $resetTokenA): void {
                SettingsManager::$after_renewal_before_write_hook = null;
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $resetTokenA . '|' . (time() - 5), false);

                $savedB = SettingsManager::save_settings([
                    'waf_mode'          => 'disabled',
                    'login_max_retries' => 2,
                ]);
                self::assertIsArray($savedB);
            };

            $resetRes = SettingsManager::reset_defaults();
            $this->assertFalse($resetRes, 'Stale reset_defaults() must fail closed when lock expired after renewal.');

            // Process B's custom settings must NOT be wiped back to factory defaults!
            $live = SettingsManager::get_settings();
            $this->assertSame('disabled', $live['waf_mode']);
            $this->assertSame(2, $live['login_max_retries']);

            // Legitimate uncontended reset_defaults() succeeds atomically and bumps revision
            $revBeforeReset = SettingsManager::get_settings_revision();
            $validReset = SettingsManager::reset_defaults();
            $this->assertIsArray($validReset);
            $this->assertSame('enabled', $validReset['waf_mode']);
            $this->assertSame(5, $validReset['login_max_retries']);
            $this->assertSame($revBeforeReset + 1, SettingsManager::get_settings_revision());
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testUndoPhase3SnapshotPopMidTransactionExpiryRollsBackPop(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            SettingsManager::save_settings(['waf_mode' => 'learning']);
            SettingsManager::save_settings(['waf_mode' => 'enabled']);
            $this->assertCount(1, SettingsManager::get_settings_snapshots());

            // Arm mid-transaction expiry hook ONLY during Phase 3 snapshot pop (after Phase 1 restore finishes)
            SettingsManager::$interleave_before_undo_pop_hook = static function (): void {
                SettingsManager::$inside_tx_before_commit_hook = static function (string $undoTxToken): void {
                    SettingsManager::$inside_tx_before_commit_hook = null;
                    update_option(SettingsManager::OPTION_MUTATION_LOCK, $undoTxToken . '|' . (time() - 3), false);
                };
            };

            $undoRes = SettingsManager::undo_last_settings();
            $this->assertFalse($undoRes['success'], 'Mid-transaction lease expiry during Phase 3 snapshot pop must ROLLBACK.');
            $this->assertSame('lock_lost', $undoRes['code'] ?? '');
            $this->assertCount(1, SettingsManager::get_settings_snapshots(), 'Rolled-back Phase 3 pop must preserve snapshot entry.');
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testNonInnoDbAndInconclusiveStorageEngineFailsClosedWithZeroWrites(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            // Seed baseline state under verified InnoDB
            $mockDb->mock_options_engine = 'InnoDB';
            SettingsManager::reset_storage_engine_cache();
            $this->assertIsArray(SettingsManager::save_settings(['waf_mode' => 'learning']));
            $this->assertIsArray(SettingsManager::save_settings(['waf_mode' => 'enabled']));
            $baselineRev = SettingsManager::get_settings_revision();
            $this->assertCount(1, SettingsManager::get_settings_snapshots());

            // Test both non-InnoDB ('MyISAM') and inconclusive/unavailable (null) engines
            foreach (['MyISAM', null] as $badEngine) {
                $mockDb->mock_options_engine = $badEngine;
                SettingsManager::reset_storage_engine_cache();

                $this->assertFalse(SettingsManager::is_options_table_innodb());

                $saveRes = SettingsManager::save_settings(['waf_mode' => 'disabled']);
                $this->assertFalse($saveRes, 'save_settings() must fail closed on non-InnoDB or unverified engine.');

                $undoRes = SettingsManager::undo_last_settings();
                $this->assertFalse($undoRes['success'], 'undo_last_settings() must fail closed on non-InnoDB or unverified engine.');

                $resetRes = SettingsManager::reset_defaults();
                $this->assertFalse($resetRes, 'reset_defaults() must fail closed on non-InnoDB or unverified engine.');

                SettingsManager::record_settings_snapshot(['waf_mode' => 'disabled']);

                // Verify zero writes occurred to settings, revision, or snapshot stack
                $this->assertSame('enabled', SettingsManager::get_settings()['waf_mode']);
                $this->assertSame($baselineRev, SettingsManager::get_settings_revision());
                $this->assertCount(1, SettingsManager::get_settings_snapshots());
            }
        } finally {
            SettingsManager::reset_storage_engine_cache();
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testResetDefaultsResetsSecondaryOptionsAndSynchronizesCron(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $saved = SettingsManager::save_settings([
                'waf_mode'                           => 'disabled',
                'waf_log_retention_days'             => 180,
                'schedule_enabled'                   => true,
                'schedule_frequency'                 => 'hourly',
                'cron_domain_reputation_enabled'     => true,
                'cron_task_schedules'                => [
                    'webcareproscan_domain_reputation_daily_check' => 'twicedaily',
                ],
                'activity_log_settings'              => [
                    'retention_days'     => 90,
                    'tamper_webhook_url' => 'https://hooks.example.com/tamper',
                ],
            ]);
            $this->assertIsArray($saved);
            $this->assertSame(180, (int) get_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION));
            $this->assertSame(90, (int) (get_option('webcareproscan_activity_log_settings', [])['retention_days'] ?? 0));
            $this->assertNotFalse(wp_next_scheduled(SettingsManager::CRON_HOOK));
            if (class_exists(\WebCareProScanner\System\Cron\CronControlCenter::class)) {
                $this->assertNotFalse(wp_next_scheduled('webcareproscan_domain_reputation_daily_check'));
            }

            $reset = SettingsManager::reset_defaults();
            $this->assertIsArray($reset);
            $this->assertSame('enabled', $reset['waf_mode']);
            $this->assertSame(60, (int) $reset['waf_log_retention_days']);
            $this->assertSame(60, (int) get_option(\WebCareProScanner\Firewall\WafFileLogger::RETENTION_OPTION));
            $this->assertSame(
                ['retention_days' => 30, 'tamper_webhook_url' => ''],
                get_option('webcareproscan_activity_log_settings')
            );
            $this->assertFalse(
                wp_next_scheduled(SettingsManager::CRON_HOOK),
                'reset_defaults() must synchronize cron schedules to match default schedule_enabled = false.'
            );
            if (class_exists(\WebCareProScanner\System\Cron\CronControlCenter::class)) {
                $this->assertFalse(
                    wp_next_scheduled('webcareproscan_domain_reputation_daily_check'),
                    'reset_defaults() must also unschedule opt-in cron tasks via CronControlCenter::sync_all_from_settings().'
                );
            }
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testPostCommitOptionLifecycleNotificationsFireOnlyAfterCommitAndIsolateListenerExceptions(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $events = [];
            add_action('added_option', static function (string $option) use (&$events): void {
                $events[] = 'added:' . $option;
            }, 10, 2);
            add_action('updated_option', static function (string $option) use (&$events): void {
                $events[] = 'updated:' . $option;
            }, 10, 3);

            // 1. Initial save commits -> added_option fires post-commit
            $this->assertIsArray(SettingsManager::save_settings(['waf_mode' => 'enabled']));
            $this->assertContains('added:' . SettingsManager::OPTION_KEY, $events);

            // 2. Rolled-back transaction must fire ZERO option lifecycle notifications
            $events = [];
            SettingsManager::$inside_tx_before_commit_hook = static function (string $txToken): void {
                SettingsManager::$inside_tx_before_commit_hook = null;
                update_option(SettingsManager::OPTION_MUTATION_LOCK, $txToken . '|' . (time() - 5), false);
            };
            $this->assertFalse(SettingsManager::save_settings(['waf_mode' => 'disabled']));
            $this->assertSame([], $events, 'Rolled-back transaction must not fire post-commit option notifications.');

            // 3. Throwing listener must NOT turn an already-committed save into a false failure
            add_action('update_option_' . SettingsManager::OPTION_KEY, static function (): void {
                throw new \RuntimeException('Simulated third-party option listener crash');
            }, 10, 3);

            $committedDespiteListenerCrash = SettingsManager::save_settings(['waf_mode' => 'learning']);
            $this->assertIsArray(
                $committedDespiteListenerCrash,
                'Listener exception after COMMIT must not convert a committed settings save into a false persistence failure.'
            );
            $this->assertSame('learning', $committedDespiteListenerCrash['waf_mode']);
            $this->assertContains('updated:' . SettingsManager::OPTION_KEY, $events);
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }

    public function testMultisiteOptionsTableSwitchRevalidatesEngineAndFailsClosedOnMyIsam(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $mockDb->mock_table_engines = [
            'wp_options'   => 'InnoDB',
            'wp_2_options' => 'MyISAM',
        ];
        $GLOBALS['wpdb'] = $mockDb;

        try {
            // 1. Blog 1 uses InnoDB -> save_settings() verifies & caches wp_options => true, succeeds
            $this->assertTrue(SettingsManager::is_options_table_innodb());
            $savedBlog1 = SettingsManager::save_settings(['waf_mode' => 'learning']);
            $this->assertIsArray($savedBlog1);
            $blog1Rev = SettingsManager::get_settings_revision();

            // 2. Switch to Blog 2 (wp_2_options using MyISAM) in the SAME PHP process WITHOUT resetting cache!
            $mockDb->options = 'wp_2_options';
            $this->assertFalse(
                SettingsManager::is_options_table_innodb(),
                'Switching $wpdb->options in multisite must invalidate/bypass previous blog cache and detect MyISAM.'
            );

            // Seed Blog 2 option directly only to verify save_settings/undo/reset refuse to modify it
            $GLOBALS['wp_mock_options'][SettingsManager::OPTION_KEY] = ['waf_mode' => 'enabled'];
            $GLOBALS['wp_mock_options'][SettingsManager::OPTION_REVISION_KEY] = 42;
            $GLOBALS['wp_mock_options'][SettingsManager::OPTION_SNAPSHOTS_KEY] = [
                ['id' => 'snap_b2', 'revision' => 42, 'timestamp' => time(), 'settings' => ['waf_mode' => 'disabled']],
            ];

            // Must fail closed without writing settings, revision, or snapshots on Blog 2's MyISAM table
            $this->assertFalse(SettingsManager::save_settings(['waf_mode' => 'disabled']));
            $this->assertFalse(SettingsManager::reset_defaults());
            $undoBlog2 = SettingsManager::undo_last_settings();
            $this->assertFalse($undoBlog2['success']);

            $this->assertSame('enabled', $GLOBALS['wp_mock_options'][SettingsManager::OPTION_KEY]['waf_mode']);
            $this->assertSame(42, (int) $GLOBALS['wp_mock_options'][SettingsManager::OPTION_REVISION_KEY]);
            $this->assertCount(1, $GLOBALS['wp_mock_options'][SettingsManager::OPTION_SNAPSHOTS_KEY]);

            // 3. Ambiguous / empty table identity must also fail closed
            $mockDb->options = '   ';
            $this->assertFalse(SettingsManager::is_options_table_innodb());

            // 4. Switching back to Blog 1 (wp_options, InnoDB) continues to succeed
            $mockDb->options = 'wp_options';
            $this->assertTrue(SettingsManager::is_options_table_innodb());
            $this->assertGreaterThan(0, $blog1Rev);
        } finally {
            SettingsManager::reset_storage_engine_cache();
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }
}
