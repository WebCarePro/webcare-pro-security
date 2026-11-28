<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Scan\ScanLock;

class ScanLockTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;
    }

    public function testAcquireAndReleaseCycle(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->assertTrue(ScanLock::acquire(101), 'First scan should acquire lock cleanly.');
        $this->assertTrue(ScanLock::is_locked(), 'Lock should report active after acquisition.');
        $this->assertSame(101, ScanLock::get_locked_scan_id(), 'Locked scan ID should match 101.');

        $token = ScanLock::get_active_lease_token(101);
        $this->assertNotEmpty($token, 'Acquired scan should have a cryptographic lease token.');

        $this->assertTrue(ScanLock::release(101, $token), 'Release with valid token must succeed.');
        $this->assertFalse(ScanLock::is_locked(), 'Lock should be inactive after release.');
        $this->assertNull(ScanLock::get_locked_scan_id(), 'Locked scan ID should be null after release.');
    }

    public function testRejectsConcurrentScanWhenMySqlAdvisoryLockHeld(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 0;

        $this->assertFalse(
            ScanLock::acquire(102),
            'Acquisition must immediately return false when GET_LOCK returns 0.'
        );
    }

    public function testRejectsConcurrentScanWhenOptionLockActiveAndReleasesAdvisoryMutex(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        update_option(ScanLock::LOCK_OPTION, [
            'scan_id'     => 101,
            'time'        => time(),
            'lease_token' => 'active_token_101',
        ]);

        $acquired = ScanLock::acquire(202);
        $this->assertFalse($acquired, 'Different scan ID must be rejected while active lock is within timeout.');

        $releasedQueries = array_filter(
            $GLOBALS['wpdb']->queries,
            static fn(string $q) => str_contains($q, 'RELEASE_LOCK')
        );
        $this->assertNotEmpty($releasedQueries, 'Must invoke RELEASE_LOCK when rejecting on option-state conflict.');
    }

    public function testAllowsReentryForSameScanId(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->assertTrue(ScanLock::acquire(303));
        $this->assertTrue(ScanLock::acquire(303), 'Same scan ID should be allowed to re-acquire its own active lock.');
    }

    public function testRecoversFromExpiredStaleLock(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        update_option(ScanLock::LOCK_OPTION, [
            'scan_id'     => 404,
            'time'        => time() - (ScanLock::LOCK_TIMEOUT_SECONDS + 30),
            'lease_token' => 'stale_token_404',
        ]);

        $this->assertFalse(ScanLock::is_locked(), 'Expired lock should not report as actively locked.');
        $this->assertTrue(ScanLock::acquire(505), 'New scan must successfully override an expired stale lock.');
        $this->assertSame(505, ScanLock::get_locked_scan_id());
    }

    public function testHeartbeatExtendsLockTimestampOnlyForOwnerWithToken(): void {
        $staleTime = time() - 200;
        $validToken = 'test_token_606';
        update_option(ScanLock::LOCK_OPTION, [
            'scan_id'     => 606,
            'time'        => $staleTime,
            'lease_token' => $validToken,
        ]);

        // Mismatched scan ID
        $this->assertFalse(ScanLock::heartbeat(999, $validToken));
        $current = get_option(ScanLock::LOCK_OPTION);
        $this->assertSame($staleTime, $current['time'], 'Non-owner scan ID must not refresh heartbeat.');

        // Mismatched token
        $this->assertFalse(ScanLock::heartbeat(606, 'wrong_token'));
        $current = get_option(ScanLock::LOCK_OPTION);
        $this->assertSame($staleTime, $current['time'], 'Invalid token must not refresh heartbeat.');

        // Empty token
        $this->assertFalse(ScanLock::heartbeat(606, ''));

        // Owner scan ID with matching token
        $this->assertTrue(ScanLock::heartbeat(606, $validToken));
        $updated = get_option(ScanLock::LOCK_OPTION);
        $this->assertGreaterThanOrEqual($staleTime + 200, $updated['time'], 'Owner scan ID should refresh lock timestamp.');
    }

    public function testReleaseWithSpecificScanIdDoesNotClearAnotherScansLock(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        ScanLock::acquire(707);
        $token = ScanLock::get_active_lease_token(707);
        $queriesBefore = $GLOBALS['wpdb']->queries;

        $this->assertFalse(ScanLock::release(808, $token));
        $this->assertFalse(ScanLock::release(707, 'wrong_token'));

        $this->assertSame(707, ScanLock::get_locked_scan_id(), 'Mismatched scan ID release must preserve active owner lock.');

        $newReleasedQueries = array_filter(
            array_slice($GLOBALS['wpdb']->queries, count($queriesBefore)),
            static fn(string $q) => str_contains($q, 'RELEASE_LOCK') && str_contains($q, ScanLock::BATCH_LOCK_NAME)
        );
        $this->assertEmpty($newReleasedQueries, 'Mismatched scan ID release must not release batch lock on database.');
    }

    public function testFailsClosedWhenWpdbUnavailable(): void {
        $GLOBALS['wpdb'] = null;

        $this->assertFalse(
            ScanLock::acquire(101),
            'Acquisition must fail closed and return false if wpdb is null.'
        );

        $this->assertFalse(
            ScanLock::acquire_batch_lock(101, 'dummy_token'),
            'Batch lock acquisition must fail closed and return false if wpdb is null.'
        );
    }

    public function testFailsClosedWhenAdvisoryLockReturnsNull(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => null;

        $this->assertFalse(
            ScanLock::acquire(808),
            'Acquisition must fail closed and return false if GET_LOCK returns null due to database lock error.'
        );
    }

    public function testBatchLockAcquireAndReleaseCycle(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        // Acquire parent scan lock first
        $this->assertTrue(ScanLock::acquire(909));
        $token = ScanLock::get_active_lease_token(909);
        $this->assertNotEmpty($token);

        // Batch lock should succeed for scan owner with token
        $this->assertTrue(ScanLock::acquire_batch_lock(909, $token), 'Scan owner must be able to acquire batch lock.');

        ScanLock::release_batch_lock();

        // Release batch queries should be present
        $releasedQueries = array_filter(
            $GLOBALS['wpdb']->queries,
            static fn(string $q) => str_contains($q, 'webcareproscan_scan_batch_mutex')
        );
        $this->assertNotEmpty($releasedQueries, 'Must release batch advisory lock.');
    }

    public function testBatchLockRejectsWhenActiveLeaseNotHeld(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        // No parent scan lock acquired
        $this->assertFalse(
            ScanLock::acquire_batch_lock(999, 'unacquired_token'),
            'Batch lock must be rejected when active scan lease is not held.'
        );
    }

    public function testFailsClosedWhenLeasePersistenceFails(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        // Simulate corrupted persistence state where get_option returns empty array
        add_filter('pre_option_' . ScanLock::LOCK_OPTION, static fn() => []);

        $acquired = ScanLock::acquire(1234);
        $this->assertFalse($acquired, 'acquire() must return false if persisted lease verification fails.');

        $releasedQueries = array_filter(
            $GLOBALS['wpdb']->queries,
            static fn(string $q) => str_contains($q, 'RELEASE_LOCK')
        );
        $this->assertNotEmpty($releasedQueries, 'Must release advisory lock if lease persistence fails.');

        remove_all_filters('pre_option_' . ScanLock::LOCK_OPTION);
    }

    public function testBatchLockAndReleaseWithLeaseToken(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->assertTrue(ScanLock::acquire(555));
        $token = ScanLock::get_active_lease_token(555);
        $this->assertNotEmpty($token);

        // Verify ownership matching on get_active_lease_token
        $this->assertNull(ScanLock::get_active_lease_token(99999), 'Mismatched scan ID must return null.');

        // Batch lock with valid token should succeed
        $this->assertTrue(ScanLock::acquire_batch_lock(555, $token));
        ScanLock::release_batch_lock();

        // Batch lock with invalid token should fail
        $this->assertFalse(ScanLock::acquire_batch_lock(555, 'bogus_token_xyz'));

        // Batch lock with empty token should fail
        $this->assertFalse(ScanLock::acquire_batch_lock(555, ''));

        // Release with invalid token should be rejected
        $this->assertFalse(ScanLock::release(555, 'bogus_token_xyz'));
        $this->assertSame(555, ScanLock::get_locked_scan_id(), 'Release with invalid token must preserve active lock.');

        // Release with empty token should be rejected
        $this->assertFalse(ScanLock::release(555, ''));
        $this->assertSame(555, ScanLock::get_locked_scan_id());

        // Release with valid token should succeed
        $this->assertTrue(ScanLock::release(555, $token));
        $this->assertNull(ScanLock::get_locked_scan_id(), 'Release with valid token must cleanly release lock.');
    }

    public function testForceReleaseClearsLockUnconditionally(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->assertTrue(ScanLock::acquire(777));
        $this->assertTrue(ScanLock::is_locked());

        $this->assertTrue(ScanLock::force_release(777));
        $this->assertFalse(ScanLock::is_locked());
        $this->assertNull(ScanLock::get_locked_scan_id());
    }

    public function testForceReleaseFailsClosedWhenAdvisoryLockFails(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;
        $this->assertTrue(ScanLock::acquire(888));

        // Advisory mutex acquisition fails
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 0;
        $this->assertFalse(ScanLock::force_release(888), 'force_release must return false when advisory mutex fails');
        $this->assertTrue(ScanLock::is_locked(), 'Option state must remain intact when force_release fails');
    }

    public function testBatchLockSerializesWorkersRecoversStaleLeaseAndEnforcesWorkerToken(): void {
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->assertTrue(ScanLock::acquire(606, 'gen_tok_606'));
        $worker1 = null;
        $this->assertTrue(ScanLock::acquire_batch_lock(606, 'gen_tok_606', $worker1));
        $this->assertNotEmpty($worker1);

        // Concurrent worker cannot acquire while batch heartbeat is active
        $worker2 = null;
        $this->assertFalse(ScanLock::acquire_batch_lock(606, 'gen_tok_606', $worker2));
        $this->assertNull($worker2);

        // Simulate worker crash + stranded persistent DB GET_LOCK(BATCH_LOCK_NAME) returning 0 after TTL expiry
        update_option(ScanLock::BATCH_LOCK_OPTION, [
            'scan_id'      => 606,
            'worker_token' => $worker1,
            'heartbeat_at' => time() - (ScanLock::BATCH_LOCK_TTL_SECONDS + 10),
        ], false);
        $GLOBALS['wpdb']->mock_get_var_callback = static function (string $q) {
            if (str_contains($q, ScanLock::BATCH_LOCK_NAME)) {
                return 0; // Stranded MySQL advisory lock on dead persistent connection
            }
            return 1;
        };

        $worker3 = null;
        $this->assertTrue(ScanLock::acquire_batch_lock(606, 'gen_tok_606', $worker3), 'Expired batch lease must recover cleanly even if persistent DB advisory lock was stranded.');
        $this->assertNotEmpty($worker3);
        $this->assertNotSame($worker1, $worker3);

        // Old worker calling release_batch_lock($worker1) must not revoke worker3's active lease
        ScanLock::release_batch_lock($worker1);
        $this->assertTrue(ScanLock::renew_batch_lock(606, (string) $worker3));

        // Active owner release clears the batch lock
        ScanLock::release_batch_lock($worker3);
        $this->assertFalse(get_option(ScanLock::BATCH_LOCK_OPTION));
    }
}
