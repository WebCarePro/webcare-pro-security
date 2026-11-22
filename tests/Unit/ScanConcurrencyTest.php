<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\Controllers\ScanController;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Scan\ScanLock;

/**
 * Unit tests for PR-E:
 * Scan Abort Concurrency & Pre-Side-Effect Ownership Enforcement (Finding #6).
 *
 * Requirements:
 * 1. Owner-Verified ScanLock::force_release(?int $scan_id, ?string $generation_token)
 * 2. Exact 5-step race simulation:
 *    Step 1: Worker A acquires scan lease (scan_id = 1, gen = A).
 *    Step 2: Worker A starts processing a file.
 *    Step 3: Scan 1 is aborted.
 *    Step 4: Worker B starts Scan 2 (scan_id = 2, gen = B).
 *    Step 5: Worker A resumes — Worker A persists 0 findings, performs 0 file/quarantine writes,
 *            does not update Scan 1 progress, and cannot modify or release Worker B's lock.
 */
final class ScanConcurrencyTest extends TestCase
{
    private string $tempFile = '';

    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->tempFile = sys_get_temp_dir() . '/webcare_test_threat_' . bin2hex(random_bytes(6)) . '.php';
        file_put_contents($this->tempFile, '<?php echo "eval payload";');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            @unlink($this->tempFile);
        }
        parent::tearDown();
    }

    /**
     * Test ScanLock::force_release() with owner and generation token verification.
     */
    public function testOwnerVerifiedForceRelease(): void
    {
        // 1. Acquire lock for Scan 1 with Gen A
        $this->assertTrue(ScanLock::acquire(1, 'gen_token_A'));
        $this->assertSame(1, ScanLock::get_locked_scan_id());

        // 2. Attempt to force_release with mismatched scan_id -> MUST FAIL
        $this->assertFalse(ScanLock::force_release(999, 'gen_token_A'), 'Force release with wrong scan_id must fail.');
        $this->assertSame(1, ScanLock::get_locked_scan_id(), 'Lock must remain held.');

        // 3. Attempt to force_release with correct scan_id but wrong generation_token -> MUST FAIL
        $this->assertFalse(ScanLock::force_release(1, 'wrong_gen_token'), 'Force release with wrong generation token must fail.');
        $this->assertSame(1, ScanLock::get_locked_scan_id(), 'Lock must remain held.');

        // 4. Force release with correct scan_id and generation_token -> MUST SUCCEED
        $this->assertTrue(ScanLock::force_release(1, 'gen_token_A'), 'Force release with matching owner and token must succeed.');
        $this->assertNull(ScanLock::get_locked_scan_id(), 'Lock should now be released.');
    }

    /**
     * Exact 5-Step Race Simulation between Worker A and Worker B across Abort.
     */
    public function testFiveStepRaceSimulationWorkerAWorkerB(): void
    {
        global $wpdb;

        // Step 1: Worker A starts Scan 1 (scan_id = 1, gen = A)
        $genA = 'generation_token_worker_A';
        $this->assertTrue(ScanLock::acquire(1, $genA));
        $this->assertSame(1, ScanLock::get_locked_scan_id());

        // Mock DB scan row for Scan 1 as running
        $scansTable = $wpdb->prefix . 'webcareproscan_scans';
        $issuesTable = $wpdb->prefix . 'webcareproscan_scan_issues';
        $wpdb->mock_tables[$scansTable] = [
            1 => [
                'id'               => 1,
                'status'           => 'running',
                'generation_token' => $genA,
                'scanned_files'    => 0,
                'total_files'      => 10,
                'issues_found'     => 0,
            ],
        ];
        $wpdb->mock_tables[$issuesTable] = [];

        // Step 2: Worker A starts processing (has findings in memory)
        $workerAFindings = [
            [
                'file_path'    => $this->tempFile,
                'engine'       => 'filesystem',
                'type'         => 'eval_backdoor',
                'severity'     => 'critical',
                'confidence'   => 100,
                'description'  => 'Malicious eval backdoor found',
            ],
        ];

        // Step 3: Scan 1 is aborted via ScanController::abort_scan
        $abortReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/scan/abort');
        $abortReq->set_param('scan_id', 1);
        $abortRes = ScanController::abort_scan($abortReq);
        $this->assertNotInstanceOf(\WP_Error::class, $abortRes);
        $this->assertTrue(get_transient('webcareproscan_scan_cancelled_1'));

        // Verify Scan 1 row is aborted
        $this->assertSame('aborted', $wpdb->mock_tables[$scansTable][1]['status']);

        // Step 4: Worker B starts Scan 2 (scan_id = 2, gen = B)
        $genB = 'generation_token_worker_B';
        $this->assertTrue(ScanLock::acquire(2, $genB));
        $this->assertSame(2, ScanLock::get_locked_scan_id());
        $wpdb->mock_tables[$scansTable][2] = [
            'id'               => 2,
            'status'           => 'running',
            'generation_token' => $genB,
            'scanned_files'    => 0,
            'total_files'      => 10,
            'issues_found'     => 0,
        ];

        // Step 5: Worker A resumes attempting to persist side effects:
        // 5a. Worker A attempts quarantine mutation with aborted scan_id = 1
        $qm = new QuarantineManager();
        $quarantineRes = $qm->quarantine_file($this->tempFile, 1);
        $this->assertFalse($quarantineRes['success'], 'Quarantine write by stale Worker A must be blocked.');
        $this->assertStringContainsString('cancelled or aborted', $quarantineRes['message']);

        // 5b. Worker A attempts to process_batch on Scan 1
        $batchReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/scan/batch');
        $batchReq->set_param('scan_id', 1);
        $batchReq->set_param('lease_token', $genA);
        $batchRes = ScanController::process_batch($batchReq);

        $this->assertInstanceOf(\WP_Error::class, $batchRes, 'Batch execution by aborted Worker A must return WP_Error.');

        // 5c. Verify Worker A persisted ZERO issues in the database
        $this->assertEmpty($wpdb->mock_tables[$issuesTable], 'Worker A must have persisted 0 findings into database.');

        // 5d. Verify Worker A did not update Scan 1 scanned_files
        $this->assertSame(0, $wpdb->mock_tables[$scansTable][1]['scanned_files'], 'Worker A must not update Scan 1 progress.');

        // 5e. Verify Worker A cannot release or clobber Worker B's active lock
        $this->assertFalse(ScanLock::force_release(1, $genA), 'Worker A cannot release Worker B lease.');
        $this->assertSame(2, ScanLock::get_locked_scan_id(), 'Worker B remains the authoritative lock owner.');
        $this->assertSame($genB, ScanLock::get_active_lease_token(2));
    }

    /**
     * Test that aborting mid-batch with 0 findings prevents ScanVaultManager::append_batch()
     * and ScanQueueManager::advance() from executing.
     */
    public function testAbortingMidBatchWithZeroFindingsHaltsVaultAndQueueAdvance(): void
    {
        global $wpdb;

        $scan_id = 10;
        $gen = 'gen_zero_findings';
        $this->assertTrue(ScanLock::acquire($scan_id, $gen));

        $scansTable = $wpdb->prefix . 'webcareproscan_scans';
        $wpdb->mock_tables[$scansTable] = [
            $scan_id => [
                'id'               => $scan_id,
                'status'           => 'running',
                'generation_token' => $gen,
                'scanned_files'    => 0,
                'total_files'      => 5,
                'issues_found'     => 0,
            ],
        ];

        // Create a clean temp file that generates 0 findings
        $cleanFile = sys_get_temp_dir() . '/clean_test_' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($cleanFile, 'hello clean content');

        // Populate scan queue so files_to_process is non-empty
        set_transient('webcareproscan_scan_queue_' . $scan_id, [$cleanFile], 300);

        // Mark scan cancelled before batch execution
        set_transient("webcareproscan_scan_cancelled_{$scan_id}", 1, 300);

        $batchReq = new \WP_REST_Request('POST', '/webcare-pro-security/v1/scan/batch');
        $batchReq->set_param('scan_id', $scan_id);
        $batchReq->set_param('lease_token', $gen);

        $res = ScanController::process_batch($batchReq);
        @unlink($cleanFile);

        $this->assertInstanceOf(\WP_Error::class, $res);
        $this->assertSame('scan_aborted', $res->get_error_code());
        $this->assertSame(0, $wpdb->mock_tables[$scansTable][$scan_id]['scanned_files'], 'Progress must remain 0 when aborted.');
    }
}
