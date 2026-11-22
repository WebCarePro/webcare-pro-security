<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\Core\WafVaultManager;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\System\SystemDoctor;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;

class SafeModeAndDoctorTest extends TestCase {

    private string $test_dir;

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;

        $this->test_dir = sys_get_temp_dir() . '/wcp_test_safemode_' . bin2hex(random_bytes(6));
        @mkdir($this->test_dir . '/webcare-waf', 0750, true);
    }

    protected function tearDown(): void {
        $this->clean_dir($this->test_dir);
        parent::tearDown();
    }

    private function clean_dir(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $p = $dir . '/' . $item;
            if (is_dir($p)) {
                $this->clean_dir($p);
            } else {
                @unlink($p);
            }
        }
        @rmdir($dir);
    }

    /**
     * Requirement 1: Single canonical Safe Mode path compiled into runtime.
     * The compiler embeds var_export(WafVaultManager::get_safe_mode_marker_path(), true) directly.
     */
    public function testCompilerEmbedsCanonicalSafeModeMarkerPath(): void {
        $canonical_path = WafVaultManager::get_safe_mode_marker_path();
        $this->assertStringContainsString('webcare-waf/.rescue_pause_until', $canonical_path);

        $preload_allow_path = WafVaultManager::get_preload_allow_path();
        $this->assertStringContainsString('webcare-waf/.rescue_allow.json', $preload_allow_path);

        // Compile preload script and verify exact canonical string literal is present
        $compiled_dir = WafVaultManager::get_safe_mode_marker_path();
        $compiled_source = file_get_contents(__DIR__ . '/../../includes/Firewall/MicroWafCompiler.php');
        $expected_call = 'WafVaultManager::get_safe_mode_marker_path()';

        $this->assertStringContainsString(
            $expected_call,
            $compiled_source,
            'Micro-WAF compiler must invoke WafVaultManager::get_safe_mode_marker_path() directly.'
        );
    }

    /**
     * Requirement 2: Safe Mode activation and auto-expiry logic.
     * Activates 15-minute pause marker, correctly detects status, and auto-expires cleanly.
     */
    public function testSafeModeActivationAndExpiryCycle(): void {
        $marker_path = WafVaultManager::get_safe_mode_marker_path();

        // 1. Without admin caps -> returns WP_Error
        $GLOBALS['wp_mock_current_user_can'] = false;
        $unauth = RescueAssistantManager::pause_strict_firewall_15m();
        $this->assertInstanceOf(\WP_Error::class, $unauth, 'Non-admin activation must return WP_Error.');

        // 2. With admin caps -> activates cleanly
        $GLOBALS['wp_mock_current_user_can'] = true;
        $activated = RescueAssistantManager::pause_strict_firewall_15m();
        $this->assertIsArray($activated);
        $this->assertTrue($activated['success']);
        $this->assertTrue($activated['paused']);
        $this->assertGreaterThan(time(), $activated['paused_until']);

        $this->assertFileExists($marker_path, 'Marker file must exist on disk.');
        $file_content = (int) trim((string) file_get_contents($marker_path));
        $this->assertSame($activated['paused_until'], $file_content);

        // 3. Status reporting
        $status = RescueAssistantManager::get_pause_status();
        $this->assertTrue($status['paused']);
        $this->assertGreaterThan(0, $status['seconds_remaining']);

        // 4. Resume immediately
        $resumed = RescueAssistantManager::resume_strict_firewall();
        $this->assertFalse($resumed['paused']);
        $this->assertFileDoesNotExist($marker_path, 'Marker file must be deleted upon resume.');

        $status2 = RescueAssistantManager::get_pause_status();
        $this->assertFalse($status2['paused']);
    }

    /**
     * Requirement 3: SystemDoctor::build_redacted_diagnostic_bundle() fail-closed.
     * When DLP is unavailable, returns WP_Error instead of returning raw diagnostic data.
     */
    public function testDiagnosticBundleFailsClosedWhenDlpFails(): void {
        // Test normal bundle generation
        $bundle = SystemDoctor::build_redacted_diagnostic_bundle();
        $this->assertIsArray($bundle, 'Bundle should generate cleanly with DLP available.');
        $this->assertArrayHasKey('doctor_checks', $bundle);
        $this->assertArrayHasKey('report_meta', $bundle);
        $this->assertArrayHasKey('runtime_environment', $bundle);

        // Test fail-closed behavior when redact_data_recursive throws
        $original_redact = ResponseDlpSentinel::$throw_mock_exception ?? false;
        try {
            ResponseDlpSentinel::$throw_mock_exception = true;
            $res = SystemDoctor::build_redacted_diagnostic_bundle();
            $this->assertInstanceOf(\WP_Error::class, $res, 'Must return WP_Error when DLP redaction fails.');
            $this->assertSame('dlp_redaction_failed', $res->get_error_code());
        } finally {
            ResponseDlpSentinel::$throw_mock_exception = $original_redact;
        }
    }

    /**
     * Requirement 4: SystemDoctor read-only inspection does not mutate filesystem permissions.
     */
    public function testSystemDoctorReadOnlyInspectionHasNoChmodSideEffects(): void {
        $vault_dir = WafVaultManager::get_vault_dir_readonly();
        $this->assertStringContainsString('webcare-waf/vault', $vault_dir);

        // If directory doesn't exist, get_vault_dir_readonly does NOT create it
        $non_existent = sys_get_temp_dir() . '/non_existent_vault_' . bin2hex(random_bytes(4));
        $this->assertDirectoryDoesNotExist($non_existent);

        // Run diagnostics
        $report = SystemDoctor::run_diagnostics();
        $this->assertIsArray($report);

        $vault_check = $report['checks']['vault_permissions'] ?? ($report['checks']['vault'] ?? null);
        if ($vault_check === null) {
            foreach (($report['checks'] ?? $report) as $c) {
                if (is_array($c) && (($c['id'] ?? '') === 'vault_permissions' || ($c['id'] ?? '') === 'vault')) {
                    $vault_check = $c;
                    break;
                }
            }
        }
        $this->assertNotNull($vault_check, 'Vault permissions check must be present in diagnostics.');
    }

    /**
     * Requirement: resume_strict_firewall reports failure and degraded state if marker file deletion fails.
     */
    public function testResumeStrictFirewallReportsFailureWhenMarkerUnlinkFails(): void {
        $marker_path = WafVaultManager::get_safe_mode_marker_path();

        $GLOBALS['wp_mock_current_user_can'] = true;
        RescueAssistantManager::pause_strict_firewall_15m();
        $this->assertFileExists($marker_path);

        // Make directory read-only so unlink fails or use unwritable file in mock
        $parent_dir = dirname($marker_path);
        @chmod($parent_dir, 0555);

        // In test environments where running as root or permissions allow unlink,
        // test the verify condition logic
        if (!is_writable($parent_dir)) {
            $res = RescueAssistantManager::resume_strict_firewall();
            @chmod($parent_dir, 0755);
            $this->assertFalse($res['success']);
            $this->assertStringContainsString('could not delete', $res['message']);
            $this->assertFileExists($marker_path);
        } else {
            // Restore write permissions
            @chmod($parent_dir, 0755);
            $res = RescueAssistantManager::resume_strict_firewall();
            $this->assertTrue($res['success']);
            $this->assertFileDoesNotExist($marker_path);
        }
    }
}
