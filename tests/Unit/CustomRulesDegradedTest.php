<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer;
use WebCareProScanner\System\AuditLogger;
use WebCareProScanner\System\SystemDoctor;

final class CustomRulesDegradedTest extends TestCase {
    #[\Override]
    protected function setUp(): void {
        parent::setUp();
        delete_transient('webcareproscan_custom_rules_degraded');
        delete_option(ModularFirewallSynthesizer::OPTION_RULES);
    }

    #[\Override]
    protected function tearDown(): void {
        AuditLogger::$operational_log_hook = null;
        delete_transient('webcareproscan_custom_rules_degraded');
        delete_option(ModularFirewallSynthesizer::OPTION_RULES);
        parent::tearDown();
    }

    public function test_has_active_blocking_rules_detects_enforce_block(): void {
        $this->assertFalse(ModularFirewallSynthesizer::has_active_blocking_rules());

        $rules = [
            [
                'id'           => 'custom_test_1',
                'category'     => 'custom',
                'action_type'  => 'block',
                'current_mode' => 'enforce',
            ],
        ];
        update_option(ModularFirewallSynthesizer::OPTION_RULES, $rules, false);

        $this->assertTrue(ModularFirewallSynthesizer::has_active_blocking_rules());
    }

    public function test_system_doctor_surfaces_custom_rules_degraded_warning(): void {
        // Without transient, status is pass
        $diagnostics = SystemDoctor::run_diagnostics();
        $check = null;
        foreach ($diagnostics['checks'] as $c) {
            if ($c['id'] === 'custom_rules_status') {
                $check = $c;
                break;
            }
        }
        $this->assertNotNull($check);
        $this->assertSame('pass', $check['status']);

        // Set degraded transient
        set_transient('webcareproscan_custom_rules_degraded', [
            'time'  => time(),
            'error' => 'Simulated syntax exception in custom rule AST',
        ], 900);

        $diagnosticsDegraded = SystemDoctor::run_diagnostics();
        $checkDegraded = null;
        foreach ($diagnosticsDegraded['checks'] as $c) {
            if ($c['id'] === 'custom_rules_status') {
                $checkDegraded = $c;
                break;
            }
        }
        $this->assertNotNull($checkDegraded);
        $this->assertSame('warn', $checkDegraded['status']);
        $this->assertStringContainsString('Simulated syntax exception in custom rule AST', $checkDegraded['message']);
    }
}
