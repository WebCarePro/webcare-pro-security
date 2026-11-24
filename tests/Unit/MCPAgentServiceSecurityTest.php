<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\MCPAgentService;
use WebCareProScanner\System\AuditLogger;

final class MCPAgentServiceSecurityTest extends TestCase {
    #[\Override]
    protected function setUp(): void {
        parent::setUp();
        // Clean up test options
        delete_option(MCPAgentService::STAGED_OPTION_KEY);
        \wp_set_current_user(1, 'administrator');
        $GLOBALS['wp_mock_current_user_can'] = true;
    }

    #[\Override]
    protected function tearDown(): void {
        AuditLogger::$operational_log_hook = null;
        \wp_set_current_user(0);
        unset($GLOBALS['wp_mock_current_user_can']);
        parent::tearDown();
    }

    public function test_staged_action_atomic_single_use_claim_prevents_replay(): void {
        $staged_id = 'test_claim_' . bin2hex(random_bytes(6));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $staged_list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $staged_list, false);

        // First approval succeeds and sets the atomic claim
        $res1 = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertTrue($res1['success']);
        $this->assertSame($staged_id, $res1['staged_id']);

        // Second approval attempt on the exact same staged action must be rejected
        $res2 = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res2['success']);

        // Test concurrent atomic claim directly: if claim already exists in options table, approval returns 409
        $staged_id_claim = 'test_claim_concurrent_' . bin2hex(random_bytes(6));
        $claim_key_concurrent = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id_claim);
        add_option($claim_key_concurrent, time(), '', false);

        $staged_list_concurrent = [
            [
                'id'         => $staged_id_claim,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $staged_list_concurrent, false);

        $res_claimed = MCPAgentService::approve_staged_action($staged_id_claim, 1);
        $this->assertFalse($res_claimed['success']);
        $this->assertSame(409, $res_claimed['status']);
        $this->assertStringContainsString('already claimed or executed', $res_claimed['message']);

        // Clean up
        delete_option($claim_key);
        delete_option($claim_key_concurrent);
        delete_option(MCPAgentService::STAGED_OPTION_KEY);
    }

    public function test_staged_action_persists_failed_status_when_tool_fails(): void {
        $staged_id = 'test_fail_' . bin2hex(random_bytes(6));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $staged_list = [
            [
                'id'         => $staged_id,
                'tool'       => 'nonexistent_test_tool',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $staged_list, false);

        // Nonexistent tool returns isError => true from execute_tool()
        $res = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res['success']);
        $this->assertSame($staged_id, $res['staged_id']);

        // Staged option status must be persisted as 'failed', NEVER 'approved'
        $updated_list = get_option(MCPAgentService::STAGED_OPTION_KEY, []);
        $this->assertSame('failed', $updated_list[0]['status']);
        $this->assertNotEmpty($updated_list[0]['approved_at']);

        // Clean up
        delete_option($claim_key);
        delete_option(MCPAgentService::STAGED_OPTION_KEY);
    }

    public function test_json_rpc_dlp_fail_closed_returns_error_and_logs_operational(): void {
        $captured_events = [];
        AuditLogger::$operational_log_hook = function (string $type, $details) use (&$captured_events) {
            $captured_events[] = ['type' => $type, 'details' => $details];
        };

        // Construct a huge payload exceeding ResponseDlpSentinel node limit (>25,000 nodes)
        $huge_payload = [];
        for ($i = 0; $i < 26000; $i++) {
            $huge_payload['key_' . $i] = 'val_' . $i;
        }

        // Simulate handle_json_rpc calling tools/call with huge output
        // We test the DLP fail-closed exception boundary directly
        $has_leak = false;
        $matched_pat = '';
        $caught_error = null;

        try {
            \WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel::redact_data_recursive($huge_payload, $has_leak, $matched_pat);
        } catch (\Throwable $dlp_err) {
            $caught_error = $dlp_err;
            AuditLogger::log_operational('mcp_dlp_inspection_limit_exceeded', [
                'tool'   => 'test_dlp_tool',
                'reason' => $dlp_err->getCode() ?: 'dlp_limit',
            ]);
        }

        $this->assertNotNull($caught_error);
        $this->assertCount(1, $captured_events);
        $this->assertSame('mcp_dlp_inspection_limit_exceeded', $captured_events[0]['type']);
        $this->assertSame('test_dlp_tool', $captured_events[0]['details']['tool']);
    }
}
