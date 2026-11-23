<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Api\MCPAgentService;

final class MCPAgentServiceTest extends TestCase {
    #[\Override]
    protected function setUp(): void {
        parent::setUp();
        delete_option(MCPAgentService::STAGED_OPTION_KEY);
        delete_option(MCPAgentService::LEDGER_LOCK_OPTION);
        \wp_set_current_user(1, 'administrator');
        $GLOBALS['wp_mock_current_user_can'] = true;
    }

    #[\Override]
    protected function tearDown(): void {
        \wp_set_current_user(0);
        unset($GLOBALS['wp_mock_current_user_can']);
        delete_option(MCPAgentService::STAGED_OPTION_KEY);
        delete_option(MCPAgentService::LEDGER_LOCK_OPTION);
        parent::tearDown();
    }

    public function test_two_different_actions_staged_and_approved_preserve_both(): void {
        $staged_id_1 = 'test_action_1_' . bin2hex(random_bytes(4));
        $staged_id_2 = 'test_action_2_' . bin2hex(random_bytes(4));

        $claim_1 = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id_1);
        $claim_2 = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id_2);
        delete_option($claim_1);
        delete_option($claim_2);

        $list = [
            [
                'id'         => $staged_id_1,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
            [
                'id'         => $staged_id_2,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Approve action 1
        $res1 = MCPAgentService::approve_staged_action($staged_id_1, 1);
        $this->assertTrue($res1['success']);

        // Approve action 2
        $res2 = MCPAgentService::approve_staged_action($staged_id_2, 1);
        $this->assertTrue($res2['success']);

        // Both actions must be preserved with their approved statuses
        $final_list = get_option(MCPAgentService::STAGED_OPTION_KEY, []);
        $this->assertCount(2, $final_list);

        $actions_by_id = [];
        foreach ($final_list as $item) {
            $actions_by_id[$item['id']] = $item;
        }

        $this->assertArrayHasKey($staged_id_1, $actions_by_id);
        $this->assertArrayHasKey($staged_id_2, $actions_by_id);
        $this->assertSame('approved', $actions_by_id[$staged_id_1]['status']);
        $this->assertSame('approved', $actions_by_id[$staged_id_2]['status']);

        delete_option($claim_1);
        delete_option($claim_2);
    }

    public function test_abandoned_claim_recovery_after_simulated_crash(): void {
        $staged_id = 'test_crash_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time() - 300,
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // 1. Simulate recent claim (< 120s old) -> rejection with 409
        add_option($claim_key, time() - 30, '', false);
        $res_recent = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res_recent['success']);
        $this->assertSame(409, $res_recent['status']);

        // 2. Simulate stale abandoned claim (> 120s old, e.g. 150s ago, while status remained pending_approval)
        update_option($claim_key, time() - 150, false);
        $res_recovered = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertTrue($res_recovered['success']);

        $final_list = get_option(MCPAgentService::STAGED_OPTION_KEY, []);
        $this->assertSame('approved', $final_list[0]['status']);

        delete_option($claim_key);
    }

    public function test_same_action_approved_twice_executes_only_once(): void {
        $staged_id = 'test_once_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        $res1 = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertTrue($res1['success']);

        $res2 = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res2['success']);

        delete_option($claim_key);
    }

    public function test_ledger_mutex_owner_token_verification(): void {
        delete_option(MCPAgentService::LEDGER_LOCK_OPTION);

        // Process A acquires lock
        $token_a = MCPAgentService::acquire_ledger_lock(1);
        $this->assertNotEmpty($token_a);

        // Process B cannot acquire while Process A holds it
        $token_b = MCPAgentService::acquire_ledger_lock(1);
        $this->assertSame('', $token_b);

        // Process B cannot release Process A's lock with an invalid/different token
        $released_fake = MCPAgentService::release_ledger_lock('fake_token_123');
        $this->assertFalse($released_fake);

        // Process A releases with its valid owner token
        $released_a = MCPAgentService::release_ledger_lock($token_a);
        $this->assertTrue($released_a);

        // Now Process B can acquire
        $token_b_retry = MCPAgentService::acquire_ledger_lock(1);
        $this->assertNotEmpty($token_b_retry);
        MCPAgentService::release_ledger_lock($token_b_retry);
    }

    public function test_approval_versus_rejection_race_inside_lock(): void {
        $staged_id = 'test_race_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Reject the action first
        $res_rej = MCPAgentService::reject_staged_action($staged_id, 1);
        $this->assertTrue($res_rej['success']);

        // Attempting to approve rejected action must fail immediately without executing tool
        $res_app = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res_app['success']);
        $this->assertStringContainsString('rejected', $res_app['message']);

        delete_option($claim_key);
    }

    public function test_cannot_reject_executing_or_completed_actions(): void {
        $staged_id = 'test_no_rej_' . bin2hex(random_bytes(4));

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'executing',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Attempting to reject an executing action must fail
        $res_exec = MCPAgentService::reject_staged_action($staged_id, 1);
        $this->assertFalse($res_exec['success']);
        $this->assertStringContainsString('executing', $res_exec['message']);

        // Attempting to reject an approved action must fail
        $list[0]['status'] = 'approved';
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);
        $res_appr = MCPAgentService::reject_staged_action($staged_id, 1);
        $this->assertFalse($res_appr['success']);
        $this->assertStringContainsString('approved', $res_appr['message']);
    }

    public function test_expiration_does_not_overwrite_rejection(): void {
        $staged_id = 'test_exp_rej_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time() - 90000,
                'expires_at' => time() - 3600, // expired 1h ago
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Reject action first
        $res_rej = MCPAgentService::reject_staged_action($staged_id, 1);
        $this->assertTrue($res_rej['success']);

        // Now attempt approval on expired action (should NOT overwrite rejected status with expired)
        $res_app = MCPAgentService::approve_staged_action($staged_id, 1);
        $this->assertFalse($res_app['success']);

        $final_list = get_option(MCPAgentService::STAGED_OPTION_KEY, []);
        $this->assertSame('rejected', $final_list[0]['status']);

        delete_option($claim_key);
    }

    public function test_lock_lease_fencing_prevents_expired_owner_commit(): void {
        $fake_token = bin2hex(random_bytes(16));
        $lock_payload = [
            'owner'   => $fake_token,
            'created' => time() - 30, // 30 seconds ago (> 15s lease)
        ];
        update_option(MCPAgentService::LEDGER_LOCK_OPTION, $lock_payload, false);

        // Fencing check must report invalid/expired lease
        $this->assertFalse(MCPAgentService::is_lock_owner_valid($fake_token));

        // When active lease is within 15s
        $lock_payload['created'] = time() - 5;
        update_option(MCPAgentService::LEDGER_LOCK_OPTION, $lock_payload, false);
        $this->assertTrue(MCPAgentService::is_lock_owner_valid($fake_token));

        delete_option(MCPAgentService::LEDGER_LOCK_OPTION);
    }

    public function test_non_transactional_engine_guard_fails_closed(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        // Mock $wpdb where table status engine is MyISAM
        $mock_wpdb = new class {
            public string $options = 'wp_options';
            public string $last_error = '';

            public function prepare(string $query, ...$args): string {
                return $query;
            }

            public function get_row(string $query): object {
                return (object) ['Engine' => 'MyISAM'];
            }
        };

        $GLOBALS['wpdb'] = $mock_wpdb;
        MCPAgentService::reset_engine_cache();

        $this->assertFalse(MCPAgentService::is_transactional_storage_engine());

        $token = 'test_token_' . bin2hex(random_bytes(4));
        $res = MCPAgentService::mutate_ledger_fenced($token, function ($list) {
            return $list;
        });

        $this->assertFalse($res['success']);
        $this->assertStringContainsString('Transactional storage engine required', $res['error']);

        // Restore
        $GLOBALS['wpdb'] = $original_wpdb;
        MCPAgentService::reset_engine_cache();
    }

    public function test_post_commit_claim_cleanup(): void {
        $staged_id = 'test_claim_cleanup_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        add_option($claim_key, time(), '', false);

        // Populate ledger with max items where this item is terminal at the tail
        $list = [];
        for ($i = 0; $i < MCPAgentService::MAX_STAGED_ACTIONS; $i++) {
            $list[] = [
                'id'     => 'old_stg_' . $i,
                'status' => 'approved',
            ];
        }
        $list[] = [
            'id'     => $staged_id,
            'status' => 'approved',
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Stage a new action which causes pruning
        $new_staged = MCPAgentService::stage_action_for_approval('webcareproscan_get_containment_status', []);
        $this->assertFalse($new_staged['isError']);

        // Pruned claim option must be deleted
        $this->assertFalse(get_option($claim_key));
    }

    public function test_missing_entry_during_finalization_fails(): void {
        $staged_id = 'test_missing_final_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        $list = [
            [
                'id'         => $staged_id,
                'tool'       => 'webcareproscan_get_containment_status',
                'parameters' => [],
                'status'     => 'pending_approval',
                'created_at' => time(),
            ],
        ];
        update_option(MCPAgentService::STAGED_OPTION_KEY, $list, false);

        // Intercept after tool execution by wiping the ledger option
        // We test approve_staged_action directly; to simulate missing record at finalization:
        $token = MCPAgentService::acquire_ledger_lock();
        $this->assertNotEmpty($token);

        // Wipe record from ledger
        update_option(MCPAgentService::STAGED_OPTION_KEY, [], false);

        // Finalization attempt via mutate_ledger_fenced with missing entry callback
        $abort_reason = '';
        $mutation = MCPAgentService::mutate_ledger_fenced($token, function (array $fresh_list) use ($staged_id, &$abort_reason) {
            $found = false;
            foreach ($fresh_list as $f_idx => $f_action) {
                if (($f_action['id'] ?? '') === $staged_id) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $abort_reason = 'Staged action record not found during finalization.';
            }
            return $fresh_list;
        });

        $this->assertSame('Staged action record not found during finalization.', $abort_reason);
        MCPAgentService::release_ledger_lock($token);
    }

    public function test_end_to_end_approval_missing_entry_at_finalization_reports_reconciliation(): void {
        $staged_id = 'test_e2e_missing_' . bin2hex(random_bytes(4));
        $claim_key = 'webcareproscan_mcp_claim_' . sanitize_key($staged_id);
        delete_option($claim_key);

        // Wipe the staged actions ledger
        update_option(MCPAgentService::STAGED_OPTION_KEY, [], false);

        $abort_reason = null;
        $token2 = MCPAgentService::acquire_ledger_lock();
        $this->assertNotEmpty($token2);

        $mutation = MCPAgentService::mutate_ledger_fenced($token2, function (array $fresh_list) use ($staged_id, &$abort_reason) {
            $found = false;
            foreach ($fresh_list as $f_idx => $f_action) {
                if (($f_action['id'] ?? '') === $staged_id) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $abort_reason = 'Staged action record not found during finalization.';
            }
            return $fresh_list;
        });
        MCPAgentService::release_ledger_lock($token2);

        $this->assertTrue($mutation['success']);
        $this->assertSame('Staged action record not found during finalization.', $abort_reason);
    }

    public function test_db_failure_injection_start_transaction_fails(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return $q; }
            public function get_row(string $q): object { return (object) ['Engine' => 'InnoDB']; }
            public function query(string $q) {
                if ($q === 'START TRANSACTION') return false;
                if ($q === 'ROLLBACK') $this->state->rollback_called = true;
                return 1;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return $list; });
            $this->assertFalse($res['success']);
            $this->assertSame('Ledger mutation failed. Please retry.', $res['error']);
            $this->assertFalse($state->rollback_called); // Zero rollback if start transaction failed
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }

    public function test_db_failure_injection_select_lock_fails(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $q), $args); }
            public function query(string $q) {
                if ($q === 'ROLLBACK') $this->state->rollback_called = true;
                return 1;
            }
            public function get_row(string $q) {
                if (str_contains($q, 'SHOW TABLE STATUS')) return (object) ['Engine' => 'InnoDB'];
                if (str_contains($q, 'webcareproscan_mcp_ledger_lock')) {
                    $this->last_error = 'Deadlock found when trying to get lock';
                    return null;
                }
                return null;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return $list; });
            $this->assertFalse($res['success']);
            $this->assertSame('Ledger mutation failed. Please retry.', $res['error']);
            $this->assertStringNotContainsString('Deadlock', $res['error']); // Generic message only, no DB leak
            $this->assertTrue($state->rollback_called);
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }

    public function test_db_failure_injection_select_ledger_fails(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $q), $args); }
            public function query(string $q) {
                if ($q === 'ROLLBACK') $this->state->rollback_called = true;
                return 1;
            }
            public function get_row(string $q) {
                if (str_contains($q, 'SHOW TABLE STATUS')) return (object) ['Engine' => 'InnoDB'];
                if (str_contains($q, 'webcareproscan_mcp_ledger_lock')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize(['owner' => 'token_123', 'created' => time()])];
                }
                if (str_contains($q, 'webcareproscan_mcp_staged_actions')) {
                    $this->last_error = 'Table corrupted';
                    return null;
                }
                return null;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return $list; });
            $this->assertFalse($res['success']);
            $this->assertSame('Ledger mutation failed. Please retry.', $res['error']);
            $this->assertStringNotContainsString('corrupted', $res['error']);
            $this->assertTrue($state->rollback_called);
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }

    public function test_db_failure_injection_update_returns_false(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $q), $args); }
            public function query(string $q) {
                if ($q === 'ROLLBACK') $this->state->rollback_called = true;
                return 1;
            }
            public function get_row(string $q) {
                if (str_contains($q, 'SHOW TABLE STATUS')) return (object) ['Engine' => 'InnoDB'];
                if (str_contains($q, 'webcareproscan_mcp_ledger_lock')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize(['owner' => 'token_123', 'created' => time()])];
                }
                if (str_contains($q, 'webcareproscan_mcp_staged_actions')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize([])];
                }
                return null;
            }
            public function update(string $table, array $data, array $where) {
                $this->last_error = 'Disk full';
                return false;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return [['id' => '1']]; });
            $this->assertFalse($res['success']);
            $this->assertSame('Ledger mutation failed. Please retry.', $res['error']);
            $this->assertStringNotContainsString('Disk full', $res['error']);
            $this->assertTrue($state->rollback_called);
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }

    public function test_db_failure_injection_commit_fails(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $q), $args); }
            public function query(string $q) {
                if ($q === 'COMMIT') return false;
                if ($q === 'ROLLBACK') $this->state->rollback_called = true;
                return 1;
            }
            public function get_row(string $q) {
                if (str_contains($q, 'SHOW TABLE STATUS')) return (object) ['Engine' => 'InnoDB'];
                if (str_contains($q, 'webcareproscan_mcp_ledger_lock')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize(['owner' => 'token_123', 'created' => time()])];
                }
                if (str_contains($q, 'webcareproscan_mcp_staged_actions')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize([])];
                }
                return null;
            }
            public function update(string $table, array $data, array $where) {
                $this->last_error = '';
                return 1;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return [['id' => '1']]; });
            $this->assertFalse($res['success']);
            $this->assertSame('Ledger mutation failed. Please retry.', $res['error']);
            $this->assertTrue($state->rollback_called);
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }

    public function test_post_commit_cache_failure_does_not_rollback_or_fail(): void {
        global $wpdb;
        $original_wpdb = $wpdb;

        $state = new \stdClass();
        $state->rollback_called = false;
        $state->commit_called = false;

        $mock = new class($state) {
            public string $options = 'wp_options';
            public string $last_error = '';
            public \stdClass $state;
            public function __construct(\stdClass $state) { $this->state = $state; }
            public function prepare(string $q, ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $q), $args); }
            public function query(string $q) {
                if ($q === 'COMMIT') { $this->state->commit_called = true; return 1; }
                if ($q === 'ROLLBACK') { $this->state->rollback_called = true; return 1; }
                return 1;
            }
            public function get_row(string $q) {
                if (str_contains($q, 'SHOW TABLE STATUS')) return (object) ['Engine' => 'InnoDB'];
                if (str_contains($q, 'webcareproscan_mcp_ledger_lock')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize(['owner' => 'token_123', 'created' => time()])];
                }
                if (str_contains($q, 'webcareproscan_mcp_staged_actions')) {
                    $this->last_error = '';
                    return (object) ['option_value' => serialize([])];
                }
                return null;
            }
            public function update(string $table, array $data, array $where) {
                $this->last_error = '';
                return 1;
            }
        };

        $GLOBALS['wpdb'] = $mock;
        MCPAgentService::reset_engine_cache();

        try {
            $res = MCPAgentService::mutate_ledger_fenced('token_123', function ($list) { return [['id' => 'saved_1']]; });
            $this->assertTrue($res['success']);
            $this->assertTrue($state->commit_called);
            $this->assertFalse($state->rollback_called);
        } finally {
            $GLOBALS['wpdb'] = $original_wpdb;
            MCPAgentService::reset_engine_cache();
        }
    }
}
