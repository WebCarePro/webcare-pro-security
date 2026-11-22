<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer;
use WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer;

class CloudflareSyncTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;
        CloudflareService::$mock_request_handler = null;
    }

    protected function tearDown(): void {
        CloudflareService::$mock_request_handler = null;
        parent::tearDown();
    }

    /**
     * Requirement 1: Free-plan 5-rule phase with 1 existing customer rule yields slot_budget = 3
     * (leaving 1 free owner slot: 5 total - 1 owner reserve - 1 customer rule = 3 WebCare slots).
     */
    public function testSlotBudgetReservesOwnerSlotAndPreservesCustomerRules(): void {
        $optimizer = new CloudflareSlotOptimizer();

        // 1 customer rule present
        $existing_rules = [
            [
                'id'          => 'cust-rule-001',
                'description' => 'Customer Custom Allow Admin',
                'action'      => 'allow',
                'expression'  => '(ip.src eq 1.2.3.4)',
            ],
        ];

        // 5 - 1 (reserve) - 1 (customer) = 3 available for WebCare
        $budget = $optimizer->calculate_webcare_slot_budget($existing_rules);
        $this->assertSame(3, $budget, 'Budget must be exactly 3 when 1 customer rule exists.');

        // 2 customer rules present -> 5 - 1 - 2 = 2
        $existing_rules[] = [
            'id'          => 'cust-rule-002',
            'description' => 'Customer Custom Block Country',
            'action'      => 'block',
            'expression'  => '(ip.geoip.country eq "XX")',
        ];
        $budget2 = $optimizer->calculate_webcare_slot_budget($existing_rules);
        $this->assertSame(2, $budget2, 'Budget must be 2 when 2 customer rules exist.');

        // 4 customer rules present -> 5 - 1 - 4 = 0 available slots
        $existing_rules[] = ['id' => 'cust-rule-003', 'description' => 'Rule 3'];
        $existing_rules[] = ['id' => 'cust-rule-004', 'description' => 'Rule 4'];
        $budget0 = $optimizer->calculate_webcare_slot_budget($existing_rules);
        $this->assertSame(0, $budget0, 'Budget must be 0 when 4 customer rules exist.');
    }

    /**
     * Requirement 2: Strict ID-based ownership.
     * Customer rule whose description contains '[WebCare Pro]' but whose ID is not in
     * webcareproscan_cf_managed_rule_ids is treated as a customer rule and preserved untouched.
     */
    public function testStrictIdBasedOwnershipPreservesCustomerRuleWithWebCareDescription(): void {
        $optimizer = new CloudflareSlotOptimizer();

        // Store active managed rule IDs
        $managed_ids = ['wcp-rule-alpha', 'wcp-rule-beta'];
        update_option(CloudflareSlotOptimizer::OPTION_MANAGED_RULE_IDS, $managed_ids);

        // Rule with WebCare prefix in description, but customer-owned ID
        $customer_spoofed_desc = [
            'id'          => 'customer-rule-xyz',
            'description' => '[WebCare Pro] User Modified Copy',
            'action'      => 'block',
        ];

        $is_webcare = $optimizer->is_webcare_rule_entry(
            $customer_spoofed_desc['id'],
            $customer_spoofed_desc['description'],
            $managed_ids
        );

        $this->assertFalse(
            $is_webcare,
            'Rule with unmanaged ID must NOT be identified as WebCare-owned even if description matches prefix.'
        );

        $budget = $optimizer->calculate_webcare_slot_budget([$customer_spoofed_desc], $managed_ids);
        // 5 - 1 (reserve) - 1 (customer rule) = 3 slots
        $this->assertSame(3, $budget, 'Customer rule with unmanaged ID must be counted against customer slots.');
    }

    /**
     * Requirement 3: Skip action semantics & owner precedence.
     * Visual skip rules must use action='skip' with action_parameters.ruleset='current'.
     * Rule ordering must be: (1) Visual skip rules, (2) User custom rules, (3) WebCare rules, (4) Visual block rules.
     */
    public function testRuleOrderingAndSkipActionSemantics(): void {
        $optimizer = new CloudflareSlotOptimizer();

        $existing_rules = [
            [
                'id'          => 'visual-skip-01',
                'description' => '[WebCare-WAF] Custom Visual Bypass',
                'action'      => 'allow', // legacy allow should be converted to skip
                'expression'  => '(http.request.uri.path eq "/custom-webhook")',
            ],
            [
                'id'          => 'user-rule-01',
                'description' => 'Owner Custom Office IP',
                'action'      => 'allow',
                'expression'  => '(ip.src eq 198.51.100.1)',
            ],
            [
                'id'          => 'visual-block-01',
                'description' => '[WebCare-WAF] Visual Geo Block',
                'action'      => 'block',
                'expression'  => '(ip.geoip.country eq "CN")',
            ],
        ];

        $captured_payload = null;

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$captured_payload, $existing_rules): array {
            if (str_contains($endpoint, 'rulesets/phases/http_request_firewall_custom/entrypoint')) {
                if ($method === 'GET') {
                    return [
                        'success' => true,
                        'result'  => ['rules' => $existing_rules],
                    ];
                }
                if ($method === 'PUT') {
                    $captured_payload = $data;
                    return [
                        'success' => true,
                        'result'  => [
                            'rules' => array_map(static function (array $r, int $idx) {
                                $r['id'] = 'cf-gen-' . $idx;
                                return $r;
                            }, $data['rules'], array_keys($data['rules'])),
                        ],
                    ];
                }
            }
            return ['success' => true, 'result' => []];
        };

        $result = $optimizer->deploy_to_cloudflare('zone-test-123');

        $this->assertTrue($result['success'], 'Deploy must succeed with mock handler.');
        $this->assertNotNull($captured_payload, 'Payload must be sent to Cloudflare.');

        $final_rules = $captured_payload['rules'] ?? [];
        $this->assertNotEmpty($final_rules);

        // Verify True Owner Rule Precedence:
        // Index 0: user-rule-01 (owner rule placed FIRST so visual skip never skips owner rules)
        $this->assertSame('user-rule-01', $final_rules[0]['id']);

        // Index 1: visual-skip-01 (converted to action='skip' and ruleset='current')
        $this->assertSame('skip', $final_rules[1]['action']);
        $this->assertSame(['ruleset' => 'current'], $final_rules[1]['action_parameters']);
        $this->assertSame('visual-skip-01', $final_rules[1]['id']);

        // Index 2: WebCare Rule 1 (compound managed rule)
        $this->assertStringContainsString('[WebCare Pro] Rule 1', $final_rules[2]['description']);

        // Last item: visual-block-01 (visual block rule placed at end)
        $last_rule = end($final_rules);
        $this->assertSame('visual-block-01', $last_rule['id']);
    }

    /**
     * Requirement: Zero budget ($slot_budget === 0) deploys cleaned ruleset removing stale WebCare rules.
     */
    public function testZeroBudgetDeploysCleanedRulesetWhenStaleWebCareRulesExist(): void {
        $optimizer = new CloudflareSlotOptimizer();

        $existing_rules = [
            ['id' => 'u1', 'description' => 'User Rule 1', 'action' => 'block'],
            ['id' => 'u2', 'description' => 'User Rule 2', 'action' => 'block'],
            ['id' => 'u3', 'description' => 'User Rule 3', 'action' => 'block'],
            ['id' => 'u4', 'description' => 'User Rule 4', 'action' => 'block'],
            ['id' => 'stale-wcp', 'description' => '[WebCare Pro] Stale Rule', 'action' => 'block'],
        ];

        update_option(CloudflareSlotOptimizer::OPTION_MANAGED_RULE_IDS, ['stale-wcp']);

        $captured_clean_payload = null;

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$captured_clean_payload, $existing_rules): array {
            if (str_contains($endpoint, 'rulesets/phases/http_request_firewall_custom/entrypoint')) {
                if ($method === 'GET') {
                    return [
                        'success' => true,
                        'result'  => ['rules' => $existing_rules],
                    ];
                }
                if ($method === 'PUT') {
                    $captured_clean_payload = $data;
                    return ['success' => true, 'result' => []];
                }
            }
            return ['success' => true, 'result' => []];
        };

        $res = $optimizer->deploy_to_cloudflare('zone-zero-budget');
        $this->assertFalse($res['success']);
        $this->assertSame(0, $res['slot_budget']);
        $this->assertNotNull($captured_clean_payload, 'A cleaned ruleset must be deployed when stale WebCare rules exist.');
        $this->assertCount(4, $captured_clean_payload['rules'], 'Stale WebCare rule must be purged from deployed rules.');
        $this->assertFalse(get_option(CloudflareSlotOptimizer::OPTION_MANAGED_RULE_IDS), 'Managed IDs option must be cleared.');
    }

    /**
     * Requirement 4: mutate_ban_queue returns false without writing when mutex lock cannot be acquired.
     */
    public function testMutateBanQueueReturnsFalseWhenMutexHeld(): void {
        // Pre-set active mutex lock in options
        $token = 'locked_by_other_process|' . (time() + 60);
        update_option('webcare_cf_queue_mutex', $token);

        // Pre-set queue with known entry
        $initial_queue = ['192.0.2.1' => ['ip' => '192.0.2.1', 'status' => 'pending']];
        update_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, $initial_queue);

        // Simulate add_option failure when option already exists
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => $token;

        $attempted_mutation = false;
        $result = CloudflareIpListSynchronizer::mutate_ban_queue(static function (array $queue) use (&$attempted_mutation): array {
            $attempted_mutation = true;
            $queue['198.51.100.99'] = ['ip' => '198.51.100.99'];
            return $queue;
        });

        $this->assertFalse($result, 'mutate_ban_queue must return false when mutex cannot be acquired.');
        $this->assertFalse($attempted_mutation, 'Callback must NOT execute when mutex is not acquired.');

        // Verify queue was preserved untouched (no un-atomic fallback)
        $persisted_queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertSame($initial_queue, $persisted_queue, 'Queue must remain unchanged when mutex fails.');
    }

    /**
     * Requirement 5: unban_ip_immediately async polling and local ledger retention.
     * On DELETE, tracks operation_id, retains local ledger while status is running,
     * and removes local entry only after status is completed and verified absent.
     */
    public function testUnbanIpImmediatelyRetainsLedgerUntilCompleted(): void {
        $ip = '203.0.113.55';
        $item_id = 'cf-item-abc-123';
        $operation_id = 'cf-op-xyz-789';

        // Set mock settings with API token and scope
        update_option('webcareproscan_settings', [
            'cloudflare_api_token' => 'mock_token',
            'cloudflare_zone_id'   => 'mock_zone',
        ]);
        set_transient(CloudflareIpListSynchronizer::OPTION_TOKEN_SCOPE, 'account', 3600);
        update_option(CloudflareIpListSynchronizer::OPTION_ACCOUNT_LIST_ID, 'mock-list-1');

        // Set active edge ban in local ledger
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => [
                'target'  => $ip,
                'mode'    => 'account',
                'item_id' => $item_id,
            ],
        ]);

        $op_status = 'running';

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$op_status, $operation_id, $item_id, $ip): array {
            if (str_contains($endpoint, 'accounts') && !str_contains($endpoint, 'rules')) {
                return ['success' => true, 'result' => [['id' => 'mock-acc-1']]];
            }
            if (str_contains($endpoint, 'items') && $method === 'DELETE') {
                return [
                    'success' => true,
                    'result'  => ['operation_id' => $operation_id],
                ];
            }
            if (str_contains($endpoint, "bulk_operations/{$operation_id}")) {
                return [
                    'success' => true,
                    'result'  => ['status' => $op_status],
                ];
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Verification search
                if ($op_status === 'completed') {
                    return ['success' => true, 'result' => []]; // Empty = confirmed deleted
                }
                return ['success' => true, 'result' => [['id' => $item_id, 'ip' => $ip]]];
            }
            return ['success' => true, 'result' => []];
        };

        // Call 1: Status is 'running'
        $unban1 = CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        $this->assertFalse($unban1, 'Must return false while async operation is pending/running.');

        // Ledger entry must be retained with state = 'pending_unban'
        $bans_after_1 = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayHasKey($ip, $bans_after_1, 'Ledger must retain entry while async operation is in progress.');
        $this->assertSame('pending_unban', $bans_after_1[$ip]['state']);
        $this->assertSame($operation_id, $bans_after_1[$ip]['operation_id']);

        // Call 2: Change status to 'completed'
        $op_status = 'completed';
        $unban2 = CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        $this->assertTrue($unban2, 'Must return true after async operation is verified completed.');

        // Local ledger entry must now be removed
        $bans_after_2 = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayNotHasKey($ip, $bans_after_2, 'Ledger entry must be removed after status is completed.');
    }

    /**
     * Requirement: unban_ip_immediately returns false and retains ledger when verification is unknown or fails.
     */
    public function testUnbanIpImmediatelyHandlesVerificationUnknown(): void {
        $ip = '203.0.113.66';
        $item_id = 'cf-item-verify-unknown';

        update_option('webcareproscan_settings', [
            'cloudflare_api_token' => 'mock_token',
            'cloudflare_zone_id'   => 'mock_zone',
        ]);
        set_transient(CloudflareIpListSynchronizer::OPTION_TOKEN_SCOPE, 'account', 3600);
        update_option(CloudflareIpListSynchronizer::OPTION_ACCOUNT_LIST_ID, 'mock-list-1');

        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => [
                'target'  => $ip,
                'mode'    => 'account',
                'item_id' => $item_id,
            ],
        ]);

        // Mock synchronous DELETE succeeding, but post-verification failing (network/API error)
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use ($ip, $item_id): array {
            if (str_contains($endpoint, 'accounts') && !str_contains($endpoint, 'rules')) {
                return ['success' => true, 'result' => [['id' => 'mock-acc-1']]];
            }
            if (str_contains($endpoint, 'items') && $method === 'DELETE') {
                return ['success' => true, 'result' => []]; // Synchronous DELETE
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Post-verification API call fails
                return ['success' => false, 'errors' => [['message' => 'Internal API error during verification']]];
            }
            return ['success' => true, 'result' => []];
        };

        $res = CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        $this->assertFalse($res, 'Must return false when post-verification state is unknown.');

        $bans = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayHasKey($ip, $bans, 'Ledger must retain entry when verification state is unknown.');
        $this->assertSame('pending_unban', $bans[$ip]['state']);
    }

    public function testCloudflareSyncAbortsWhenGetRulesFails(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'mock-zone-123',
            'cloudflare_api_token' => 'mock-token-xyz',
        ]);

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET'): array {
            if ($method === 'GET') {
                return ['success' => false, 'errors' => [['message' => 'Rate limited or connection error']]];
            }
            if ($method === 'PUT') {
                throw new \RuntimeException('PUT must not be invoked when GET fails!');
            }
            return ['success' => true];
        };

        $res = \WebCareProScanner\Firewall\VirtualPatchManager::deploy_to_cloudflare_edge([
            'patch_id'      => 'TEST-PATCH-01',
            'title'         => 'Test',
            'cf_expression' => '(http.request.uri.path contains "test")',
        ]);

        $this->assertFalse($res['success'], 'Deploy must fail when GET rules fails.');
        $this->assertStringContainsString('Rate limited', $res['message']);
    }

    public function testFailedAsyncCreateRequeuesIps(): void {
        $ip = '203.0.113.88';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => [
                'target'       => $ip,
                'mode'         => 'account',
                'state'        => 'pending_create',
                'operation_id' => 'op-fail-123',
            ],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-fail-123' => [
                'operation_id' => 'op-fail-123',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'create',
                'ips'          => [$ip],
                'status'       => 'running',
            ],
        ]);

        CloudflareService::$mock_request_handler = static function (string $endpoint): array {
            if (str_contains($endpoint, 'operations/op-fail-123')) {
                return ['success' => true, 'result' => ['status' => 'failed']];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $active = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayNotHasKey($ip, $active, 'Incomplete pending_create entry must be cleaned up on failure.');

        $queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayHasKey($ip, $queue, 'Failed create IP must be re-queued in ban queue.');
    }

    public function testTriStateDeleteVerificationDoesNotRemoveOnApiError(): void {
        $ip = '203.0.113.99';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => [
                'target'  => $ip,
                'mode'    => 'account',
                'item_id' => 'item-99',
                'state'   => 'active',
            ],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-del-123' => [
                'operation_id' => 'op-del-123',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
            ],
        ]);

        // When poll says completed, but verify search endpoint returns API error (500/rate-limited)
        CloudflareService::$mock_request_handler = static function (string $endpoint): array {
            if (str_contains($endpoint, 'operations/op-del-123')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                return ['success' => false, 'errors' => [['message' => 'Cloudflare API failure']]];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $active = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayHasKey($ip, $active, 'Active ban must NOT be removed when verification state is unknown due to API failure.');
    }

    public function testPaginatedCreateReconciliationResolvesAllIps(): void {
        $ip1 = '203.0.113.101';
        $ip2 = '203.0.113.102';

        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip1 => ['target' => $ip1, 'state' => 'pending_create'],
            $ip2 => ['target' => $ip2, 'state' => 'pending_create'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-create-paginated' => [
                'operation_id' => 'op-create-paginated',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'create',
                'ips'          => [$ip1, $ip2],
                'status'       => 'running',
            ],
        ]);

        // Mock pagination: page 1 returns ip1 + cursor "cursor_page_2"; page 2 returns ip2
        CloudflareService::$mock_request_handler = static function (string $endpoint): array {
            if (str_contains($endpoint, 'operations/op-create-paginated')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?per_page=100')) {
                if (str_contains($endpoint, 'cursor=cursor_page_2')) {
                    return [
                        'success'     => true,
                        'result'      => [['id' => 'item-id-102', 'ip' => '203.0.113.102']],
                        'result_info' => ['cursors' => ['after' => '']],
                    ];
                }
                return [
                    'success'     => true,
                    'result'      => [['id' => 'item-id-101', 'ip' => '203.0.113.101']],
                    'result_info' => ['cursors' => ['after' => 'cursor_page_2']],
                ];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $active = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertSame('item-id-101', $active[$ip1]['item_id'] ?? null);
        $this->assertSame('item-id-102', $active[$ip2]['item_id'] ?? null);
        $this->assertSame('active', $active[$ip1]['state'] ?? null);
        $this->assertSame('active', $active[$ip2]['state'] ?? null);

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('completed', $ops['op-create-paginated']['status'] ?? null);
    }

    public function testRule2ExcludesNonBlockOrNonActivePatches(): void {
        $optimizer = new CloudflareSlotOptimizer();

        $patches = [
            'ACTIVE_BLOCK' => [
                'stage'  => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
                'action' => 'block',
                'cf_expression' => '(http.request.uri.path contains "vuln1")',
            ],
            'SHADOW_BLOCK' => [
                'stage'  => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_SHADOW,
                'action' => 'block',
                'cf_expression' => '(http.request.uri.path contains "vuln2")',
            ],
            'ACTIVE_LOG' => [
                'stage'  => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
                'action' => 'log',
                'cf_expression' => '(http.request.uri.path contains "vuln3")',
            ],
            'ACTIVE_CHALLENGE' => [
                'stage'  => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
                'action' => 'challenge',
                'cf_expression' => '(http.request.uri.path contains "vuln4")',
            ],
        ];

        $snapshot = new \WebCareProScanner\Firewall\CAF\StackSnapshot(
            wp_version: '7.0.0',
            php_version: '8.4.0',
            active_plugins: [],
            inactive_plugins: [],
            active_themes: ['active' => ['twentytwentyfour', '1.0.0']],
            inactive_themes: [],
            rest_namespaces: [],
            detected_ecosystems: [],
            generated_at: time(),
            snapshot_hash: 'abc'
        );

        $expr = $optimizer->compile_rule2_stackguard_expression($snapshot, $patches);
        $this->assertStringContainsString('vuln1', $expr);
        $this->assertStringNotContainsString('vuln2', $expr, 'Shadow stage patches must NOT be compiled into Rule 2 block rule.');
        $this->assertStringNotContainsString('vuln3', $expr, 'Log action patches must NOT be compiled into Rule 2 block rule.');
        $this->assertStringNotContainsString('vuln4', $expr, 'Challenge action patches must NOT be compiled into Rule 2 block rule.');
    }

    public function testPatchUpdateDemotionExcludesOldExpressionFromCloudflare(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'zone-test-123',
            'cloudflare_api_token' => 'token-test-123',
            'waf_auto_enforce_virtual_patches' => true,
        ]);

        $last_put_rules = [];
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$last_put_rules): array {
            if ($method === 'PUT') {
                $last_put_rules = $data['rules'] ?? [];
                return ['success' => true];
            }
            if (str_contains($endpoint, 'entrypoint')) {
                return [
                    'success' => true,
                    'result'  => ['rules' => $last_put_rules],
                ];
            }
            return ['success' => true];
        };

        // 1. Deploy active/block patch
        $patch_manifest = [
            'patch_id'      => 'VPATCH-DEMOTE-001',
            'title'         => 'Test Exploit Shield',
            'cf_expression' => '(http.request.uri.path contains "exploit_path_1")',
            'stage'         => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
            'action'        => 'block',
        ];
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-DEMOTE-001', $patch_manifest);

        $this->assertNotEmpty($last_put_rules);
        $found_v1 = false;
        foreach ($last_put_rules as $r) {
            if (str_contains($r['expression'] ?? '', 'exploit_path_1')) {
                $found_v1 = true;
                break;
            }
        }
        $this->assertTrue($found_v1, 'Initial active/block patch must be deployed to Cloudflare Edge.');

        // 2. Demote the same patch_id to shadow
        $patch_manifest['stage'] = \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_SHADOW;
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-DEMOTE-001', $patch_manifest);

        $found_demoted = false;
        foreach ($last_put_rules as $r) {
            if (str_contains($r['expression'] ?? '', 'exploit_path_1')) {
                $found_demoted = true;
                break;
            }
        }
        $this->assertFalse($found_demoted, 'Demoted patch expression must be immediately removed from Cloudflare Rule 2.');

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-DEMOTE-001');
    }

    public function testAsyncDeleteKeepsOperationPendingOnUnknownVerification(): void {
        $ip = '203.0.113.199';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'mode' => 'account', 'item_id' => 'item-199', 'state' => 'active'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-del-retry' => [
                'operation_id' => 'op-del-retry',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
            ],
        ]);

        CloudflareService::$mock_request_handler = static function (string $endpoint): array {
            if (str_contains($endpoint, 'operations/op-del-retry')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                return ['success' => false, 'errors' => [['message' => '502 Bad Gateway']]];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertArrayHasKey('op-del-retry', $ops);
        $this->assertSame('running', $ops['op-del-retry']['status']);
        $this->assertSame([$ip], $ops['op-del-retry']['ips']);

        $active = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayHasKey($ip, $active);
    }

    public function testAsyncCreatePersistsLastCursorWhenPageCapReached(): void {
        $ip = '203.0.113.200';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'state' => 'pending_create'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-create-cap' => [
                'operation_id' => 'op-create-cap',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'create',
                'ips'          => [$ip],
                'status'       => 'running',
            ],
        ]);

        $call_count = 0;
        CloudflareService::$mock_request_handler = static function (string $endpoint) use (&$call_count): array {
            if (str_contains($endpoint, 'operations/op-create-cap')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?per_page=100')) {
                $call_count++;
                return [
                    'success'     => true,
                    'result'      => [['id' => 'other-' . $call_count, 'ip' => '198.51.100.' . $call_count]],
                    'result_info' => ['cursors' => ['after' => 'cursor_token_' . $call_count]],
                ];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $this->assertSame(10, $call_count, 'Synchronizer must enforce max 10 pages per tick.');

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('running', $ops['op-create-cap']['status']);
        $this->assertSame('cursor_token_10', $ops['op-create-cap']['last_cursor'] ?? null);
        $this->assertSame([$ip], $ops['op-create-cap']['ips']);
    }

    public function testRemovePatchReportsEdgeReconciledFalseAndSetsPendingSyncOnFailure(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'zone-fail-edge',
            'cloudflare_api_token' => 'token-fail-edge',
        ]);
        delete_option('webcareproscan_vpatch_pending_cf_sync');

        // Initial active patch
        update_option(\WebCareProScanner\Firewall\VirtualPatchManager::OPTION_PATCHES, [
            'VPATCH-FAIL-EDGE' => [
                'patch_id'               => 'VPATCH-FAIL-EDGE',
                'title'                  => 'Edge Fail Test',
                'deployed_to_cloudflare' => true,
                'cf_expression'          => '(http.request.uri.path contains "fail")',
            ],
        ]);

        // Mock Cloudflare failure on PUT/ruleset
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET'): array {
            if ($method === 'PUT') {
                return ['success' => false, 'errors' => [['message' => '500 Internal Cloudflare Error']]];
            }
            if (str_contains($endpoint, 'entrypoint')) {
                return ['success' => true, 'result' => ['rules' => []]];
            }
            return ['success' => false];
        };

        $res = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-FAIL-EDGE');
        $this->assertTrue($res['success']);
        $this->assertTrue($res['local_removed']);
        $this->assertFalse($res['edge_reconciled']);
        $this->assertTrue((bool) get_option('webcareproscan_vpatch_pending_cf_sync'));

        delete_option('webcareproscan_vpatch_pending_cf_sync');
    }

    public function testOneSlotBudgetOmitsVirtualPatchesFromCloudflare(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'zone-1slot',
            'cloudflare_api_token' => 'token-1slot',
            'waf_auto_enforce_virtual_patches' => true,
        ]);

        // 3 user rules exist: 5 - 1 (reserve) - 3 (user) = 1 WebCare slot (Rule 1 only, Rule 2 omitted)
        $user_rules = [
            ['id' => 'u1', 'description' => 'User Rule 1', 'action' => 'block', 'expression' => '(ip.src eq 1.1.1.1)'],
            ['id' => 'u2', 'description' => 'User Rule 2', 'action' => 'block', 'expression' => '(ip.src eq 2.2.2.2)'],
            ['id' => 'u3', 'description' => 'User Rule 3', 'action' => 'block', 'expression' => '(ip.src eq 3.3.3.3)'],
        ];

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use ($user_rules): array {
            if ($method === 'PUT') {
                return ['success' => true, 'result' => ['rules' => $data['rules'] ?? []]];
            }
            if (str_contains($endpoint, 'entrypoint')) {
                return ['success' => true, 'result' => ['rules' => $user_rules]];
            }
            return ['success' => true];
        };

        $patch_manifest = [
            'patch_id'      => 'VPATCH-1SLOT-001',
            'title'         => '1-Slot Test',
            'cf_expression' => '(http.request.uri.path contains "slot_test")',
            'stage'         => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
            'action'        => 'block',
        ];
        $apply_res = \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-1SLOT-001', $patch_manifest);

        $this->assertTrue($apply_res['success']);
        $this->assertFalse($apply_res['deployed_to_cloudflare'], 'Patch must NOT be marked deployed_to_cloudflare when Rule 2 is omitted in 1-slot budget.');

        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-1SLOT-001');
    }

    public function testConfirmedPresentDeleteSubmitsFreshDeleteRequest(): void {
        $ip = '203.0.113.222';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'mode' => 'account', 'item_id' => 'item-222', 'state' => 'active'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-present-retry' => [
                'operation_id' => 'op-present-retry',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
                'retry_count'  => 0,
            ],
        ]);

        $fresh_delete_submitted = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$fresh_delete_submitted, $ip): array {
            if (str_contains($endpoint, 'operations/op-present-retry')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Item is confirmed present!
                return [
                    'success' => true,
                    'result'  => [['id' => 'item-222', 'ip' => $ip]],
                ];
            }
            if ($method === 'DELETE' && str_contains($endpoint, 'items')) {
                $fresh_delete_submitted = true;
                return ['success' => true, 'result' => ['operation_id' => 'op-new-fresh-delete-999']];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $this->assertTrue($fresh_delete_submitted, 'A fresh Cloudflare DELETE request must be actively submitted when item is confirmed present.');

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('op-new-fresh-delete-999', $ops['op-present-retry']['operation_id']);
        $this->assertSame(1, $ops['op-present-retry']['retry_count']);
        $this->assertSame('running', $ops['op-present-retry']['status']);
    }

    public function testReconcilePendingOperationsPollsNewOpIdAndTransitionsTerminalOnFifthFailure(): void {
        $ip = '203.0.113.233';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'mode' => 'account', 'item_id' => 'item-233', 'state' => 'active'],
        ]);

        // Scenario 1: op_id key is 'op-initial', but operation_id metadata is 'op-resubmitted-888'
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-initial' => [
                'operation_id' => 'op-resubmitted-888',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
                'retry_count'  => 4, // 4 retries already completed
            ],
        ]);

        $polled_ids = [];
        $delete_calls = 0;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$polled_ids, &$delete_calls, $ip): array {
            if (str_contains($endpoint, 'operations/')) {
                preg_match('/operations\/([^\/\?]+)/', $endpoint, $m);
                if (!empty($m[1])) {
                    $polled_ids[] = $m[1];
                }
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Item still confirmed present
                return [
                    'success' => true,
                    'result'  => [['id' => 'item-233', 'ip' => $ip]],
                ];
            }
            if ($method === 'DELETE') {
                $delete_calls++;
                return ['success' => true, 'result' => ['operation_id' => 'op-fifth-delete-777']];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        // Must poll op-resubmitted-888, NOT op-initial
        $this->assertContains('op-resubmitted-888', $polled_ids, 'Must poll operation_id from metadata rather than op_id array key.');
        $this->assertSame(1, $delete_calls, 'Retry count was 4 (< 5), so 5th delete attempt must be submitted.');

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('op-fifth-delete-777', $ops['op-initial']['operation_id']);
        $this->assertSame(5, $ops['op-initial']['retry_count']);
        $this->assertSame('running', $ops['op-initial']['status'], '5th delete attempt stays running until it has completed and been verified.');

        // Scenario 2: Next tick — 5th delete attempt completes, item is STILL confirmed present -> transitions to failed_terminal
        $sync->reconcile_pending_operations();

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('failed_terminal', $ops['op-initial']['status'], 'Must transition to failed_terminal once 5th attempt verification fails.');

        // Scenario 3: Subsequent tick — failed_terminal is skipped and never polled again
        $polled_count_before = count($polled_ids);
        $sync->reconcile_pending_operations();
        $this->assertSame($polled_count_before, count($polled_ids), 'failed_terminal operation must be skipped without polling.');
    }

    public function testRemovingSynthesizedPatchExcludesExpressionFromCloudflareRule2(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'zone-synth-123',
            'cloudflare_api_token' => 'token-synth-123',
            'waf_auto_enforce_virtual_patches' => true,
        ]);

        $patch_id = 'SYNTH-CVE-2026-9999';
        $synth_patch = [
            'patch_id'      => $patch_id,
            'title'         => 'Synthesized Test Hotpatch',
            'cf_expression' => '(http.request.uri.path contains "synth_exploit_path")',
            'stage'         => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
            'action'        => 'block',
            'enabled'       => true,
            'deployed_to_cloudflare' => true,
        ];

        update_option(\WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, [
            $patch_id => $synth_patch,
        ]);

        // Confirm it appears in active patches
        $active_before = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        $this->assertArrayHasKey($patch_id, $active_before);

        $deployed_rules = [];
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$deployed_rules): array {
            if ($method === 'PUT') {
                $deployed_rules = $data['rules'] ?? [];
            }
            if (str_contains($endpoint, 'entrypoint')) {
                return ['success' => true, 'result' => ['rules' => []]];
            }
            return ['success' => true];
        };

        $res = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch($patch_id);
        $this->assertTrue($res['success']);
        $this->assertTrue($res['local_removed']);

        // Check active patches does NOT contain the patch
        $active_after = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        $this->assertArrayNotHasKey($patch_id, $active_after, 'Removed synthesized patch must not appear in active patches.');

        // Check synthesized patch option was disabled / revoked
        $synth_after = get_option(\WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, []);
        $this->assertFalse($synth_after[$patch_id]['enabled'] ?? true);
        $this->assertSame(\WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_REVOKED, $synth_after[$patch_id]['stage'] ?? null);

        // Verify deployed Cloudflare rules do NOT contain the synth patch expression
        foreach ($deployed_rules as $rule) {
            $this->assertStringNotContainsString('synth_exploit_path', $rule['expression'] ?? '');
        }
    }

    public function testEdgeAutoSyncReconcilesPendingVpatchSyncFlag(): void {
        update_option('webcareproscan_settings', [
            'cloudflare_zone_id'   => 'zone-sync-123',
            'cloudflare_api_token' => 'token-sync-123',
        ]);
        update_option('webcareproscan_vpatch_pending_cf_sync', true);

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null): array {
            if (str_contains($endpoint, 'entrypoint')) {
                return ['success' => true, 'result' => ['rules' => []]];
            }
            return ['success' => true];
        };

        \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::execute_edge_auto_sync();

        $this->assertFalse(get_option('webcareproscan_vpatch_pending_cf_sync', false), 'execute_edge_auto_sync must clear pending vpatch sync flag on success.');
    }

    public function testDeleteMultipleUnresolvedIpsSubmitsSingleBatchRequestAndTracksOpId(): void {
        $ipA = '203.0.113.11';
        $ipB = '203.0.113.12';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ipA => ['target' => $ipA, 'mode' => 'account', 'item_id' => 'item-A', 'state' => 'active'],
            $ipB => ['target' => $ipB, 'mode' => 'account', 'item_id' => 'item-B', 'state' => 'active'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-multi-delete' => [
                'operation_id' => 'op-multi-delete',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ipA, $ipB],
                'status'       => 'running',
                'retry_count'  => 0,
            ],
        ]);

        $submitted_delete_batches = [];
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$submitted_delete_batches, $ipA, $ipB): array {
            if (str_contains($endpoint, 'operations/op-multi-delete')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Both items are still confirmed present!
                $search_ip = str_contains($endpoint, rawurlencode($ipA)) ? $ipA : $ipB;
                $item_id = ($search_ip === $ipA) ? 'item-A' : 'item-B';
                return [
                    'success' => true,
                    'result'  => [['id' => $item_id, 'ip' => $search_ip]],
                ];
            }
            if ($method === 'DELETE' && str_contains($endpoint, 'items')) {
                $submitted_delete_batches[] = $data['items'] ?? [];
                return ['success' => true, 'result' => ['operation_id' => 'op-batch-delete-unified']];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $this->assertCount(1, $submitted_delete_batches, 'Must submit exactly ONE consolidated batch delete request for multiple confirmed present IPs.');
        $this->assertCount(2, $submitted_delete_batches[0], 'Batch request must contain both item IDs.');

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('op-batch-delete-unified', $ops['op-multi-delete']['operation_id']);
        $this->assertSame('running', $ops['op-multi-delete']['status']);
        $this->assertSame(1, $ops['op-multi-delete']['retry_count']);
    }

    public function testVerificationUnknownDoesNotExhaustDeleteRetries(): void {
        $ip = '203.0.113.13';
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-unknown-retry' => [
                'operation_id' => 'op-unknown-retry',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
                'retry_count'  => 0,
            ],
        ]);

        $delete_submitted = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$delete_submitted): array {
            if (str_contains($endpoint, 'operations/op-unknown-retry')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                // Transient Cloudflare API failure -> verification_unknown
                return ['success' => false, 'errors' => [['message' => 'Rate limit exceeded']]];
            }
            if ($method === 'DELETE') {
                $delete_submitted = true;
                return ['success' => true, 'result' => ['operation_id' => 'op-fresh-delete']];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();

        // Run 6 consecutive ticks under verification_unknown
        for ($i = 0; $i < 6; $i++) {
            $sync->reconcile_pending_operations();
        }

        $this->assertFalse($delete_submitted, 'No fresh delete request should be submitted when verification state is unknown.');

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame(0, $ops['op-unknown-retry']['retry_count'], 'verification_unknown must not increment delete retry_count.');
        $this->assertSame('running', $ops['op-unknown-retry']['status'], 'Operation must stay running and NOT transition to failed_terminal due to verification failures.');
    }

    public function testDeleteSucceedingWithoutOperationIdDoesNotPollStaleOpId(): void {
        $ip = '203.0.113.14';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'mode' => 'account', 'item_id' => 'item-14', 'state' => 'active'],
        ]);
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-stale-test' => [
                'operation_id' => 'op-old-completed-id',
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'running',
                'retry_count'  => 0,
            ],
        ]);

        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use ($ip): array {
            if (str_contains($endpoint, 'operations/op-old-completed-id')) {
                return ['success' => true, 'result' => ['status' => 'completed']];
            }
            if (str_contains($endpoint, 'items?search=')) {
                return ['success' => true, 'result' => [['id' => 'item-14', 'ip' => $ip]]];
            }
            if ($method === 'DELETE') {
                // DELETE succeeds synchronously or returns success without operation_id
                return ['success' => true, 'result' => []];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertArrayNotHasKey('operation_id', $ops['op-stale-test'], 'Must unset operation_id when DELETE response lacks an operation ID so old completed ID is not re-polled.');
        $this->assertSame('awaiting_list_verification', $ops['op-stale-test']['status'], 'Operation must enter awaiting_list_verification state when DELETE lacks an operation_id.');

        // On next tick, verify it bypasses bulk-operation polling and directly verifies the list
        $polled_ops = [];
        $verified_search = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$polled_ops, &$verified_search): array {
            if (str_contains($endpoint, 'bulk_operations/')) {
                $polled_ops[] = $endpoint;
                return ['success' => false, 'errors' => [['message' => 'Old operation not found']]];
            }
            if (str_contains($endpoint, 'items?search=')) {
                $verified_search = true;
                // Item is now confirmed absent!
                return ['success' => true, 'result' => []];
            }
            return ['success' => true];
        };

        $sync->reconcile_pending_operations();

        $this->assertEmpty($polled_ops, 'Must NOT poll stale op_id or bulk_operations endpoint when in awaiting_list_verification state.');
        $this->assertTrue($verified_search, 'Must perform direct list item verification on next tick.');

        $active = get_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, []);
        $this->assertArrayNotHasKey($ip, $active, 'IP must be confirmed absent and removed from active ledger.');
    }

    public function testRetryDeleteFailurePreservesAwaitingListVerificationWithoutPollingStaleId(): void {
        $ip = '203.0.113.15';
        update_option(CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ip => ['target' => $ip, 'mode' => 'account', 'item_id' => 'item-15', 'state' => 'active'],
        ]);
        // Operation already in awaiting_list_verification state without operation_id
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-stale-fallback-guard' => [
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'awaiting_list_verification',
                'retry_count'  => 1,
            ],
        ]);

        $delete_attempts = 0;
        // Step 1: Direct verification runs, IP is STILL confirmed present, but the retry DELETE fails
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$delete_attempts, $ip): array {
            if (str_contains($endpoint, 'items?search=')) {
                return ['success' => true, 'result' => [['id' => 'item-15', 'ip' => $ip]]];
            }
            if ($method === 'DELETE') {
                $delete_attempts++;
                return ['success' => false, 'errors' => [['message' => 'Internal Cloudflare Error']]];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $this->assertSame(1, $delete_attempts);
        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('awaiting_list_verification', $ops['op-stale-fallback-guard']['status'], 'Status must remain awaiting_list_verification when DELETE fails.');
        $this->assertArrayNotHasKey('operation_id', $ops['op-stale-fallback-guard']);

        // Step 2: Next tick — ensure it STILL bypasses bulk-operation polling and does NOT poll the original ledger key 'op-stale-fallback-guard'
        $polled_ops = [];
        $verified_on_next_tick = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$polled_ops, &$verified_on_next_tick): array {
            if (str_contains($endpoint, 'bulk_operations/')) {
                $polled_ops[] = $endpoint;
                return ['success' => false, 'errors' => [['message' => 'Stale op ID polled!']]];
            }
            if (str_contains($endpoint, 'items?search=')) {
                $verified_on_next_tick = true;
                return ['success' => true, 'result' => []]; // Confirmed absent now
            }
            return ['success' => true];
        };

        $sync->reconcile_pending_operations();

        $this->assertEmpty($polled_ops, 'Must NOT poll original op_id array key after a failed DELETE attempt.');
        $this->assertTrue($verified_on_next_tick, 'Must directly re-verify list items on the following tick.');
    }

    public function testMissingOperationIdWithUnknownVerificationPreservesAwaitingListVerificationWithoutPollingStaleOpId(): void {
        $ip = '203.0.113.16';
        update_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, [
            'op-stale-ledger-key-999' => [
                'account_id'   => 'acc-1',
                'list_id'      => 'list-1',
                'type'         => 'delete',
                'ips'          => [$ip],
                'status'       => 'awaiting_list_verification',
                'retry_count'  => 0,
            ],
        ]);

        // Step 1: Direct verification runs, but Cloudflare list-search fails -> verification_unknown
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null): array {
            if (str_contains($endpoint, 'items?search=')) {
                return ['success' => false, 'errors' => [['message' => 'Cloudflare API timeout']]];
            }
            return ['success' => true];
        };

        $sync = new CloudflareIpListSynchronizer();
        $sync->reconcile_pending_operations();

        $ops = get_option(CloudflareIpListSynchronizer::OPTION_PENDING_OPERATIONS, []);
        $this->assertSame('awaiting_list_verification', $ops['op-stale-ledger-key-999']['status'], 'Operation must preserve awaiting_list_verification status when verification is unknown.');
        $this->assertArrayNotHasKey('operation_id', $ops['op-stale-ledger-key-999']);

        // Step 2: Next tick — ensure it does NOT poll bulk_operations/op-stale-ledger-key-999 and routes directly to list search
        $polled_bulk_ops = [];
        $search_executed = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method = 'GET', ?array $data = null) use (&$polled_bulk_ops, &$search_executed): array {
            if (str_contains($endpoint, 'bulk_operations/')) {
                $polled_bulk_ops[] = $endpoint;
                return ['success' => false, 'errors' => [['message' => 'Stale op ID was polled!']]];
            }
            if (str_contains($endpoint, 'items?search=')) {
                $search_executed = true;
                return ['success' => true, 'result' => []]; // Confirmed absent
            }
            return ['success' => true];
        };

        $sync->reconcile_pending_operations();

        $this->assertEmpty($polled_bulk_ops, 'Central polling invariant must NEVER poll original op_id ledger key when operation_id is missing.');
        $this->assertTrue($search_executed, 'Must directly execute list search verification.');
    }

    public function testRemovePatchFailsGracefullyWhenSynthesizedPersistenceFails(): void {
        $patch_id = 'SYNTH-FAIL-TEST';
        $synth_patch = [
            'patch_id' => $patch_id,
            'title'    => 'Synth Fail Test',
            'enabled'  => true,
            'stage'    => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE,
        ];
        update_option(\WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, [
            $patch_id => $synth_patch,
        ]);

        // Mock pre_option_ to simulate storage write failure (persisted option still has enabled => true)
        add_filter('pre_option_' . \WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, static function () use ($patch_id, $synth_patch) {
            return [$patch_id => $synth_patch]; // Always returns enabled => true
        });

        $res = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch($patch_id);
        $this->assertFalse($res['success'], 'remove_patch must report failure when local persistence fails.');
        $this->assertFalse($res['local_removed'], 'local_removed must be false when persistence fails.');
        remove_all_filters('pre_option_' . \WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES);

        // Sub-scenario: Enabled is false, but stage was NOT persisted as STAGE_REVOKED
        $unrevoked_patch = [
            'patch_id' => 'SYNTH-UNREVOKED-TEST',
            'title'    => 'Synth Unrevoked Test',
            'enabled'  => false,
            'stage'    => \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_STAGED, // Not STAGE_REVOKED
        ];
        update_option(\WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, [
            'SYNTH-UNREVOKED-TEST' => $unrevoked_patch,
        ]);
        add_filter('pre_option_' . \WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, static function () use ($unrevoked_patch) {
            return ['SYNTH-UNREVOKED-TEST' => $unrevoked_patch];
        });

        $res2 = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('SYNTH-UNREVOKED-TEST');
        $this->assertFalse($res2['success'], 'remove_patch must fail when persisted stage is not STAGE_REVOKED.');
        $this->assertFalse($res2['local_removed']);
        remove_all_filters('pre_option_' . \WebCareProScanner\Firewall\VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES);
    }

    /**
     * Requirement: handle_loopback_flush rejects tokens signed with 'webcare_cf_fallback_salt'
     * and fails closed if no secret key is available.
     */
    public function testHandleLoopbackFlushRejectsFallbackSaltAndFailsClosed(): void {
        $now = time();
        $nonce = 'test_nonce_12345';
        $insecure_salt = 'webcare_cf_fallback_salt';
        $insecure_sig = hash_hmac('sha256', "cf_flush|{$now}|{$nonce}", $insecure_salt);
        $insecure_token = "{$now}:{$nonce}:{$insecure_sig}";

        // Mock wp_send_json_error to intercept response
        $caught_error = null;
        $caught_code = 0;
        $GLOBALS['wp_mock_send_json_error'] = static function ($data, $status_code) use (&$caught_error, &$caught_code) {
            $caught_error = $data;
            $caught_code = $status_code;
            throw new \RuntimeException('wp_send_json_error_intercepted: ' . ($data['message'] ?? ''));
        };

        $_POST['token'] = $insecure_token;

        // Ensure SecretVault has a real key, so 'webcare_cf_fallback_salt' will be rejected
        try {
            CloudflareIpListSynchronizer::handle_loopback_flush();
            $this->fail('handle_loopback_flush must reject token signed with fallback salt');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('Invalid loopback signature', $e->getMessage());
            $this->assertSame(403, $caught_code);
        }

        unset($GLOBALS['wp_mock_send_json_error']);
        unset($_POST['token']);
    }
}
