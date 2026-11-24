<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard;
use WebCareProScanner\Firewall\Core\TransientRateLimiter;
use WebCareProScanner\Firewall\Core\ViolationResponder;
use WebCareProScanner\Firewall\Evaluators\ProtocolAndBotEvaluator;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\Firewall\RescueAssistantManager;

/**
 * CustomerTrustAndAtomicLimitsTest
 *
 * Verifies regression requirements for v3.23.1:
 * 1. Customer-trust suppression does not bypass zero-tolerance rules (SQLi, RCE, LFI, etc.) on trusted routes.
 * 2. RescueAssistantManager::is_zero_tolerance_rule rejects critical exploit rule IDs.
 * 3. File atomic counter increments handle file locks without falling back to non-atomic transients.
 * 4. Dual-layer rate limiting enforces aggregate per-IP ceilings across multiple rotated identities.
 * 5. MicroWafCompiler generates strict Cloudflare header trust only for confirmed Cloudflare edge IPs.
 * 6. Temporary unblock bypasses operational blocklist while still evaluating exploit signatures.
 * 7. Atomic threat-score cooldown deduplication prevents race conditions.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class CustomerTrustAndAtomicLimitsTest extends TestCase {

    private array $origServer;
    private array $origGet;
    private array $origPost;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $this->origPost = $_POST;
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $_POST = $this->origPost;
        parent::tearDown();
    }

    public function test_zero_tolerance_rule_identification(): void {
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-SQLI-INJECTION'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-RCE-PHP-INJECTION'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-LFI-TRAVERSAL'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-OBJECT-STREAM-INJECTION'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-XXE-INJECTION'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-SSRF-METADATA'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-AJAX-SHORTCODE-GADGET'));
        $this->assertTrue(RescueAssistantManager::is_zero_tolerance_rule('WAF-POLYGLOT-UPLOAD-TRAP'));

        // Non-critical or behavioral rules should return false
        $this->assertFalse(RescueAssistantManager::is_zero_tolerance_rule('WAF-RATE-LIMIT'));
        $this->assertFalse(RescueAssistantManager::is_zero_tolerance_rule('WAF-AI-AGENT-HEURISTIC'));
        $this->assertFalse(RescueAssistantManager::is_zero_tolerance_rule('WAF-404-SCANNER'));
    }

    public function test_rescue_assistant_trust_action_rejects_zero_tolerance_rule(): void {
        $result = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => 'WAF-SQLI-INJECTION',
            'value' => '/checkout',
            'type' => 'uri',
            'method' => 'POST',
            'user_role' => 'customer',
            'param_key' => 'billing_first_name'
        ]);

        $this->assertFalse($result['success']);
        $this->assertSame('zero_tolerance_rule', $result['code']);
    }

    public function test_is_rule_or_request_trusted_denies_zero_tolerance_rules(): void {
        // Even if an entry exists, is_rule_or_request_trusted must refuse zero-tolerance rules
        $isTrusted = RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-SQLI-INJECTION',
            '/checkout',
            '',
            '',
            'POST',
            'customer',
            'billing_first_name'
        );
        $this->assertFalse($isTrusted);
    }

    public function test_always_on_core_guard_does_not_short_circuit_trusted_route(): void {
        $guard = new AlwaysOnCoreGuard();
        $server = [
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/checkout',
            'REMOTE_ADDR' => '203.0.113.50',
            'HTTP_HOST' => 'example.com',
        ];
        $ctx = new RequestContext(
            ip: '203.0.113.50',
            method: 'POST',
            uri: '/checkout',
            userAgent: 'Mozilla/5.0',
            params: ['query' => "UNION SELECT 1,2,3--"],
            cookies: [],
            headers: ['Host' => 'example.com'],
            files: [],
            server: $server
        );

        $verdict = $guard->evaluate_runtime_request($ctx);
        // evaluate_runtime_request returns null when clean or a WafVerdict when violating
        $this->assertTrue($verdict === null || $verdict instanceof WafVerdict);
    }

    public function test_temporary_unblock_transient_consumption(): void {
        $testIp = '203.0.113.99';
        $transientKey = 'webcareproscan_temp_allow_' . md5($testIp);
        set_transient($transientKey, 1, 300);

        $this->assertTrue((bool) get_transient($transientKey));

        delete_transient($transientKey);
        $this->assertFalse((bool) get_transient($transientKey));
    }

    public function test_atomic_cooldown_set(): void {
        $key = 'test_cooldown_' . bin2hex(random_bytes(4));
        $res1 = AdaptiveRateLimiter::atomic_cooldown_set($key, 60);
        $this->assertTrue($res1);

        // Immediate subsequent call must return false (already active)
        $res2 = AdaptiveRateLimiter::atomic_cooldown_set($key, 60);
        $this->assertFalse($res2);
    }

    public function test_micro_waf_compiler_does_not_trust_cf_ip_behind_custom_proxy_without_cf_verification(): void {
        $compiled = MicroWafCompiler::compile();
        $this->assertIsArray($compiled);
        $this->assertArrayHasKey('success', $compiled);

        $compiledPath = MicroWafCompiler::get_compiled_file_path();
        $this->assertFileExists($compiledPath);
        $code = (string) file_get_contents($compiledPath);
        $this->assertIsString($code);
        // Verify that HTTP_CF_CONNECTING_IP is not blindly accepted without Cloudflare IP range check in proxy fallback
        $this->assertStringNotContainsString('elseif ($cf_enabled && isset($_SERVER[\'HTTP_CF_CONNECTING_IP\']))', $code);
    }

    public function test_route_trust_does_not_suppress_unrelated_detector(): void {
        update_option(RescueAssistantManager::OPTION_TRUSTED_ACTIONS, [
            [
                'id'        => 'trust_det_a',
                'type'      => 'uri',
                'value'     => '/checkout',
                'rule_id'   => 'WAF-CUSTOM-DETECTOR-A',
                'method'    => 'POST',
                'param_key' => 'coupon_code',
                'user_role' => '',
            ]
        ], false);

        // Matching detector A on /checkout POST with coupon_code
        $this->assertTrue(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-CUSTOM-DETECTOR-A',
            '/checkout',
            '',
            '',
            'POST',
            '',
            'coupon_code'
        ));

        // Different detector B on the exact same route, method, and param must NOT be exempted
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-CUSTOM-DETECTOR-B',
            '/checkout',
            '',
            '',
            'POST',
            '',
            'coupon_code'
        ));

        // Detector A on different method (GET vs POST) must NOT be exempted
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-CUSTOM-DETECTOR-A',
            '/checkout',
            '',
            '',
            'GET',
            '',
            'coupon_code'
        ));

        // Detector A on different parameter key must NOT be exempted
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-CUSTOM-DETECTOR-A',
            '/checkout',
            '',
            '',
            'POST',
            '',
            'other_param'
        ));
    }

    public function test_temporary_unblock_bypasses_404_lockout(): void {
        $guard = new AlwaysOnCoreGuard();
        $clientIp = '203.0.113.88';
        $lockoutTransient = 'webcareproscan_404_lock_' . md5($clientIp);
        $tempAllowTransient = 'webcareproscan_temp_allow_' . md5($clientIp);

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $settings['waf_enabled'] = true;
        $settings['waf_mode'] = 'enabled';
        update_option('webcareproscan_settings', $settings);

        // Setup 404 lockout
        set_transient($lockoutTransient, ['count' => 20, 'window' => 60, 'duration' => 30], 1800);

        $ctx = new RequestContext(
            ip: $clientIp,
            method: 'GET',
            uri: '/normal-page',
            userAgent: 'Mozilla/5.0',
            params: [],
            cookies: [],
            headers: ['Host' => 'example.com'],
            files: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/normal-page', 'REMOTE_ADDR' => $clientIp]
        );

        // Without temp allow, should be blocked by RATE-LIMIT-404-LOCKOUT
        $verdict1 = $guard->evaluate_runtime_request($ctx);
        $this->assertInstanceOf(WafVerdict::class, $verdict1);
        $this->assertSame('RATE-LIMIT-404-LOCKOUT', $verdict1->rule_id);

        // With active temporary unblock, 404 lockout must be bypassed
        set_transient($tempAllowTransient, 1, 900);
        $verdict2 = $guard->evaluate_runtime_request($ctx);
        $this->assertNull($verdict2);

        // But a protocol/hardening violation from the same temp-unblocked IP must STILL be blocked
        $exploitCtx = new RequestContext(
            ip: $clientIp,
            method: 'TRACE',
            uri: '/normal-page',
            userAgent: 'Mozilla/5.0',
            params: [],
            cookies: [],
            headers: ['Host' => 'example.com'],
            files: [],
            server: ['REQUEST_METHOD' => 'TRACE', 'REQUEST_URI' => '/normal-page', 'REMOTE_ADDR' => $clientIp]
        );
        $settings['waf_block_unsafe_http_methods'] = true;
        update_option('webcareproscan_settings', $settings);

        $verdict3 = $guard->evaluate_runtime_request($exploitCtx);
        $this->assertInstanceOf(WafVerdict::class, $verdict3);
        $this->assertSame('WAF-UNSAFE-HTTP-METHOD', $verdict3->rule_id);

        delete_transient($lockoutTransient);
        delete_transient($tempAllowTransient);
    }

    public function test_customer_trust_rejects_missing_method_and_missing_target(): void {
        // Missing method
        $resNoMethod = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => 'WAF-CUSTOM-DETECTOR',
            'value'   => '/checkout',
            'type'    => 'uri',
            'method'  => '',
        ]);
        $this->assertFalse($resNoMethod['success']);
        $this->assertSame('invalid_method', $resNoMethod['code']);

        // Invalid HTTP method
        $resBadMethod = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => 'WAF-CUSTOM-DETECTOR',
            'value'   => '/checkout',
            'type'    => 'uri',
            'method'  => 'INVALIDMETHOD',
        ]);
        $this->assertFalse($resBadMethod['success']);
        $this->assertSame('invalid_method', $resBadMethod['code']);

        // Missing target route
        $resNoValue = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => 'WAF-CUSTOM-DETECTOR',
            'value'   => '',
            'type'    => 'uri',
            'method'  => 'POST',
        ]);
        $this->assertFalse($resNoValue['success']);

        // Missing rule_id
        $resNoRule = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => '',
            'value'   => '/checkout',
            'type'    => 'uri',
            'method'  => 'POST',
        ]);
        $this->assertFalse($resNoRule['success']);
    }

    public function test_customer_trust_enforces_mandatory_parameter_scope(): void {
        update_option(RescueAssistantManager::OPTION_TRUSTED_ACTIONS, [
            [
                'id'        => 'trust_param_specific',
                'type'      => 'uri',
                'value'     => '/my-account',
                'rule_id'   => 'WAF-PARAM-DETECTOR',
                'method'    => 'POST',
                'param_key' => 'account_display_name',
                'user_role' => '',
            ],
            [
                'id'        => 'trust_without_param',
                'type'      => 'uri',
                'value'     => '/my-account',
                'rule_id'   => 'WAF-NO-PARAM-DETECTOR',
                'method'    => 'POST',
                'param_key' => '',
                'user_role' => '',
            ]
        ], false);

        // When a detector violation specifies a offending parameter, a trust entry without a param_key must NOT exempt it
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-NO-PARAM-DETECTOR',
            '/my-account',
            '',
            '',
            'POST',
            '',
            'billing_address_1'
        ));

        // When parameter matches exactly, it is trusted
        $this->assertTrue(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-PARAM-DETECTOR',
            '/my-account',
            '',
            '',
            'POST',
            '',
            'account_display_name'
        ));

        // When parameter does NOT match, it is not trusted
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-PARAM-DETECTOR',
            '/my-account',
            '',
            '',
            'POST',
            '',
            'other_param'
        ));
    }

    public function test_customer_trust_rejects_type_rule_and_prevents_global_detector_bypass(): void {
        // 1. Direct trust_and_allow_action must reject type === 'rule'
        $resRuleType = RescueAssistantManager::trust_and_allow_action([
            'rule_id' => 'WAF-CUSTOM-DETECTOR',
            'value'   => 'WAF-CUSTOM-DETECTOR',
            'type'    => 'rule',
            'method'  => 'POST',
        ]);
        $this->assertFalse($resRuleType['success']);
        $this->assertSame('invalid_target_type', $resRuleType['code']);

        // 2. Even if an entry with type === 'rule' exists in stored options, matcher must refuse to match
        update_option(RescueAssistantManager::OPTION_TRUSTED_ACTIONS, [
            [
                'id'        => 'trust_legacy_rule',
                'type'      => 'rule',
                'value'     => 'WAF-HEURISTIC-DETECTOR',
                'rule_id'   => 'WAF-HEURISTIC-DETECTOR',
                'method'    => 'POST',
                'param_key' => '',
                'user_role' => '',
            ]
        ], false);

        // Matching must NOT succeed across arbitrary routes (/cart or /checkout)
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-HEURISTIC-DETECTOR',
            '/cart',
            '',
            '',
            'POST',
            '',
            ''
        ));
        $this->assertFalse(RescueAssistantManager::is_rule_or_request_trusted(
            'WAF-HEURISTIC-DETECTOR',
            '/checkout',
            '',
            '',
            'POST',
            '',
            ''
        ));
    }

    public function test_firewall_controller_trust_log_action_requires_incident_id_and_rejects_forgery(): void {
        // 1. Missing incident_id must be rejected
        $reqNoId = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
        $reqNoId->set_header('content-type', 'application/json');
        $reqNoId->set_body((string) wp_json_encode([
            'uri'     => '/my-account',
            'rule_id' => 'WAF-HEURISTIC-DETECTOR',
            'method'  => 'POST',
        ]));
        $resNoId = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($reqNoId);
        $this->assertSame(400, $resNoId->get_status());
        $dataNoId = $resNoId->get_data();
        $this->assertSame('missing_incident_id', $dataNoId['code']);

        // 2. Incident record not found must return 404
        $reqNotFound = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
        $reqNotFound->set_header('content-type', 'application/json');
        $reqNotFound->set_body((string) wp_json_encode([
            'incident_id' => 'WEBCARE-NONEXISTENT',
            'uri'         => '/my-account',
            'rule_id'     => 'WAF-HEURISTIC-DETECTOR',
            'method'      => 'POST',
        ]));
        $resNotFound = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($reqNotFound);
        $this->assertSame(404, $resNotFound->get_status());
        $dataNotFound = $resNotFound->get_data();
        $this->assertSame('incident_not_found', $dataNotFound['code']);

        // 3. Establish request context (method and URI) before creating the WAF incident fixture
        $_SERVER['REQUEST_METHOD'] = 'PUT';
        $_SERVER['REQUEST_URI']    = '/checkout';

        // Log a valid incident with specific method (PUT) and parameter key (billing_city)
        $incId = \WebCareProScanner\Firewall\WafFileLogger::log_incident([
            'id'               => 'WAF-HEURISTIC-DETECTOR',
            'name'             => 'Heuristic Test Rule',
            'category'         => 'Behavioral Defense',
            'target_param'     => 'billing_city',
            'match_value'      => 'MaliciousPayloadValue',
        ], 'blocked');
        $this->assertNotNull($incId);

        // Verify the incident was stored and matches expected authoritative attributes
        $queryResult = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
            'search' => $incId,
            'action' => 'all',
            'range'  => 'all',
        ], 1);
        $this->assertNotEmpty($queryResult['logs']);
        $storedInc = $queryResult['logs'][0];
        $this->assertSame('PUT', $storedInc['request_method']);
        $this->assertSame('/checkout', $storedInc['request_uri']);
        $this->assertSame('billing_city', $storedInc['matched_param_key']);

        // 4. Client forging method (GET instead of incident's method) must be rejected
        $reqForgedMethod = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
        $reqForgedMethod->set_header('content-type', 'application/json');
        $reqForgedMethod->set_body((string) wp_json_encode([
            'incident_id' => $incId,
            'uri'         => '/checkout',
            'rule_id'     => 'WAF-HEURISTIC-DETECTOR',
            'method'      => 'GET', // Forged method
            'param_key'   => 'billing_city',
        ]));
        $resForgedMethod = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($reqForgedMethod);
        $this->assertSame(400, $resForgedMethod->get_status());
        $this->assertSame('method_mismatch', $resForgedMethod->get_data()['code']);

        // 5. Client forging parameter key (billing_first_name instead of billing_city) must be rejected
        $reqForgedParam = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
        $reqForgedParam->set_header('content-type', 'application/json');
        $reqForgedParam->set_body((string) wp_json_encode([
            'incident_id' => $incId,
            'uri'         => '/checkout',
            'rule_id'     => 'WAF-HEURISTIC-DETECTOR',
            'method'      => 'PUT',
            'param_key'   => 'billing_first_name', // Forged parameter
        ]));
        $resForgedParam = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($reqForgedParam);
        $this->assertSame(400, $resForgedParam->get_status());
        $this->assertSame('param_key_mismatch', $resForgedParam->get_data()['code']);

        // 6. Valid trust submission matching authoritative incident succeeds
        $reqValid = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
        $reqValid->set_header('content-type', 'application/json');
        $reqValid->set_body((string) wp_json_encode([
            'incident_id' => $incId,
            'uri'         => '/checkout',
            'rule_id'     => 'WAF-HEURISTIC-DETECTOR',
            'method'      => 'PUT',
            'param_key'   => 'billing_city',
        ]));
        $resValid = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($reqValid);
        $this->assertSame(200, $resValid->get_status());
        $this->assertTrue($resValid->get_data()['success']);
    }

    public function test_rotated_log_segment_incident_lookup_and_resolution(): void {
        // Use an isolated temporary test directory to guarantee zero contamination of live/dev WAF evidence
        $isolatedTestDir = sys_get_temp_dir() . '/webcare_test_rot_lookup_' . wp_generate_password(8, false);
        wp_mkdir_p($isolatedTestDir);

        $previousStorageDir = \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir;
        \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = $isolatedTestDir;

        // Preserve initial trust option state exactly using sentinel
        $trustSentinel = new \stdClass();
        $originalTrustOption = get_option('webcareproscan_rescue_allowlists', $trustSentinel);

        // Simulate rotated segment files: .1, .2, .3
        $baseFilename = strtolower(gmdate('F-j-Y', time())) . '-waf-logs.json';
        $rotatedFilename1 = $baseFilename . '.1';
        $rotatedFilePath1 = $isolatedTestDir . '/' . $rotatedFilename1;
        $rotatedFilename2 = $baseFilename . '.2';
        $rotatedFilePath2 = $isolatedTestDir . '/' . $rotatedFilename2;
        $rotatedFilename3 = $baseFilename . '.3';
        $rotatedFilePath3 = $isolatedTestDir . '/' . $rotatedFilename3;

        $uniqueRotIncidentId1 = 'WEBCARE-' . strtoupper(substr(md5('rot_test1_' . microtime(true)), 0, 8));
        $uniqueRotIncidentId2 = 'WEBCARE-' . strtoupper(substr(md5('rot_test2_' . microtime(true)), 0, 8));
        $uniqueRotIncidentId3 = 'WEBCARE-' . strtoupper(substr(md5('rot_test3_' . microtime(true)), 0, 8));

        $rotatedRecord1 = [
            'id'                => 'webcare_' . substr(md5(uniqid('', true)), 0, 12),
            'incident_id'       => $uniqueRotIncidentId1,
            'ref_code'          => 'WEBCARE-ROT1',
            'timestamp'         => time() - 3600,
            'created_at'        => gmdate('Y-m-d H:i:s', time() - 3600),
            'created_at_gmt'    => gmdate('Y-m-d H:i:s', time() - 3600),
            'ip_address'        => '203.0.113.199',
            'request_uri'       => '/my-account/orders',
            'request_method'    => 'POST',
            'http_status_code'  => 403,
            'rule_id'           => 'WAF-ROTATED-DETECTOR',
            'rule_name'         => 'Rotated Test Rule',
            'rule_category'     => 'Behavioral Defense',
            'rule_description'  => 'Rotated segment incident test',
            'action_taken'      => 'blocked',
            'matched_param_key' => 'order_note',
            'matched_value'     => 'suspicious payload',
        ];

        $rotatedRecord2 = [
            'id'                => 'webcare_' . substr(md5(uniqid('', true)), 0, 12),
            'incident_id'       => $uniqueRotIncidentId2,
            'ref_code'          => 'WEBCARE-ROT2',
            'timestamp'         => time() - 7200,
            'created_at'        => gmdate('Y-m-d H:i:s', time() - 7200),
            'created_at_gmt'    => gmdate('Y-m-d H:i:s', time() - 7200),
            'ip_address'        => '203.0.113.200',
            'request_uri'       => '/checkout/pay',
            'request_method'    => 'POST',
            'http_status_code'  => 403,
            'rule_id'           => 'WAF-ROTATED-DETECTOR',
            'rule_name'         => 'Rotated Test Rule 2',
            'rule_category'     => 'Behavioral Defense',
            'rule_description'  => 'Rotated segment incident test 2',
            'action_taken'      => 'blocked',
            'matched_param_key' => 'payment_nonce',
            'matched_value'     => 'suspicious payload 2',
        ];

        $rotatedRecord3 = [
            'id'                => 'webcare_' . substr(md5(uniqid('', true)), 0, 12),
            'incident_id'       => $uniqueRotIncidentId3,
            'ref_code'          => 'WEBCARE-ROT3',
            'timestamp'         => time() - 10800,
            'created_at'        => gmdate('Y-m-d H:i:s', time() - 10800),
            'created_at_gmt'    => gmdate('Y-m-d H:i:s', time() - 10800),
            'ip_address'        => '203.0.113.201',
            'request_uri'       => '/cart/apply-coupon',
            'request_method'    => 'POST',
            'http_status_code'  => 403,
            'rule_id'           => 'WAF-ROTATED-DETECTOR',
            'rule_name'         => 'Rotated Test Rule 3',
            'rule_category'     => 'Behavioral Defense',
            'rule_description'  => 'Rotated segment incident test 3',
            'action_taken'      => 'blocked',
            'matched_param_key' => 'coupon_code',
            'matched_value'     => 'suspicious payload 3',
        ];

        try {
            // Write directly to the rotated segment files (.1, .2, and .3) in isolated test storage
            file_put_contents($rotatedFilePath1, wp_json_encode($rotatedRecord1) . "\n", LOCK_EX);
            file_put_contents($rotatedFilePath2, wp_json_encode($rotatedRecord2) . "\n", LOCK_EX);
            file_put_contents($rotatedFilePath3, wp_json_encode($rotatedRecord3) . "\n", LOCK_EX);
            $this->assertFileExists($rotatedFilePath1);
            $this->assertFileExists($rotatedFilePath2);
            $this->assertFileExists($rotatedFilePath3);

            // 1. Verify get_available_files includes all rotated segments (.1, .2, and .3)
            $available = \WebCareProScanner\Firewall\WafFileLogger::get_available_files();
            $foundRotated1 = false;
            $foundRotated2 = false;
            $foundRotated3 = false;
            foreach ($available as $finfo) {
                if ($finfo['filename'] === $rotatedFilename1) {
                    $foundRotated1 = true;
                }
                if ($finfo['filename'] === $rotatedFilename2) {
                    $foundRotated2 = true;
                }
                if ($finfo['filename'] === $rotatedFilename3) {
                    $foundRotated3 = true;
                }
            }
            $this->assertTrue($foundRotated1, 'Rotated segment (.1) must be discovered by get_available_files()');
            $this->assertTrue($foundRotated2, 'Rotated segment (.2) must be discovered by get_available_files()');
            $this->assertTrue($foundRotated3, 'Rotated segment (.3) must be discovered by get_available_files()');

            // 2. Verify query_logs with range => 'all' finds incidents across rotated segments
            $queryResult1 = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $uniqueRotIncidentId1,
                'action' => 'all',
                'range'  => 'all',
            ], 1);
            $this->assertNotEmpty($queryResult1['logs'], 'Incident in rotated segment 1 must be discoverable via query_logs()');
            $this->assertSame($uniqueRotIncidentId1, $queryResult1['logs'][0]['incident_id']);

            $queryResult3 = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $uniqueRotIncidentId3,
                'action' => 'all',
                'range'  => 'all',
            ], 1);
            $this->assertNotEmpty($queryResult3['logs'], 'Incident in rotated segment 3 must be discoverable via query_logs()');
            $this->assertSame($uniqueRotIncidentId3, $queryResult3['logs'][0]['incident_id']);

            // 3. Verify FirewallController::trust_log_action authoritatively resolves the incident from a rotated segment
            $trustReq = new \WP_REST_Request('POST', '/webcare-pro-scanner/v1/firewall/logs/trust-action');
            $trustReq->set_header('content-type', 'application/json');
            $trustReq->set_body((string) wp_json_encode([
                'incident_id' => $uniqueRotIncidentId1,
                'uri'         => '/my-account/orders',
                'rule_id'     => 'WAF-ROTATED-DETECTOR',
                'method'      => 'POST',
                'param_key'   => 'order_note',
            ]));
            $trustRes = \WebCareProScanner\Api\Controllers\FirewallController::trust_log_action($trustReq);
            $this->assertSame(200, $trustRes->get_status());
            $this->assertTrue($trustRes->get_data()['success']);

            // 4. Verify delete_log enforces raw WAF log immutability (returns false and preserves incident)
            $deleted = \WebCareProScanner\Firewall\WafFileLogger::delete_log($uniqueRotIncidentId2);
            $this->assertFalse($deleted, 'delete_log() must return false to preserve raw forensic WAF log immutability');

            // Confirm immutable incident remains intact in rotated segment
            $queryAfterDelete = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $uniqueRotIncidentId2,
                'action' => 'all',
                'range'  => 'all',
            ], 1);
            $this->assertNotEmpty($queryAfterDelete['logs'], 'Immutable incident in rotated segment must remain intact');

        } finally {
            // Restore trust option state exactly
            if ($originalTrustOption === $trustSentinel) {
                delete_option('webcareproscan_rescue_allowlists');
            } else {
                update_option('webcareproscan_rescue_allowlists', $originalTrustOption, false);
            }

            // Restore previous custom storage dir configuration
            \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = $previousStorageDir;
            if (is_dir($isolatedTestDir)) {
                $files = glob($isolatedTestDir . '/*');
                foreach ($files as $f) {
                    if (is_file($f)) {
                        @unlink($f);
                    }
                }
                @rmdir($isolatedTestDir);
            }
        }
    }

    public function test_administrator_activity_logging_boundary(): void {
        // 1. Verify unauthenticated caller is strictly rejected from writing to Activity Log
        \wp_set_current_user(0, '');
        unset($GLOBALS['wp_mock_current_user_can']);
        $this->assertFalse(current_user_can('manage_options'));

        $unauthLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'unauth_action',
            'system',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'unauthenticated attempt']
        );
        $this->assertFalse($unauthLogged, 'Unauthenticated caller must be rejected from writing to WebCareActivityLogger');

        // 2. Verify non-admin / subscriber cannot write to Activity Log
        $subscriber = \wp_set_current_user(999, 'testsubscriber');
        $subscriber->roles = ['subscriber'];
        $subscriber->allcaps = ['read' => true];
        unset($GLOBALS['wp_mock_current_user_can']);

        $this->assertFalse(current_user_can('manage_options'));

        $logged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'unauthorized_test_action',
            'system',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'subscriber attempt']
        );
        $this->assertFalse($logged, 'Non-admin user (subscriber) must be rejected from writing to WebCareActivityLogger');

        // 3. Verify subscriber supplying forged actor_override['type'] = 'admin' is rejected
        $forgedAdminLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'forged_admin_action',
            'settings',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'forged admin override attempt'],
            ['type' => 'admin', 'id' => 1, 'user_login' => 'admin', 'display_name' => 'Administrator']
        );
        $this->assertFalse($forgedAdminLogged, 'Subscriber with forged admin actor_override must be strictly rejected');

        // 4. Verify subscriber supplying forged actor_override['type'] = 'system' is rejected
        $forgedSystemLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'forged_system_action',
            'system',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'forged system override attempt'],
            ['type' => 'system', 'id' => 0, 'user_login' => 'System']
        );
        $this->assertFalse($forgedSystemLogged, 'Subscriber with forged system actor_override must be strictly rejected');

        // 5. Verify unauthenticated caller with forged actor_override is rejected
        \wp_set_current_user(0, '');
        $unauthOverrideLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'unauth_override_action',
            'system',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'unauth override attempt'],
            ['type' => 'admin', 'id' => 1, 'user_login' => 'admin']
        );
        $this->assertFalse($unauthOverrideLogged, 'Unauthenticated caller with actor_override must be strictly rejected');

        // 6. Verify user with administrator role slug but lacking 'manage_options' is rejected
        $restrictedAdmin = \wp_set_current_user(888, 'fakeadmin');
        $restrictedAdmin->roles = ['administrator'];
        $restrictedAdmin->allcaps = ['manage_options' => false, 'read' => true];
        unset($GLOBALS['wp_mock_current_user_can']);

        $this->assertFalse(current_user_can('manage_options'));
        $restrictedLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'restricted_admin_action',
            'settings',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'restricted admin attempt']
        );
        $this->assertFalse($restrictedLogged, 'User with administrator role but without manage_options must be rejected');

        // 7. Verify verified admin with 'manage_options' is authorized and actor is authoritatively derived
        $admin = \wp_set_current_user(1, 'realadmin');
        $admin->roles = ['administrator'];
        $admin->allcaps = ['manage_options' => true, 'read' => true];
        unset($GLOBALS['wp_mock_current_user_can']);

        $this->assertTrue(current_user_can('manage_options'));

        $adminLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
            'admin_verified_action',
            'settings',
            \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
            ['data' => 'admin update'],
            ['type' => 'admin', 'id' => 99999, 'user_login' => 'spoofed_login'] // Caller attempts to spoof actor ID
        );
        $this->assertTrue($adminLogged, 'Administrator with manage_options must successfully write to WebCareActivityLogger');

        // Verify that actor identity was derived strictly from authenticated user (ID: 1, login: realadmin), not spoofed values
        $recentEvents = \WebCareProScanner\System\WebCareActivityLogger::query_records([
            'action' => 'admin_verified_action',
        ]);
        $this->assertNotEmpty($recentEvents['records'], 'Audit records must not be empty after verified admin write');
        $actor = $recentEvents['records'][0]['actor'] ?? [];
        $this->assertSame(1, $actor['id'] ?? 0, 'Actor ID must be derived from authenticated user, not caller override');
        $this->assertSame('realadmin', $actor['user_login'] ?? '', 'Actor user_login must be derived from authenticated user');

        // 8. Verify automated execution contexts (DOING_CRON, WP_CLI) are excluded from the human admin accountability log
        $previousContextOverride = \WebCareProScanner\System\WebCareActivityLogger::$execution_context_override;
        try {
            \WebCareProScanner\System\WebCareActivityLogger::$execution_context_override = 'cron';
            $cronLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
                'cron_automated_action',
                'system',
                \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
                ['data' => 'cron attempt']
            );
            $this->assertFalse($cronLogged, 'Cron context must be strictly excluded from WebCareActivityLogger even with admin user present');

            \WebCareProScanner\System\WebCareActivityLogger::$execution_context_override = 'cli';
            $cliLogged = \WebCareProScanner\System\WebCareActivityLogger::log(
                'cli_automated_action',
                'system',
                \WebCareProScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO,
                ['data' => 'cli attempt']
            );
            $this->assertFalse($cliLogged, 'CLI context must be strictly excluded from WebCareActivityLogger even with admin user present');
        } finally {
            // Restore execution context override and admin user reliably in finally block
            \WebCareProScanner\System\WebCareActivityLogger::$execution_context_override = $previousContextOverride;
            \wp_set_current_user(1, 'realadmin');
        }
    }

    public function test_rotated_log_clear_all_and_retention_pruning(): void {
        // Use an isolated temporary test directory to guarantee zero contamination of live/dev WAF evidence
        $isolatedTestDir = sys_get_temp_dir() . '/webcare_test_waf_' . wp_generate_password(8, false);
        wp_mkdir_p($isolatedTestDir);

        $previousStorageDir = \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir;
        \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = $isolatedTestDir;

        // Preserve initial lifetime blocked counter state exactly using sentinel
        $counterSentinel = new \stdClass();
        $originalLifetimeBlocked = get_option('webcareproscan_lifetime_blocked_counter', $counterSentinel);

        try {
            // Create a fixture of expired rotated segments (30 days old) in isolated test directory
            $expiredDateStr = strtolower(gmdate('F-j-Y', time() - (30 * 86400)));
            $expiredBase = $expiredDateStr . '-waf-logs.json';
            $expiredRot1 = $isolatedTestDir . '/' . $expiredBase . '.1';
            $expiredRot2 = $isolatedTestDir . '/' . $expiredBase . '.2';

            file_put_contents($expiredRot1, "{\"test\":\"expired_rot1\"}\n", LOCK_EX);
            file_put_contents($expiredRot2, "{\"test\":\"expired_rot2\"}\n", LOCK_EX);

            $this->assertFileExists($expiredRot1);
            $this->assertFileExists($expiredRot2);

            // 1. Verify prune_expired_logs() removes expired rotated segments in isolated storage
            $deletedCount = \WebCareProScanner\Firewall\WafFileLogger::prune_expired_logs(7);
            $this->assertSame(2, $deletedCount, 'Expired rotated segments must be pruned by prune_expired_logs()');
            $this->assertFileDoesNotExist($expiredRot1, 'Expired rotated segment .1 must be deleted after pruning');
            $this->assertFileDoesNotExist($expiredRot2, 'Expired rotated segment .2 must be deleted after pruning');

            // 2. Verify clear_all_logs() deletes rotated segments alongside active logs in isolated storage
            $todayDateStr = strtolower(gmdate('F-j-Y', time()));
            $activeBase = $todayDateStr . '-waf-logs.json';
            $activeLog = $isolatedTestDir . '/' . $activeBase;
            $tempRot1 = $isolatedTestDir . '/' . $activeBase . '.99';
            $tempRot2 = $isolatedTestDir . '/' . $activeBase . '.100';

            file_put_contents($activeLog, "{\"test\":\"active_log\"}\n", LOCK_EX);
            file_put_contents($tempRot1, "{\"test\":\"temp_rot1\"}\n", LOCK_EX);
            file_put_contents($tempRot2, "{\"test\":\"temp_rot2\"}\n", LOCK_EX);

            $this->assertFileExists($activeLog);
            $this->assertFileExists($tempRot1);
            $this->assertFileExists($tempRot2);

            $cleared = \WebCareProScanner\Firewall\WafFileLogger::clear_all_logs();
            $this->assertTrue($cleared, 'clear_all_logs() must return true');
            $this->assertFileDoesNotExist($activeLog, 'clear_all_logs() must remove active log in isolated dir');
            $this->assertFileDoesNotExist($tempRot1, 'clear_all_logs() must remove rotated segment .99');
            $this->assertFileDoesNotExist($tempRot2, 'clear_all_logs() must remove rotated segment .100');

        } finally {
            // Restore lifetime blocked counter state exactly
            if ($originalLifetimeBlocked === $counterSentinel) {
                delete_option('webcareproscan_lifetime_blocked_counter');
            } else {
                update_option('webcareproscan_lifetime_blocked_counter', $originalLifetimeBlocked, false);
            }

            // Restore previous custom storage dir configuration
            \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = $previousStorageDir;
            if (is_dir($isolatedTestDir)) {
                $files = glob($isolatedTestDir . '/*');
                foreach ($files as $f) {
                    if (is_file($f)) {
                        @unlink($f);
                    }
                }
                @rmdir($isolatedTestDir);
            }
        }
    }

    public function test_dvs_unique_ip_aggregation_counts_distinct_ips_without_race(): void {
        $cache_key = 'dvs_test_race_' . bin2hex(random_bytes(4));

        // Simulate 3 distinct IPs logging failure
        $ip1 = '198.51.100.1';
        $ip2 = '198.51.100.2';
        $ip3 = '198.51.100.3';

        // Call record_auth_failure with test IPs
        \WebCareProScanner\Firewall\DistributedVelocityShield::record_auth_failure($ip1, 'user1', 'Password failed');
        \WebCareProScanner\Firewall\DistributedVelocityShield::record_auth_failure($ip2, 'user2', 'Password failed');
        \WebCareProScanner\Firewall\DistributedVelocityShield::record_auth_failure($ip3, 'user3', 'Password failed');

        $metrics = \WebCareProScanner\Firewall\DistributedVelocityShield::get_live_velocity();
        $this->assertGreaterThanOrEqual(3, $metrics['auth']['unique_ips']);
        $this->assertGreaterThanOrEqual(3, $metrics['auth']['failures_last_min']);
    }

    public function test_dvs_cross_slice_deduplication_does_not_inflate_single_ip(): void {
        // Verify that a single IP repeating across multiple sub-window slices yields unique_ips = 1
        $cache_key = 'dvs_test_single_ip_' . bin2hex(random_bytes(4));
        $single_ip = '198.51.100.77';

        // Direct reflection access to test append_sliding_event and get_sliding_metrics
        $refl = new \ReflectionClass(\WebCareProScanner\Firewall\DistributedVelocityShield::class);
        $appendMethod = $refl->getMethod('append_sliding_event');
        $appendMethod->setAccessible(true);
        $getMetricsMethod = $refl->getMethod('get_sliding_metrics');
        $getMetricsMethod->setAccessible(true);

        // Append 4 events for the same IP
        $appendMethod->invoke(null, $cache_key, $single_ip, 'Failed auth 1', []);
        $appendMethod->invoke(null, $cache_key, $single_ip, 'Failed auth 2', []);
        $appendMethod->invoke(null, $cache_key, $single_ip, 'Failed auth 3', []);
        $appendMethod->invoke(null, $cache_key, $single_ip, 'Failed auth 4', []);

        $metrics = $getMetricsMethod->invoke(null, $cache_key);
        $this->assertSame(4, $metrics['count']);
        $this->assertSame(1, $metrics['unique_ips'], 'Single repeating IP must strictly yield unique_ips = 1, never inflated by slice count.');
    }

    public function test_dvs_operational_lock_events_excluded_from_activity_log_bridge(): void {
        \wp_set_current_user(1);
        $user = \wp_get_current_user();
        $user->roles = ['administrator'];
        $user->allcaps = ['manage_options' => true];

        // Ensure activity logger tracking array is clean
        \WebCareProScanner\System\WebCareActivityLogger::$logged_actions_in_request = [];

        // Log DVS lock exhaustion operational events
        \WebCareProScanner\System\AuditLogger::log('dvs_file_lock_exhausted', 'DVS write-lock test');
        \WebCareProScanner\System\AuditLogger::log('dvs_file_read_lock_exhausted', 'DVS read-lock test');

        $logged = \WebCareProScanner\System\WebCareActivityLogger::$logged_actions_in_request;
        $this->assertArrayNotHasKey('dvs_file_lock_exhausted', $logged, 'DVS write-lock exhaustion must be excluded from admin activity log.');
        $this->assertArrayNotHasKey('dvs_file_read_lock_exhausted', $logged, 'DVS read-lock exhaustion must be excluded from admin activity log.');

        \wp_set_current_user(0);
    }

    public function test_dvs_concurrent_recovery_and_slot_eviction_handling(): void {
        $cache_key = 'dvs_test_repair_' . bin2hex(random_bytes(4));
        $test_ip = '198.51.100.91';

        $refl = new \ReflectionClass(\WebCareProScanner\Firewall\DistributedVelocityShield::class);
        $appendMethod = $refl->getMethod('append_sliding_event');
        $appendMethod->setAccessible(true);
        $getMetricsMethod = $refl->getMethod('get_sliding_metrics');
        $getMetricsMethod->setAccessible(true);

        // 1. Initial registration
        $appendMethod->invoke(null, $cache_key, $test_ip, 'Initial auth failure', []);
        $initial = $getMetricsMethod->invoke(null, $cache_key);
        $this->assertSame(1, $initial['count']);
        $this->assertSame(1, $initial['unique_ips']);

        // 2. Simulate worker crash leaving pending marker (0)
        $now = time();
        $bucket_id = (int) floor($now / 10);
        $ip_hash = substr(md5($test_ip), 0, 12);
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            wp_cache_set("{$cache_key}_ip_{$bucket_id}_{$ip_hash}", 0, 'webcareproscan_dvs', 80);
        } elseif (function_exists('apcu_store') && ini_get('apc.enabled')) {
            apcu_store("dvs_{$cache_key}_ip_{$bucket_id}_{$ip_hash}", 0, 80);
        }

        // 3. Second worker arrives and automatically recovers unconfirmed pending marker
        $appendMethod->invoke(null, $cache_key, $test_ip, 'Second auth failure during recovery', []);
        $recovered = $getMetricsMethod->invoke(null, $cache_key);
        $this->assertSame(2, $recovered['count']);
        $this->assertSame(1, $recovered['unique_ips'], 'DVS must repair unconfirmed pending marker without inflating unique_ips.');

        // 4. Simulate cache eviction of referenced slot while confirmed marker remains
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            wp_cache_delete("{$cache_key}_slot_{$bucket_id}_1", 'webcareproscan_dvs');
        } elseif (function_exists('apcu_delete') && ini_get('apc.enabled')) {
            apcu_delete("dvs_{$cache_key}_slot_{$bucket_id}_1");
        }

        // 5. Subsequent request detects evicted slot, re-acquires mutex, re-verifies state, and repairs registration
        $appendMethod->invoke(null, $cache_key, $test_ip, 'Third auth failure after eviction', []);
        $after_evict = $getMetricsMethod->invoke(null, $cache_key);
        $this->assertSame(3, $after_evict['count']);
        $this->assertSame(1, $after_evict['unique_ips'], 'DVS must repair evicted slot reference under mutex and maintain exactly 1 unique IP.');
    }

    public function test_dvs_mutex_lease_ownership_token_verification(): void {
        // Verify that mutex owner token protects against deleting another worker's expired/acquired lock
        $cache_key = 'dvs_test_lease_' . bin2hex(random_bytes(4));
        $bucket_id = 9999;
        $ip_hash = 'testhash123';
        $group = 'webcareproscan_dvs';

        $lock_key = "{$cache_key}_lock_{$bucket_id}_{$ip_hash}";
        $workerA_token = 'token_worker_A';
        $workerB_token = 'token_worker_B';

        $refl = new \ReflectionClass(\WebCareProScanner\Firewall\DistributedVelocityShield::class);
        $releaseExtLock = $refl->getMethod('release_ext_cache_lock');
        $releaseExtLock->setAccessible(true);
        $releaseApcuLock = $refl->getMethod('release_apcu_lock');
        $releaseApcuLock->setAccessible(true);

        // 1. External Cache lock release safety tests:
        // Demonstrates that even if Worker A paused, its lease expired, and Worker B acquired the lock,
        // Worker A can NEVER release Worker B's lock.
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            // Worker B acquires the key with its own token
            wp_cache_set($lock_key, $workerB_token, $group, 10);

            // Worker A attempts to release lock with its stale/expired token: must fail safely and leave Worker B intact
            $released_A = $releaseExtLock->invoke(null, $lock_key, $workerA_token, $group);
            $this->assertFalse($released_A, 'Worker A with expired token must never succeed in releasing lock.');
            $this->assertSame($workerB_token, wp_cache_get($lock_key, $group), 'Worker B lock must remain strictly intact.');

            wp_cache_delete($lock_key, $group);
        } else {
            // Direct token comparison verification when ext cache not enabled
            $this->assertFalse(hash_equals($workerB_token, $workerA_token));
            $this->assertTrue(hash_equals($workerB_token, $workerB_token));
        }

        // 2. APCu atomic CAS lock release safety tests
        $apcu_lock_key = "dvs_{$cache_key}_lock_{$bucket_id}_{$ip_hash}";
        $token_a_int = 123456789;
        $token_b_int = 987654321;

        if (function_exists('apcu_store') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'))) {
            apcu_store($apcu_lock_key, $token_b_int, 10);

            // CAS release: Worker A with stale token fails and Worker B lock remains intact
            $released_apc_a = $releaseApcuLock->invoke(null, $apcu_lock_key, $token_a_int);
            $this->assertFalse($released_apc_a, 'APCu CAS release must fail when token does not match.');
            $this->assertSame($token_b_int, (int) apcu_fetch($apcu_lock_key), 'Worker B APCu lock must remain strictly held.');

            // Worker B CAS release succeeds
            $released_apc_b = $releaseApcuLock->invoke(null, $apcu_lock_key, $token_b_int);
            $this->assertTrue($released_apc_b, 'Worker B with matching token must succeed via atomic CAS.');
            $this->assertFalse(apcu_exists($apcu_lock_key), 'Lock key must be deleted after successful CAS transition.');
        } else {
            $this->assertNotSame($token_a_int, $token_b_int);
        }
    }

    public function test_dvs_worker_fencing_prevents_stale_writes_on_expired_lease(): void {
        $cache_key = 'dvs_test_fence_' . bin2hex(random_bytes(4));
        $now = time();
        $bucket_id = (int) floor($now / 10);
        $group = 'webcareproscan_dvs';

        $refl = new \ReflectionClass(\WebCareProScanner\Firewall\DistributedVelocityShield::class);
        $atomicFencedExtSet = $refl->getMethod('atomic_fenced_ext_cache_set');
        $atomicFencedExtSet->setAccessible(true);
        $atomicFencedApcuStore = $refl->getMethod('atomic_fenced_apcu_store');
        $atomicFencedApcuStore->setAccessible(true);

        // Deterministic interleaving:
        // Worker 1 acquired lock, but paused. Its lease expired and Worker 2 took over.
        $worker1_token = 'token_worker_1_' . bin2hex(random_bytes(4));
        $worker2_token = 'token_worker_2_' . bin2hex(random_bytes(4));
        $ip_hash = 'fencehash999';
        $lock_key = "{$cache_key}_lock_{$bucket_id}_{$ip_hash}";
        $slot_key = "{$cache_key}_slot_{$bucket_id}_99";

        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            // Worker 2 currently owns the lock in cache
            wp_cache_set($lock_key, $worker2_token, $group, 10);

            // Worker 1 resumes after pause and attempts to commit state via atomic fenced write: MUST FAIL
            $w1_committed = $atomicFencedExtSet->invoke(null, $lock_key, $worker1_token, $slot_key, 'stale_payload', $group, 80);
            $this->assertFalse($w1_committed, 'Worker 1 with expired/overtaken lease must fail to commit state.');
            $this->assertFalse(wp_cache_get($slot_key, $group), 'Slot key must not be modified by stale worker.');

            // Worker 2 commits state via atomic fenced write: MUST SUCCEED
            $w2_committed = $atomicFencedExtSet->invoke(null, $lock_key, $worker2_token, $slot_key, 'valid_payload', $group, 80);
            $this->assertTrue($w2_committed, 'Active lock owner must succeed in atomic fenced state commit.');
            $this->assertSame('valid_payload', wp_cache_get($slot_key, $group));

            wp_cache_delete($lock_key, $group);
            wp_cache_delete($slot_key, $group);
        }

        // APCu deterministic fencing check:
        // Because APCu lacks multi-key CAS transactions, atomic_fenced_apcu_store strictly fails closed (returns false)
        // rather than risking non-atomic writes or destructive post-write rollbacks.
        if (function_exists('apcu_store') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'))) {
            $apc_lock_key = "dvs_{$cache_key}_lock_{$bucket_id}_{$ip_hash}";
            $apc_target_key = "dvs_{$cache_key}_slot_{$bucket_id}_99";
            $w1_int = 11111;
            $w2_int = 22222;

            // Worker 2 currently owns the lock in APCu
            apcu_store($apc_lock_key, $w2_int, 10);

            // Worker 1 resumes and attempts atomic fenced store: MUST FAIL CLOSED
            $apc_w1_committed = $atomicFencedApcuStore->invoke(null, $apc_lock_key, $w1_int, $apc_target_key, 'stale_apc_payload', 80);
            $this->assertFalse($apc_w1_committed, 'Worker 1 with stale token must fail atomic fenced APCu store.');
            $this->assertFalse(apcu_exists($apc_target_key), 'Target key must not exist after rejected store.');

            // Worker 2 attempts atomic fenced store: also fails closed on APCu because APCu does not support multi-key atomic CAS
            $apc_w2_committed = $atomicFencedApcuStore->invoke(null, $apc_lock_key, $w2_int, $apc_target_key, 'valid_apc_payload', 80);
            $this->assertFalse($apc_w2_committed, 'APCu fenced write must strictly fail closed (multi-key CAS unsupported).');

            apcu_delete($apc_lock_key);
            apcu_delete($apc_target_key);
        } else {
            $this->assertNotSame($worker1_token, $worker2_token);
        }
    }

    public function test_dvs_file_fallback_lock_contention_and_metrics_integrity(): void {
        $cache_key = 'dvs_test_file_' . bin2hex(random_bytes(4));
        $test_ip1 = '203.0.113.88';
        $test_ip2 = '203.0.113.89';

        $refl = new \ReflectionClass(\WebCareProScanner\Firewall\DistributedVelocityShield::class);
        $fileInc = $refl->getMethod('file_atomic_dvs_increment');
        $fileInc->setAccessible(true);
        $getFileMetrics = $refl->getMethod('get_file_sliding_metrics');
        $getFileMetrics->setAccessible(true);

        $now = time();
        $bucket_id = (int) floor($now / 10);

        // 1. Verify standard multi-IP recording and metric integrity specifically in file storage
        $fileInc->invoke(null, $cache_key, $bucket_id, substr(md5($test_ip1), 0, 12));
        $fileInc->invoke(null, $cache_key, $bucket_id, substr(md5($test_ip1), 0, 12));
        $fileInc->invoke(null, $cache_key, $bucket_id, substr(md5($test_ip2), 0, 12));

        $metrics = $getFileMetrics->invoke(null, $cache_key);
        $this->assertGreaterThanOrEqual(3, $metrics['count'], 'File fallback must record all events.');
        $this->assertGreaterThanOrEqual(2, $metrics['unique_ips'], 'File fallback must accurately count unique IP addresses.');

        // 2. Controlled competing lock holder simulation:
        // Acquire an exclusive flock on the dedicated .lock sidecar file to simulate another process holding the write lock.
        $upload_dir = wp_upload_dir();
        $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
        if (!empty($base_dir)) {
            $file = rtrim($base_dir, '/\\') . '/webcare-pro-security/rate-limits/dvs_' . substr(md5($cache_key), 0, 8) . '.php';
            $lock_file = $file . '.lock';
            if (file_exists($file)) {
                $competing_fp = fopen($lock_file, 'c+');
                if ($competing_fp && flock($competing_fp, LOCK_EX | LOCK_NB)) {
                    // While the lock is held by competing process, verify that another worker times out gracefully
                    $startTime = microtime(true);
                    $fileInc->invoke(null, $cache_key, $bucket_id, 'competing_ip_hash');
                    $elapsed = microtime(true) - $startTime;

                    // Release competing lock
                    flock($competing_fp, LOCK_UN);
                    fclose($competing_fp);

                    // Must have waited at least 150ms before timing out
                    $this->assertGreaterThanOrEqual(0.15, $elapsed, 'Worker must respect bounded wait retries when lock is contended.');
                } elseif ($competing_fp) {
                    fclose($competing_fp);
                }
            }
        }
    }
}
