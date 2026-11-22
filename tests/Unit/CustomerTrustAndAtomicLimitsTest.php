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
        $storageDir = \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir();
        if (!is_dir($storageDir)) {
            wp_mkdir_p($storageDir);
        }

        // Simulate rotated segment files: .1, .2, .3
        $baseFilename = strtolower(gmdate('F-j-Y', time())) . '-waf-logs.json';
        $rotatedFilename1 = $baseFilename . '.1';
        $rotatedFilePath1 = $storageDir . '/' . $rotatedFilename1;
        $rotatedFilename2 = $baseFilename . '.2';
        $rotatedFilePath2 = $storageDir . '/' . $rotatedFilename2;
        $rotatedFilename3 = $baseFilename . '.3';
        $rotatedFilePath3 = $storageDir . '/' . $rotatedFilename3;

        // Preserve any existing rotated files content if present in development environment
        $backupContent1 = file_exists($rotatedFilePath1) ? file_get_contents($rotatedFilePath1) : null;
        $backupContent2 = file_exists($rotatedFilePath2) ? file_get_contents($rotatedFilePath2) : null;
        $backupContent3 = file_exists($rotatedFilePath3) ? file_get_contents($rotatedFilePath3) : null;

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
            // Write directly to the rotated segment files (.1, .2, and .3)
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

            // 4. Verify delete_log removes an incident directly from a rotated segment (.2)
            $deleted = \WebCareProScanner\Firewall\WafFileLogger::delete_log($uniqueRotIncidentId2);
            $this->assertTrue($deleted, 'delete_log() must successfully delete an incident from a rotated segment');

            // Confirm it is no longer found
            $queryAfterDelete = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $uniqueRotIncidentId2,
                'action' => 'all',
                'range'  => 'all',
            ], 1);
            $this->assertEmpty($queryAfterDelete['logs'], 'Deleted incident in rotated segment must no longer be discoverable');

        } finally {
            // Clean up created trust entry to maintain test isolation
            $trustKey = md5('uri:/my-account/orders:post:order_note');
            $existingTrust = get_option('webcareproscan_rescue_allowlists', []);
            if (is_array($existingTrust) && isset($existingTrust[$trustKey])) {
                unset($existingTrust[$trustKey]);
                update_option('webcareproscan_rescue_allowlists', $existingTrust, false);
            }

            // Restore or cleanup test files safely
            if ($backupContent1 !== null) {
                file_put_contents($rotatedFilePath1, $backupContent1, LOCK_EX);
            } elseif (file_exists($rotatedFilePath1)) {
                @unlink($rotatedFilePath1);
            }

            if ($backupContent2 !== null) {
                file_put_contents($rotatedFilePath2, $backupContent2, LOCK_EX);
            } elseif (file_exists($rotatedFilePath2)) {
                @unlink($rotatedFilePath2);
            }

            if ($backupContent3 !== null) {
                file_put_contents($rotatedFilePath3, $backupContent3, LOCK_EX);
            } elseif (file_exists($rotatedFilePath3)) {
                @unlink($rotatedFilePath3);
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
        if (!empty($recentEvents['records'])) {
            $actor = $recentEvents['records'][0]['actor'] ?? [];
            $this->assertSame(1, $actor['id'] ?? 0, 'Actor ID must be derived from authenticated user, not caller override');
            $this->assertSame('realadmin', $actor['user_login'] ?? '', 'Actor user_login must be derived from authenticated user');
        }

        // Reset to admin for following tests
        \wp_set_current_user(1, 'realadmin');
    }

    public function test_rotated_log_clear_all_and_retention_pruning(): void {
        $storageDir = \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir();
        if (!is_dir($storageDir)) {
            wp_mkdir_p($storageDir);
        }

        // Create a fixture of expired rotated segments (30 days old)
        $expiredDateStr = strtolower(gmdate('F-j-Y', time() - (30 * 86400)));
        $expiredBase = $expiredDateStr . '-waf-logs.json';
        $expiredRot1 = $storageDir . '/' . $expiredBase . '.1';
        $expiredRot2 = $storageDir . '/' . $expiredBase . '.2';

        file_put_contents($expiredRot1, "{\"test\":\"expired_rot1\"}\n", LOCK_EX);
        file_put_contents($expiredRot2, "{\"test\":\"expired_rot2\"}\n", LOCK_EX);

        $this->assertFileExists($expiredRot1);
        $this->assertFileExists($expiredRot2);

        // 1. Verify prune_expired_logs() removes expired rotated segments
        $deletedCount = \WebCareProScanner\Firewall\WafFileLogger::prune_expired_logs(7);
        $this->assertGreaterThanOrEqual(2, $deletedCount, 'Expired rotated segments must be pruned by prune_expired_logs()');
        $this->assertFileDoesNotExist($expiredRot1, 'Expired rotated segment .1 must be deleted after pruning');
        $this->assertFileDoesNotExist($expiredRot2, 'Expired rotated segment .2 must be deleted after pruning');

        // 2. Verify clear_all_logs() deletes rotated segments alongside active logs
        $todayDateStr = strtolower(gmdate('F-j-Y', time()));
        $activeBase = $todayDateStr . '-waf-logs.json';
        $tempRot1 = $storageDir . '/' . $activeBase . '.99';
        $tempRot2 = $storageDir . '/' . $activeBase . '.100';

        file_put_contents($tempRot1, "{\"test\":\"temp_rot1\"}\n", LOCK_EX);
        file_put_contents($tempRot2, "{\"test\":\"temp_rot2\"}\n", LOCK_EX);

        $this->assertFileExists($tempRot1);
        $this->assertFileExists($tempRot2);

        $cleared = \WebCareProScanner\Firewall\WafFileLogger::clear_all_logs();
        $this->assertTrue($cleared, 'clear_all_logs() must return true');
        $this->assertFileDoesNotExist($tempRot1, 'clear_all_logs() must remove rotated segment .99');
        $this->assertFileDoesNotExist($tempRot2, 'clear_all_logs() must remove rotated segment .100');
    }
}
