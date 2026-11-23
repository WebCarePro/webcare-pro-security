<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;
use WebCareProScanner\System\AuditLogger;

/**
 * ResponseDlpSentinelTest
 *
 * Regression test suite covering outbound Response DLP Sentinel bounded traversal,
 * inline secret redaction, large /wp-json/ index safety, circular reference handling,
 * fail-closed HTTP 503 behavior, and guest/logged-in isolation.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ResponseDlpSentinelTest extends TestCase {

    private string $tempLogDir;

    protected function setUp(): void {
        parent::setUp();
        ResponseDlpSentinel::$throw_mock_exception = false;
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_current_user'] = null;

        $this->tempLogDir = sys_get_temp_dir() . '/wcp_dlp_test_' . uniqid();
        if (!is_dir($this->tempLogDir)) {
            mkdir($this->tempLogDir, 0755, true);
        }
        AuditLogger::$custom_log_dir = $this->tempLogDir;
    }

    protected function tearDown(): void {
        ResponseDlpSentinel::$throw_mock_exception = false;
        AuditLogger::$custom_log_dir = null;
        if (is_dir($this->tempLogDir)) {
            $files = glob($this->tempLogDir . '/*');
            if (is_array($files)) {
                foreach ($files as $f) {
                    if (is_file($f)) {
                        @unlink($f);
                    }
                }
            }
            @rmdir($this->tempLogDir);
        }
        parent::tearDown();
    }

    /**
     * 1. Normal REST response passes through unchanged.
     */
    public function testNormalRestResponsePassesThroughUnchanged(): void {
        $data = [
            'id'    => 42,
            'title' => 'Hello World',
            'meta'  => [
                'status'  => 'published',
                'excerpt' => 'A legitimate benign post snippet.',
            ],
        ];

        $response = new \WP_REST_Response($data, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/posts/42');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(200, $filtered->get_status());
        $this->assertSame($data, $filtered->get_data());
        $this->assertEmpty(get_option(ResponseDlpSentinel::OPTION_EVENTS, []));
    }

    /**
     * 2. REST response containing a recognized secret is redacted and triggers handle_dlp_breach().
     */
    public function testRestResponseWithSecretIsRedactedAndTriggersBreachEvent(): void {
        $data = [
            'id'          => 101,
            'config_dump' => 'DB_PASSWORD: define("DB_PASSWORD", "SuperSecretPass123!");',
            'api_key'     => 'AKIAIOSFODNN7EXAMPLE',
        ];

        $response = new \WP_REST_Response($data, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/debug-dump');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(200, $filtered->get_status());

        $filteredData = $filtered->get_data();
        $this->assertIsArray($filteredData);
        $this->assertStringNotContainsString('SuperSecretPass123!', $filteredData['config_dump']);
        $this->assertStringContainsString('[REDACTED_BY_WEBCARE_DLP]', $filteredData['config_dump']);
        $this->assertStringNotContainsString('AKIAIOSFODNN7EXAMPLE', $filteredData['api_key']);
        $this->assertSame('[REDACTED_AWS_KEY]', $filteredData['api_key']);

        $events = get_option(ResponseDlpSentinel::OPTION_EVENTS, []);
        $this->assertNotEmpty($events, 'DLP breach event must be recorded in OPTION_EVENTS.');
        $this->assertSame('wp_config_secret_define', $events[0]['pattern']);
    }

    /**
     * 3. Realistic multi-route /wp-json/ index fixture (> 6,000 nodes, depth 6–8)
     * completes cleanly within approved budget (HTTP 200, no fatal, no false incident).
     */
    public function testRealisticMultiRouteWpJsonIndexCompletesCleanly(): void {
        // Build realistic multi-plugin /wp-json/ index with > 6,000 nodes and depth 6-8
        $index = [
            'name'        => 'My Production LMS & E-Commerce Site',
            'description' => 'Just another WordPress site',
            'url'         => 'https://example.com',
            'home'        => 'https://example.com',
            'namespaces'  => [
                'wp/v2',
                'wc/v3',
                'learndash/v2',
                'elementor/v1',
                'rankmath/v1',
                'wpforms/v1',
            ],
            'authentication' => [],
            'routes'         => [],
        ];

        for ($r = 0; $r < 400; $r++) {
            $routePath = '/custom/v1/resource-' . $r;
            $index['routes'][$routePath] = [
                'namespace' => 'custom/v1',
                'methods'   => ['GET', 'POST'],
                'endpoints' => [
                    [
                        'methods' => ['GET'],
                        'args'    => [
                            'context' => [
                                'required'          => false,
                                'default'           => 'view',
                                'enum'              => ['view', 'embed', 'edit'],
                                'type'              => 'string',
                                'sanitize_callback' => 'sanitize_key',
                                'validate_callback' => 'rest_validate_request_arg',
                            ],
                            'page' => [
                                'required' => false,
                                'default'  => 1,
                                'type'     => 'integer',
                            ],
                            'per_page' => [
                                'required' => false,
                                'default'  => 10,
                                'type'     => 'integer',
                            ],
                        ],
                    ],
                ],
                '_links' => [
                    'self' => [
                        ['href' => 'https://example.com/wp-json' . $routePath],
                    ],
                ],
            ];
        }

        $nodes = 0;
        $maxDepth = 0;
        $dummyLeak = false;
        $dummyPattern = '';
        $visited = [];
        ResponseDlpSentinel::redact_data_recursive($index, $dummyLeak, $dummyPattern, 0, $nodes, $visited, $maxDepth);

        $this->assertGreaterThan(6000, $nodes, 'Fixture must contain > 6,000 nodes.');
        $this->assertGreaterThanOrEqual(6, $maxDepth, 'Fixture depth must be at least 6.');
        $this->assertLessThanOrEqual(25, $maxDepth, 'Fixture depth must be within MAX_RECURSION_DEPTH.');

        $response = new \WP_REST_Response($index, 200);
        $request  = new \WP_REST_Request('GET', '/');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(200, $filtered->get_status());
        $this->assertEmpty(get_option(ResponseDlpSentinel::OPTION_EVENTS, []));
    }

    /**
     * 4. Shallow array exceeding MAX_RECURSION_NODES (> 25,000 nodes)
     * returns generic HTTP 503 WP_REST_Response with code webcare_dlp_inspection_unavailable and NO PHP fatal.
     */
    public function testShallowArrayExceedingNodeBudgetFailsClosedWith503(): void {
        $largeArray = [];
        for ($i = 0; $i < 25050; $i++) {
            $largeArray['key_' . $i] = 'val_' . $i;
        }

        $response = new \WP_REST_Response($largeArray, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/bulk-data');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(503, $filtered->get_status());
        $data = $filtered->get_data();
        $this->assertIsArray($data);
        $this->assertSame('webcare_dlp_inspection_unavailable', $data['code']);
        $this->assertSame('The response could not be safely inspected.', $data['message']);
    }

    /**
     * 5. Nested array/object exceeding MAX_RECURSION_DEPTH (> 25)
     * returns HTTP 503 and NO PHP fatal.
     */
    public function testNestedStructureExceedingDepthLimitFailsClosedWith503(): void {
        $deep = ['leaf' => 'deep_value'];
        for ($d = 0; $d < 28; $d++) {
            $deep = ['level_' . $d => $deep];
        }

        $response = new \WP_REST_Response($deep, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/deep-tree');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(503, $filtered->get_status());
        $data = $filtered->get_data();
        $this->assertSame('webcare_dlp_inspection_unavailable', $data['code']);
    }

    /**
     * 6. Circular object reference returns HTTP 503 and NO PHP fatal.
     */
    public function testCircularObjectReferenceFailsClosedWith503(): void {
        $objA = new \stdClass();
        $objB = new \stdClass();
        $objA->child = $objB;
        $objB->parent = $objA;

        $response = new \WP_REST_Response(['root' => $objA], 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/circular-graph');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(503, $filtered->get_status());
        $data = $filtered->get_data();
        $this->assertSame('webcare_dlp_inspection_unavailable', $data['code']);
    }

    /**
     * 7. Inspection failure does NOT record a DLP exfiltration breach in OPTION_EVENTS or ban the visitor,
     * and DOES record the operational diagnostic without response body data.
     */
    public function testInspectionFailureDoesNotRecordBreachAndLogsSanitizedDiagnostic(): void {
        $largeArray = [];
        for ($i = 0; $i < 25100; $i++) {
            $largeArray['k' . $i] = 'confidential_internal_payload_' . $i;
        }

        $response = new \WP_REST_Response($largeArray, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/unbounded-export');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertSame(503, $filtered->get_status());

        // Must NOT log exfiltration breach event
        $events = get_option(ResponseDlpSentinel::OPTION_EVENTS, []);
        $this->assertEmpty($events, 'No breach event should be recorded in OPTION_EVENTS on budget failure.');

        // Must write sanitized audit log without leaking the response body
        $auditLogFile = $this->tempLogDir . '/audit.log.php';
        $this->assertFileExists($auditLogFile);
        $logContents = file_get_contents($auditLogFile);

        $this->assertStringContainsString('dlp_inspection_limit_exceeded', $logContents);
        $this->assertStringContainsString('node_budget', $logContents);
        $this->assertTrue(
            str_contains($logContents, '/wp/v2/unbounded-export') || str_contains($logContents, '\/wp\/v2\/unbounded-export'),
            'Sanitized route must be logged in audit log.'
        );
        $this->assertStringNotContainsString('confidential_internal_payload_', $logContents);
    }

    /**
     * 8. Logged-in REST request bypasses DLP inspection as before.
     */
    public function testLoggedInUserBypassesDlpInspection(): void {
        $user = new \WP_User(1, 'administrator', ['administrator']);
        $GLOBALS['wp_mock_current_user'] = $user;

        // Even an array that would exceed bounds or contain raw secrets passes untouched for authenticated users
        $adminSecretData = [
            'aws_key'  => 'AKIAIOSFODNN7EXAMPLE',
            'overflow' => array_fill(0, 30000, 'item'),
        ];

        $response = new \WP_REST_Response($adminSecretData, 200);
        $request  = new \WP_REST_Request('GET', '/wp/v2/admin-settings');
        $server   = new \stdClass();

        $filtered = ResponseDlpSentinel::filter_rest_response($response, $server, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(200, $filtered->get_status());
        $this->assertSame($adminSecretData, $filtered->get_data(), 'Logged-in request must bypass DLP completely.');
        $this->assertEmpty(get_option(ResponseDlpSentinel::OPTION_EVENTS, []));
    }
}
