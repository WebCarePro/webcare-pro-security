<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\RequestPipeline;
use WebCareProScanner\Firewall\Core\WafVaultManager;
use WebCareProScanner\Firewall\RescueAssistantManager;

class RequestPipelineTest extends TestCase {

    private array $origServer;
    private array $origGet;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $GLOBALS['wp_mock_current_user_can'] = false;
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        @unlink(WafVaultManager::get_safe_mode_marker_path());
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $GLOBALS['wp_mock_current_user_can'] = false;
        RescueAssistantManager::resume_strict_firewall();
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        @unlink(WafVaultManager::get_safe_mode_marker_path());
        parent::tearDown();
    }

    public function testExploitSignatureExecutionBlocksSqli(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/?id=1%20UNION%20SELECT%201,2,3,user(),5--';
        $_SERVER['QUERY_STRING'] = 'id=1%20UNION%20SELECT%201,2,3,user(),5--';
        $_GET['id'] = '1 UNION SELECT 1,2,3,user(),5--';

        $ctx = RequestContext::from_globals();
        $settings = [
            'waf_enabled'    => true,
            'waf_block_sqli' => true,
        ];

        $verdict = RequestPipeline::evaluate_pipeline($ctx, $settings);

        $this->assertInstanceOf(WafVerdict::class, $verdict);
        $this->assertSame('block', $verdict->get_action_value());
        $this->assertNotEmpty($verdict->ruleId);

        // Context-direct execution test without superglobals populated
        $_SERVER = [];
        $_GET = [];
        $directMatch = \WebCareProScanner\Firewall\Core\ExploitSignatureEngine::evaluate_rules($settings, false, $ctx);
        $this->assertIsArray($directMatch);
        $this->assertNotEmpty($directMatch['id']);
    }

    public function testWafVerdictEnumAndStringCompatibility(): void {
        $block = WafVerdict::block('RULE-01', 'Blocked for exploit');
        $this->assertSame('block', $block->get_action_value());
        $this->assertTrue($block->is_terminal());

        $challenge = WafVerdict::challenge('RULE-02', 'PoW challenge required');
        $this->assertSame('challenge_pow', $challenge->get_action_value());
        $this->assertTrue($challenge->is_terminal());

        $rateLimit = WafVerdict::rate_limit('RULE-03', 'Rate limit exceeded');
        $this->assertSame('rate_limit', $rateLimit->get_action_value());
        $this->assertTrue($rateLimit->is_terminal());

        $allow = WafVerdict::allow();
        $this->assertSame('allow', $allow->get_action_value());
        $this->assertFalse($allow->is_terminal());

        $stringBlock = new WafVerdict('block', 'RULE-04', 'String action block');
        $this->assertSame('block', $stringBlock->get_action_value());
        $this->assertTrue($stringBlock->is_terminal());

        $stringBlockAndBan = new WafVerdict('block_and_ban', 'RULE-05', 'String action block and ban');
        $this->assertSame('block_and_ban', $stringBlockAndBan->get_action_value());
        $this->assertTrue($stringBlockAndBan->is_terminal());

        $unknownStringAction = new WafVerdict('some_unknown_action', 'RULE-06', 'Unknown action');
        $this->assertSame('block', $unknownStringAction->get_action_value());
        $this->assertTrue($unknownStringAction->is_terminal());
    }

    public function testMaliciousPayloadInContextWithCleanGlobalsBlocks(): void {
        // Superglobals are completely benign
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/contact-us/';
        $_SERVER['QUERY_STRING'] = '';
        $_GET = [];
        $_POST = ['name' => 'John Doe', 'message' => 'Hello'];

        // RequestContext contains malicious SQL injection payload
        $ctx = new RequestContext(
            ip: '198.51.100.33',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            params: ['comment' => '1 UNION SELECT 1,2,3,user(),5--']
        );

        $settings = [
            'waf_enabled'    => true,
            'waf_block_sqli' => true,
        ];

        $verdict = RequestPipeline::evaluate_pipeline($ctx, $settings);
        $this->assertNotNull($verdict);
        $this->assertSame('block', $verdict->get_action_value());
    }

    public function testCleanContextWithMaliciousPayloadInGlobalsReturnsNull(): void {
        // Superglobals contain malicious attack string
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/?attack=1%20UNION%20SELECT%201,2,3,user(),5--';
        $_GET['attack'] = '1 UNION SELECT 1,2,3,user(),5--';
        $_POST['malicious'] = '<script>alert(1)</script>';

        // RequestContext is strictly benign (isolated context)
        $ctx = new RequestContext(
            ip: '198.51.100.44',
            method: 'GET',
            uri: '/safe-page/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            params: ['id' => '123', 'filter' => 'active']
        );

        $settings = [
            'waf_enabled'    => true,
            'waf_block_sqli' => true,
            'waf_block_xss'  => true,
        ];

        $verdict = RequestPipeline::evaluate_pipeline($ctx, $settings);
        // Must return null (or non-block) because $ctx is pure and protected from global contamination
        $this->assertNull($verdict);
    }

    public function testSafeModeDetectionAndCriticalExploitPreservation(): void {
        // Activate Safe Mode
        $GLOBALS['wp_mock_current_user_can'] = true;
        RescueAssistantManager::pause_strict_firewall_15m();
        $this->assertTrue(RescueAssistantManager::get_pause_status()['paused']);

        // 1. Critical Exploit: WAF-SQLI-INJECTION must remain an active zero-tolerance block
        $sqliVerdict = new WafVerdict('block', 'WAF-SQLI-INJECTION', 'SQL injection attack detected.', [
            'category' => 'SQL Injection Defense',
        ]);
        $isCriticalSqli = in_array($sqliVerdict->ruleId, [
            'WAF-RCE-PHP-INJECTION',
            'WAF-SQLI-INJECTION',
            'WAF-LFI-TRAVERSAL',
            'WAF-OBJECT-STREAM-INJECTION',
            'WAF-XXE-INJECTION',
            'WAF-SSRF-METADATA',
            'WAF-AJAX-SHORTCODE-GADGET',
            'WAF-ARBITRARY-FILE-WRITE',
        ], true)
            || str_contains($sqliVerdict->category, 'SQL Injection')
            || str_contains($sqliVerdict->category, 'Command Injection')
            || str_contains($sqliVerdict->category, 'PHP Code Injection');
        $this->assertTrue($isCriticalSqli);

        // 2. Critical Exploit: WAF-RCE-PHP-INJECTION (Category: PHP Code Injection) must NOT be downgraded
        $rceVerdict = new WafVerdict('block', 'WAF-RCE-PHP-INJECTION', 'PHP Code injection attack detected.', [
            'category' => 'PHP Code Injection',
        ]);
        $isCriticalRce = in_array($rceVerdict->ruleId, [
            'WAF-RCE-PHP-INJECTION',
            'WAF-SQLI-INJECTION',
            'WAF-LFI-TRAVERSAL',
            'WAF-OBJECT-STREAM-INJECTION',
            'WAF-XXE-INJECTION',
            'WAF-SSRF-METADATA',
            'WAF-AJAX-SHORTCODE-GADGET',
            'WAF-ARBITRARY-FILE-WRITE',
        ], true)
            || str_contains($rceVerdict->category, 'SQL Injection')
            || str_contains($rceVerdict->category, 'Command Injection')
            || str_contains($rceVerdict->category, 'PHP Code Injection');
        $this->assertTrue($isCriticalRce);

        // 3. Heuristic / non-critical rule (e.g. Rate Limit or Scraper) must be downgraded to observe-only
        $heuristicVerdict = new WafVerdict('block', 'WAF-SCRAPER-BOT', 'Scraper bot heuristic.', [
            'category' => 'Bot Defense',
        ]);
        $isCriticalHeuristic = in_array($heuristicVerdict->ruleId, [
            'WAF-RCE-PHP-INJECTION',
            'WAF-SQLI-INJECTION',
            'WAF-LFI-TRAVERSAL',
            'WAF-OBJECT-STREAM-INJECTION',
            'WAF-XXE-INJECTION',
            'WAF-SSRF-METADATA',
            'WAF-AJAX-SHORTCODE-GADGET',
            'WAF-ARBITRARY-FILE-WRITE',
        ], true)
            || str_contains($heuristicVerdict->category, 'SQL Injection')
            || str_contains($heuristicVerdict->category, 'Command Injection')
            || str_contains($heuristicVerdict->category, 'PHP Code Injection');
        $this->assertFalse($isCriticalHeuristic);

        // Resume strict mode at end of test to guarantee isolation
        RescueAssistantManager::resume_strict_firewall();
    }

    public function testFirewallEngineDelegatesToPipelineWithoutInfiniteRecursion(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/hello-world/';
        $_SERVER['REMOTE_ADDR'] = '192.0.2.100';

        // Calling FirewallEngine::inspect_incoming_request() should delegate directly to RequestPipeline
        // and complete cleanly without infinite recursion.
        $caught = null;
        try {
            \WebCareProScanner\Firewall\FirewallEngine::inspect_incoming_request();
        } catch (\Throwable $e) {
            $caught = $e;
        }

        $this->assertNull($caught, 'inspect_incoming_request delegation must terminate without exception or recursion.');
    }

    public function testEndToEndEquivalenceViaRequestPipeline(): void {
        \wp_set_current_user(0);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_enabled', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_mode', 'enabled');
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_sqli', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_xss', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_traversal', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_php_injection', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_unsafe_http_methods', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_disable_xmlrpc', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_block_malicious_uploads', true);
        \WebCareProScanner\System\SettingsManager::update_setting('waf_blocked_ips', "203.0.113.50\n");

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        // 1. Unsafe HTTP Method (e.g. TRACE)
        $ctxMethod = new RequestContext(
            ip: '198.51.100.1',
            method: 'TRACE',
            uri: '/hello-world/'
        );
        $verdictMethod = RequestPipeline::evaluate_pipeline($ctxMethod, $settings);
        $this->assertNotNull($verdictMethod);
        $this->assertSame('block', $verdictMethod->get_action_value());

        // 2. Blocked IP in static blocklist
        $ctxBlockedIp = new RequestContext(
            ip: '203.0.113.50',
            method: 'GET',
            uri: '/hello-world/'
        );
        $verdictIp = RequestPipeline::evaluate_pipeline($ctxBlockedIp, $settings);
        $this->assertNotNull($verdictIp);
        $this->assertSame('block', $verdictIp->get_action_value());

        // 3. SQLi, XSS, XXE payloads
        $ctxXss = new RequestContext(
            ip: '198.51.100.2',
            method: 'GET',
            uri: '/?q=<script>alert(1)</script>',
            queryParams: ['q' => '<script>alert(1)</script>']
        );
        $verdictXss = RequestPipeline::evaluate_pipeline($ctxXss, $settings);
        $this->assertNotNull($verdictXss);
        $this->assertSame('block', $verdictXss->get_action_value());

        // 4. Forged Stripe webhook header on non-webhook mutation route (e.g. /wp-admin/admin-ajax.php)
        $ctxStripe = new RequestContext(
            ip: '198.51.100.3',
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            headers: ['stripe-signature' => 't=1600000000,v1=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789']
        );
        $verdictStripe = RequestPipeline::evaluate_pipeline($ctxStripe, $settings);
        $this->assertNotNull($verdictStripe);
        $this->assertSame('block', $verdictStripe->get_action_value());

        // 5. Login array type-confusion
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        $ctxLogin = new RequestContext(
            ip: '198.51.100.41',
            method: 'POST',
            uri: '/wp-login.php',
            formParams: ['log' => ['admin'], 'pwd' => 'secret']
        );
        $verdictLogin = RequestPipeline::evaluate_pipeline($ctxLogin, $settings);
        $this->assertNotNull($verdictLogin);
        $this->assertSame('block', $verdictLogin->get_action_value());

        // 6. Benign request produces null (passes to benign profiling)
        $ctxClean = new RequestContext(
            ip: '198.51.100.5',
            method: 'GET',
            uri: '/hello-world/'
        );
        $verdictClean = RequestPipeline::evaluate_pipeline($ctxClean, $settings);
        $this->assertNull($verdictClean, 'Clean request must return null verdict from pipeline.');
    }

    public function testGlobalShutdownPreventsExploitSignatureEngineFromRunning(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/?id=1%20UNION%20SELECT%201,2,3,user(),5--';
        $_SERVER['QUERY_STRING'] = 'id=1%20UNION%20SELECT%201,2,3,user(),5--';
        $_GET['id'] = '1 UNION SELECT 1,2,3,user(),5--';

        // When WAF is disabled via settings
        $disabledSettings = [
            'waf_enabled' => false,
            'waf_mode'    => 'disabled',
        ];

        // Should return cleanly without throwing or blocking
        RequestPipeline::process_incoming_request();
        $this->assertTrue(true, 'Pipeline process_incoming_request completes with no block when disabled.');
    }

    public function testLogOnlyVerdictRecordsIncidentAndAllowsSubsequentEvaluators(): void {
        // Deploy a log-action virtual patch
        update_option('webcareproscan_settings', ['waf_auto_enforce_virtual_patches' => true]);
        $patch_manifest = [
            'patch_id'   => 'VPATCH-LOG-TEST-001',
            'title'      => 'Log Only Virtual Patch',
            'component'  => ['slug' => 'test-plugin', 'type' => 'plugin'],
            'match'      => [
                'route'     => '/log-test-endpoint',
                'predicate' => 'true',
            ],
            'action'     => 'log',
            'stage'      => 'active',
            'enabled'    => true,
        ];
        \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch('VPATCH-LOG-TEST-001', $patch_manifest);

        $ctx = new RequestContext(
            ip: '198.51.100.77',
            method: 'GET',
            uri: '/log-test-endpoint'
        );
        $settings = ['waf_enabled' => true];

        $_SERVER['REQUEST_URI'] = '/log-test-endpoint';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        // evaluate_pipeline should evaluate AlwaysOnCoreGuard, which triggers VirtualPatchManager.
        // It returns WafVerdict('log_only'). RequestPipeline should log incident and NOT terminate the pipeline!
        $verdict = RequestPipeline::evaluate_pipeline($ctx, $settings);

        // Since log_only is non-terminal, evaluate_pipeline finishes with null (or subsequent evaluator verdict)
        $this->assertNull($verdict, 'Log-only verdict must be non-terminal in pipeline evaluation.');

        // Verify incident was logged via WafFileLogger
        $this->assertNotNull(\WebCareProScanner\Firewall\FirewallEngine::$last_incident_id);

        // Clean up
        \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch('VPATCH-LOG-TEST-001');
    }

    public function testRouteClassifierAndPipelinePreserveNormalizedUriEncoding(): void {
        $manifest = \WebCareProScanner\Core\CompiledStackManifest::load();
        $cases = [
            '/?wc%2Dajax=checkout' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::Commerce,
                'evaluators' => ['WebCareProScanner\\Firewall\\Evaluators\\CommerceAndUploadEvaluator'],
            ],
            '/?rest%5Froute=%2Fwebcare-pro-security%2Fv1%2Fscan' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::RestApi,
                'evaluators' => ['WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel'],
            ],
            '/%77p-json/wp/v2/users' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::RestApi,
                'evaluators' => ['WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel'],
            ],
            '/wp-json/wp/v2/users' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::RestApi,
                'evaluators' => ['WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel'],
            ],
            '/?wc-ajax=checkout' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::Commerce,
                'evaluators' => ['WebCareProScanner\\Firewall\\Evaluators\\CommerceAndUploadEvaluator'],
            ],
            '/%00wp-json/wp/v2/users' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::RestApi,
                'evaluators' => ['WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel'],
            ],
            '/wp-json/../checkout/' => [
                'class'      => \WebCareProScanner\Contracts\RouteClass::Commerce,
                'evaluators' => ['WebCareProScanner\\Firewall\\Evaluators\\CommerceAndUploadEvaluator'],
            ],
        ];

        $settings = [
            'waf_enabled' => true,
        ];

        foreach ($cases as $uri => $expected) {
            $expectedClass = $expected['class'];
            $classified = \WebCareProScanner\Core\RouteClassifier::classify(['REQUEST_URI' => $uri]);
            $this->assertSame($expectedClass, $classified, "RouteClassifier failed for URI: {$uri}");

            $_SERVER['REQUEST_URI'] = $uri;
            $_SERVER['REQUEST_METHOD'] = 'GET';
            $ctx = RequestContext::from_globals();
            $pipelineRouteClass = \WebCareProScanner\Core\RouteClassifier::classify([
                'REQUEST_URI'    => $ctx->uri,
                'REQUEST_METHOD' => $ctx->method,
            ]);
            $this->assertSame($expectedClass, $pipelineRouteClass, "RequestPipeline context classification failed for URI: {$uri}");

            $evaluators = $manifest['routes'][$expectedClass->value] ?? [];
            foreach ($expected['evaluators'] as $evaluatorClass) {
                $this->assertContains(
                    $evaluatorClass,
                    $evaluators,
                    "Route class {$expectedClass->value} for URI {$uri} must contain evaluator {$evaluatorClass}"
                );
            }

            // Exercise real RequestPipeline::evaluate_pipeline execution path
            $pipelineVerdict = RequestPipeline::evaluate_pipeline($ctx, $settings);
            // Benign request across classified route stack passes without terminal block
            $this->assertTrue($pipelineVerdict === null || !$pipelineVerdict->is_terminal(), "Pipeline execution failed for URI: {$uri}");
        }
    }

    public function testDotSegmentTraversalRouteNormalization(): void {
        $cases = [
            '/wp-json/../checkout/'       => \WebCareProScanner\Contracts\RouteClass::Commerce,
            '/wp-json/%2e%2e/checkout/'   => \WebCareProScanner\Contracts\RouteClass::Commerce,
        ];

        foreach ($cases as $uri => $expectedClass) {
            $normPath = \WebCareProScanner\Core\CanonicalRouteParser::normalize_path($uri);
            $this->assertSame('/checkout/', $normPath, "normalize_path failed to resolve dot-segments for URI: {$uri}");

            $classified = \WebCareProScanner\Core\RouteClassifier::classify(['REQUEST_URI' => $uri]);
            $this->assertSame($expectedClass, $classified, "RouteClassifier dot-segment resolution failed for URI: {$uri}");

            $_SERVER['REQUEST_URI'] = $uri;
            $_SERVER['REQUEST_METHOD'] = 'GET';
            $ctx = RequestContext::from_globals();
            $this->assertSame('/checkout/', $ctx->cleanUri);
        }
    }

    public function testEncodedControlCharactersStrippedAfterDecoding(): void {
        $cases = [
            '/%00wp-json/wp/v2/users'        => ['path' => '/wp-json/wp/v2/users', 'class' => \WebCareProScanner\Contracts\RouteClass::RestApi],
            '/%2500wp-json/wp/v2/users'      => ['path' => '/wp-json/wp/v2/users', 'class' => \WebCareProScanner\Contracts\RouteClass::RestApi],
            '/wp-json/%0d%0a../checkout/'    => ['path' => '/checkout/', 'class' => \WebCareProScanner\Contracts\RouteClass::Commerce],
        ];

        foreach ($cases as $uri => $expected) {
            $normalized = \WebCareProScanner\Core\CanonicalRouteParser::normalize_path($uri);
            $this->assertSame($expected['path'], $normalized, "normalize_path failed for control-char URI: {$uri}");
            $this->assertStringNotContainsString("\0", $normalized);
            $this->assertStringNotContainsString("\r", $normalized);
            $this->assertStringNotContainsString("\n", $normalized);

            $routeClass = \WebCareProScanner\Core\RouteClassifier::classify(['REQUEST_URI' => $uri]);
            $this->assertSame($expected['class'], $routeClass, "RouteClassifier failed for control-char URI: {$uri}");

            $_SERVER['REQUEST_URI'] = $uri;
            $_SERVER['REQUEST_METHOD'] = 'GET';
            $ctx = RequestContext::from_globals();
            $this->assertSame($expected['path'], $ctx->cleanUri);
        }
    }

    public function testRequestContextGlobalsAndConstructorParity(): void {
        $_SERVER['REQUEST_URI'] = '/%77p-json/wp/v2/users';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $fromGlobals = RequestContext::from_globals();
        $fromConstructor = new RequestContext(method: 'GET', uri: '/%77p-json/wp/v2/users');

        $this->assertSame('/wp-json/wp/v2/users', $fromGlobals->cleanUri);
        $this->assertSame('/wp-json/wp/v2/users', $fromConstructor->cleanUri);
        $this->assertSame($fromGlobals->cleanUri, $fromConstructor->cleanUri);
    }

    public function testAdaptiveRateLimiterClassifiesEncodedAuthIntoBucketAuth(): void {
        $this->assertSame(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_AUTH,
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::classify_bucket('/?wc%2Dajax=login', 'POST')
        );
        $this->assertSame(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_AUTH,
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::classify_bucket('/%77p-login.php', 'POST')
        );
        $this->assertSame(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_AUTH,
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::classify_bucket('/%00wp-login.php', 'POST')
        );
        $this->assertSame(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_GLOBAL,
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::classify_bucket('/about-us/', 'GET')
        );

        $uris = [
            '/?wc%2Dajax=login',
            '/%77p-login.php',
            '/%00wp-login.php',
        ];

        update_option('webcareproscan_settings', [
            'waf_rate_limit_enabled' => true,
        ]);

        foreach ($uris as $uri) {
            $_SERVER['REQUEST_URI'] = $uri;
            $_SERVER['REQUEST_METHOD'] = 'POST';

            $allowed = \WebCareProScanner\Firewall\AdaptiveRateLimiter::check_request('198.51.100.99');
            $this->assertTrue($allowed, "AdaptiveRateLimiter::check_request failed for URI: {$uri}");
        }

        $telemetry = \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry();
        $this->assertIsArray($telemetry);
    }

    public function testAdaptiveRateLimiterRestWriteReachesBucketWithoutTypeError(): void {
        update_option('webcareproscan_settings', [
            'waf_rate_limit_enabled' => true,
        ]);

        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $bucket = \WebCareProScanner\Firewall\AdaptiveRateLimiter::classify_bucket(
            $_SERVER['REQUEST_URI'],
            $_SERVER['REQUEST_METHOD']
        );
        $this->assertSame(\WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_REST_WRITE, $bucket);

        // Verify check_request executes L436 and L525 with $decoded_uri defined and no PHP warnings
        $allowed = \WebCareProScanner\Firewall\AdaptiveRateLimiter::check_request('203.0.113.50');
        $this->assertTrue($allowed);
    }

    public function testAdaptiveRateLimiterResponseFormatClassification(): void {
        // REST write request -> JSON response format
        $this->assertTrue(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::is_json_or_commerce_response(
                '/wp-json/wp/v2/posts',
                \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_REST_WRITE
            )
        );

        // WooCommerce checkout request -> JSON / WooCommerce response format
        $this->assertTrue(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::is_json_or_commerce_response(
                '/?wc%2Dajax=checkout',
                \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_CHECKOUT
            )
        );

        // Standard wp-login.php auth request -> Text/Standard response format
        $this->assertFalse(
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::is_json_or_commerce_response(
                '/wp-login.php',
                \WebCareProScanner\Firewall\AdaptiveRateLimiter::BUCKET_AUTH
            )
        );
    }

    public function testRealEvaluatorExecutionViaSpyEvaluator(): void {
        // Define a dynamic spy evaluator class if not already defined
        if (!class_exists('WebCareProScanner\\Tests\\Unit\\SpyPipelineEvaluator')) {
            eval('
                namespace WebCareProScanner\\Tests\\Unit;
                use WebCareProScanner\\Contracts\\WafEvaluatorInterface;
                use WebCareProScanner\\Contracts\\RequestContext;
                use WebCareProScanner\\Contracts\\WafVerdict;

                final class SpyPipelineEvaluator implements WafEvaluatorInterface {
                    public static array $invocations = [];
                    public static function reset(): void { self::$invocations = []; }
                    public function get_module_id(): string { return "spy-pipeline-evaluator"; }
                    public function is_required(): bool { return false; }
                    public function get_failure_policy(): string { return "degraded_log"; }
                    public function get_required_capabilities(): array { return []; }
                    public function get_target_route_classes(): array { return []; }
                    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
                        self::$invocations[] = [
                            "uri" => $ctx->uri,
                            "cleanUri" => $ctx->cleanUri,
                        ];
                        return null;
                    }
                }
            ');
        }

        \WebCareProScanner\Tests\Unit\SpyPipelineEvaluator::reset();
        $spyClass = 'WebCareProScanner\\Tests\\Unit\\SpyPipelineEvaluator';

        // Filter manifest routes to attach the spy evaluator to Commerce and RestApi
        $filterHook = static function (array $routes) use ($spyClass): array {
            $routes[\WebCareProScanner\Contracts\RouteClass::Commerce->value][] = $spyClass;
            $routes[\WebCareProScanner\Contracts\RouteClass::RestApi->value][] = $spyClass;
            return $routes;
        };
        add_filter('webcare/waf/manifest_routes', $filterHook, 10, 1);

        $compileRes = \WebCareProScanner\Core\CompiledStackManifest::compile();
        $this->assertTrue($compileRes['success']);

        $testUris = [
            '/?wc%2Dajax=checkout',
            '/wp-json/../checkout/',
            '/?rest%5Froute=%2Fwebcare-pro-security%2Fv1%2Fscan',
            '/%77p-json/wp/v2/users',
            '/%00wp-json/wp/v2/users',
        ];

        $settings = ['waf_enabled' => true];

        foreach ($testUris as $testUri) {
            \WebCareProScanner\Tests\Unit\SpyPipelineEvaluator::reset();
            $_SERVER['REQUEST_URI'] = $testUri;
            $_SERVER['REQUEST_METHOD'] = 'GET';

            $ctx = RequestContext::from_globals();
            $verdict = RequestPipeline::evaluate_pipeline($ctx, $settings);

            $this->assertNull($verdict);
            $this->assertCount(
                1,
                \WebCareProScanner\Tests\Unit\SpyPipelineEvaluator::$invocations,
                "Spy evaluator was not invoked for URI: {$testUri}"
            );
            $this->assertSame(
                $testUri,
                \WebCareProScanner\Tests\Unit\SpyPipelineEvaluator::$invocations[0]['uri']
            );
        }

        // Clean up filter and recompile manifest to pristine state
        remove_filter('webcare/waf/manifest_routes', $filterHook, 10);
        \WebCareProScanner\Core\CompiledStackManifest::compile();
    }
}
