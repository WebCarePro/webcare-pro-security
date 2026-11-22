<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\Evaluators\AiAgentBehaviorEvaluator;
use WebCareProScanner\System\SettingsManager;

final class ContextPureAiAndBotVerificationTest extends TestCase {

    private AiAgentBehaviorEvaluator $evaluator;

    protected function setUp(): void {
        parent::setUp();
        $this->evaluator = new AiAgentBehaviorEvaluator();
        SettingsManager::update_setting('waf_ai_challenge_stealth_agents', true);
        SettingsManager::update_setting('waf_ai_allow_search_citations', true);
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        $GLOBALS['wp_mock_transients'] = [];
        @unlink(\WebCareProScanner\Firewall\Core\WafVaultManager::get_safe_mode_marker_path());
        $_COOKIE = [];
        $_GET = [];
        $_POST = [];
        $_SERVER = [];
    }

    protected function tearDown(): void {
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        $GLOBALS['wp_mock_transients'] = [];
        parent::tearDown();
    }

    public function test_ai_evaluator_uses_context_pure_properties(): void {
        // Request without Sec-Fetch headers and with mobile mismatch in context headers
        $ctx = new RequestContext(
            ip: '198.51.100.55',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            headers: [
                'sec-ch-ua'        => '"Chromium";v="120"',
                'sec-ch-ua-mobile' => '?1', // Mismatch against Windows NT
            ],
            server: [
                'HTTPS' => 'on',
            ],
            formParams: [
                'webcare_render_ts' => AiAgentBehaviorEvaluator::generate_render_timestamp(),
            ]
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict);
        $this->assertSame(WafAction::Challenge, $verdict->action);
    }

    public function test_api_routes_receive_429_rate_limit_instead_of_html_pow(): void {
        $ctx = new RequestContext(
            ip: '198.51.100.56',
            method: 'POST',
            uri: '/wp-json/wp/v2/posts',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            headers: [
                'sec-ch-ua'        => '"Chromium";v="120"',
                'sec-ch-ua-mobile' => '?1',
            ],
            server: [
                'HTTPS' => 'on',
            ],
            formParams: [
                'webcare_render_ts' => AiAgentBehaviorEvaluator::generate_render_timestamp(),
            ]
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict);
        $this->assertSame('rate_limit', $verdict->get_action_value());
        $this->assertSame(429, $verdict->statusCode);
        $this->assertSame('WAF-AI-AGENT-API-RATELIMIT', $verdict->ruleId);
    }

    public function test_ai_search_citation_bots_verified_via_official_cidrs(): void {
        // Test OpenAI SearchBot in official CIDR range 20.171.206.15
        $this->assertTrue(
            BotReconDefense::is_search_bot_in_official_cidrs('20.171.206.15', 'oai-searchbot')
        );

        // Test Claude SearchBot in official CIDR range 160.79.104.50
        $this->assertTrue(
            BotReconDefense::is_search_bot_in_official_cidrs('160.79.104.50', 'claude-searchbot')
        );

        // Test random IP is rejected
        $this->assertFalse(
            BotReconDefense::is_search_bot_in_official_cidrs('198.51.100.99', 'oai-searchbot')
        );
    }

    public function test_verified_search_engine_requires_read_only_public_crawl(): void {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        // Attempting a POST request pretending to be Googlebot must never be accepted as genuine search crawl
        $this->assertFalse(
            BotReconDefense::is_genuine_search_engine('66.249.66.1', 'Googlebot/2.1 (+http://www.google.com/bot.html)')
        );
    }

    public function test_spoofed_perplexity_bot_from_unverified_ip_is_not_exempted(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        // Unverified IP (even from shared Fastly ranges 151.101.1.1) must NOT be exempted
        $this->assertFalse(
            BotReconDefense::is_verified_ai_citation_bot('151.101.1.1', 'PerplexityBot/1.0 (+https://perplexity.ai/bot)')
        );
        $this->assertFalse(
            BotReconDefense::is_search_bot_in_official_cidrs('151.101.1.1', 'perplexitybot')
        );
    }

    public function test_https_detection_prefers_explicit_context_over_global_is_ssl(): void {
        // Case 1: Context explicitly sets HTTPS='off' while global $_SERVER['HTTPS'] is 'on'
        $_SERVER['HTTPS'] = 'on'; // global is_ssl() returns true

        // Form parameters with valid timestamp so render ts isn't triggered
        $render_ts = AiAgentBehaviorEvaluator::generate_render_timestamp();

        $ctx_http = new RequestContext(
            ip: '198.51.100.57',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            headers: [
                'sec-ch-ua'          => '"Chromium";v="120"',
                'sec-ch-ua-mobile'   => '?0', // No mismatch
                'sec-ch-ua-platform' => '"Windows"',
            ],
            server: [
                'HTTPS' => 'off', // Explicitly OFF in context
            ],
            formParams: [
                'webcare_render_ts' => $render_ts,
            ]
        );

        // If context precedence works, $is_https is false, so missing Sec-Fetch-* is NOT evaluated (+0 risk). Total risk < 45. Verdict is null.
        $verdict_http = $this->evaluator->evaluate_runtime_request($ctx_http);
        $this->assertNull($verdict_http, 'Explicit HTTPS=off in context must not trigger missing Sec-Fetch-* heuristic even when global is_ssl() is true.');

        // Case 2: Context explicitly sets HTTPS='on'
        $ctx_https = new RequestContext(
            ip: '198.51.100.58',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            headers: [
                'sec-ch-ua'        => '"Chromium";v="120"',
                'sec-ch-ua-mobile' => '?1', // Mismatch against Windows NT (+40 risk)
            ],
            server: [
                'HTTPS' => 'on', // Explicitly ON in context (triggers +35 missing sec-fetch)
            ],
            formParams: [
                'webcare_render_ts' => $render_ts,
            ]
        );
        $verdict_https = $this->evaluator->evaluate_runtime_request($ctx_https);
        $this->assertNotNull($verdict_https);
        $this->assertSame(WafAction::Challenge, $verdict_https->action);

        // Case 3: Missing HTTPS key in context falls back to global is_ssl()
        $_SERVER['HTTPS'] = 'off'; // global is_ssl() false
        $ctx_fallback = new RequestContext(
            ip: '198.51.100.59',
            method: 'POST',
            uri: '/contact-us/',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            headers: [
                'sec-ch-ua'          => '"Chromium";v="120"',
                'sec-ch-ua-mobile'   => '?0',
                'sec-ch-ua-platform' => '"Windows"',
            ],
            server: [], // No HTTPS key
            formParams: [
                'webcare_render_ts' => $render_ts,
            ]
        );
        $verdict_fallback = $this->evaluator->evaluate_runtime_request($ctx_fallback);
        $this->assertNull($verdict_fallback, 'Missing HTTPS key in context correctly falls back to global is_ssl().');
    }
}
