<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Firewall\Evaluators\AiAgentBehaviorEvaluator;
use WebCareProScanner\Firewall\OutboundEgressFirewall;
use WebCareProScanner\System\SettingsManager;

final class ShopperAndAiDefenseTest extends TestCase {

    private AiAgentBehaviorEvaluator $evaluator;
    private array $origServer = [];
    private array $origGet = [];
    private array $origPost = [];
    private array $origCookie = [];

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $this->origPost = $_POST;
        $this->origCookie = $_COOKIE;
        $this->evaluator = new AiAgentBehaviorEvaluator();
        SettingsManager::update_setting('waf_ai_challenge_stealth_agents', true);
        @unlink(\WebCareProScanner\Firewall\Core\WafVaultManager::get_safe_mode_marker_path());
        $_COOKIE = [];
        $_GET = [];
        $_POST = [];
        $_SERVER = [];
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $_POST = $this->origPost;
        $_COOKIE = $this->origCookie;
        parent::tearDown();
    }

    public function test_forged_logged_in_cookie_does_not_bypass_ai_shield(): void {
        $_SERVER['HTTPS'] = 'on';
        $_COOKIE['wordpress_logged_in_fakecookiehash'] = 'fake_user_payload';
        // Sub-250ms velocity token generated to push score >= 60
        $_POST['webcare_render_ts'] = AiAgentBehaviorEvaluator::generate_render_timestamp();

        $ctx = new RequestContext(
            ip: '198.51.100.30',
            method: 'POST',
            uri: '/wp-comments-post.php',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict, 'Forged unverified logged_in cookie must NOT bypass AI evaluator');
        $this->assertSame(WafAction::Challenge, $verdict->action);
    }

    public function test_arbitrary_wc_ajax_param_does_not_bypass_ai_shield(): void {
        $_SERVER['HTTPS'] = 'on';
        $_GET['wc-ajax'] = 'arbitrary_unregistered_action';
        $_POST['webcare_render_ts'] = AiAgentBehaviorEvaluator::generate_render_timestamp();

        $ctx = new RequestContext(
            ip: '198.51.100.31',
            method: 'POST',
            uri: '/?wc-ajax=arbitrary_unregistered_action',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict, 'Unregistered wc-ajax query without active shopper session must NOT bypass AI evaluator');
    }

    public function test_mobile_social_ad_webviews_exempt_from_missing_sec_fetch_penalty(): void {
        $_SERVER['HTTPS'] = 'on';
        $ctx = new RequestContext(
            ip: '198.51.100.32',
            method: 'GET',
            uri: '/product/summer-dress/',
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 280.0.0.17.114'
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNull($verdict, 'Instagram iOS in-app WebView without Sec-Fetch-* must not be challenged');
    }

    public function test_outbound_firewall_blocks_dotless_decimal_hex_and_octal_ipv4_literals(): void {
        SettingsManager::update_setting('outbound_firewall_mode', 'enforce');
        SettingsManager::update_setting('outbound_firewall_block_ssrf', true);

        // Dotless decimal literal (2130706433 = 127.0.0.1)
        $r1 = OutboundEgressFirewall::inspect_outbound_request(false, [], 'http://2130706433/admin');
        $this->assertInstanceOf(\WP_Error::class, $r1);
        $this->assertSame('webcare_egress_blocked', $r1->get_error_code());

        // Hex literal (0x7f000001 = 127.0.0.1)
        $r2 = OutboundEgressFirewall::inspect_outbound_request(false, [], 'http://0x7f000001/status');
        $this->assertInstanceOf(\WP_Error::class, $r2);
        $this->assertSame('webcare_egress_blocked', $r2->get_error_code());

        // Octal literal (017700000001 = 127.0.0.1)
        $r3 = OutboundEgressFirewall::inspect_outbound_request(false, [], 'http://017700000001/internal');
        $this->assertInstanceOf(\WP_Error::class, $r3);
        $this->assertSame('webcare_egress_blocked', $r3->get_error_code());
    }
}
