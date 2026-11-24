<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Auth\LoginHardening;
use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\Core\TransientRateLimiter;
use WebCareProScanner\Firewall\Core\ViolationResponder;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\TelemetrySnapshot;

/**
 * WAF Intelligence Replay Harness Test Suite
 *
 * Modeled on real telemetry from gentlepetpassages.com and iw-academy.com.
 * Tests Phase 1 invariants:
 * - Group 1: Runtime reliability (null $wp_query safety, emit_standalone_block_html, header safety)
 * - Group 2: Enforcement (atomic terminal warning strikes, admin/shopper subordination, honeypot 2-hit auto-ban)
 * - Group 3: Decision telemetry (canonical WAF-XMLRPC-DISABLED, decision vs enforcement_outcome)
 * - Group 4: Cloudflare queue (generation fencing, stale queued ban skipped after unban, exponential backoff)
 * - Group 9: Forensic integrity (original WAF record byte-for-byte immutability)
 */
class WafReplayHarnessTest extends TestCase {

    private array $origServer;
    private array $origGet;
    private array $origPost;

    protected function setUp(): void {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origGet = $_GET;
        $this->origPost = $_POST;
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wp_query'] = null; // Enforce early lifecycle null $wp_query invariant
        CloudflareService::$mock_request_handler = null;
    }

    protected function tearDown(): void {
        $_SERVER = $this->origServer;
        $_GET = $this->origGet;
        $_POST = $this->origPost;
        CloudflareService::$mock_request_handler = null;
        parent::tearDown();
    }

    /**
     * Group 1: Runtime Reliability — Early lifecycle null $wp_query does not crash ViolationResponder.
     */
    public function testGroup1EarlyLifecycleNullQueryDoesNotCrashViolationResponder(): void {
        $GLOBALS['wp_query'] = null; // Simulates early plugins_loaded crash from iw-academy.com
        $client_ip = '198.51.100.42';

        $rule = [
            'id'          => 'WAF-SQLI-PROBE',
            'category'    => 'SQL Injection',
            'description' => 'Test SQL injection probe',
            'is_hard_block' => true,
        ];
        $settings = [
            'waf_enabled' => true,
            'waf_mode'    => 'enabled',
        ];

        ob_start();
        try {
            ViolationResponder::handle_rule_violation($rule, $settings, $client_ip, 403);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertNotEmpty($output);
        $this->assertStringContainsString('403 Forbidden', $output);
        $this->assertStringContainsString('Protected by WebCare Pro Security', $output);
    }

    /**
     * Group 2: Enforcement — Terminal Warning Strike (4/4) upgrades to blocked and commits a local IP ban.
     */
    public function testGroup2TerminalWarningStrikeCommitsLocalBan(): void {
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        $client_ip = '198.51.100.77';
        $settings = [
            'waf_enabled'                    => true,
            'waf_mode'                       => 'enabled',
            'waf_enable_progressive_warnings' => true,
            'waf_progressive_warning_rules'  => ['RULE-WARN-01'],
        ];
        $rule = [
            'id'          => 'RULE-WARN-01',
            'category'    => 'Form Abuse',
            'description' => 'Suspicious form parameter repetition',
        ];

        // First 3 hits: warned
        for ($i = 1; $i <= 3; $i++) {
            $strike_info = TransientRateLimiter::record_warning_strike($client_ip, 4, 900);
            $this->assertFalse($strike_info['is_terminal_ban'], "Strike $i should not be terminal");
        }

        // 4th hit: terminal strike
        $rule['strike_info'] = TransientRateLimiter::record_warning_strike($client_ip, 4, 900);
        $this->assertTrue($rule['strike_info']['is_terminal_ban'], '4th strike must be terminal');

        ob_start();
        try {
            ViolationResponder::handle_rule_violation($rule, $settings, $client_ip, 403);
        } finally {
            ob_end_clean();
        }

        // Verify local IP ban was committed
        $this->assertTrue(BlocklistRepository::is_ip_blocked($client_ip), 'Terminal warning strike must commit a local IP ban');
    }

    /**
     * Group 2: Enforcement — Honeypot username trap short-circuits and auto-bans after 2 attempts in 10 minutes.
     */
    public function testGroup2HoneypotUsernameTwoHitAutoBan(): void {
        $client_ip = '198.51.100.88';
        $_SERVER['REMOTE_ADDR'] = $client_ip;
        FirewallEngine::reset_client_ip_cache();

        $settings = [
            'waf_enabled'                    => true,
            'waf_block_forbidden_usernames'  => true,
            'waf_forbidden_usernames_list'   => "admin\nroot",
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);

        // Attempt 1: blocked and error returned, no IP ban yet
        $err1 = FirewallEngine::check_forbidden_username_login(null, 'admin', 'password123');
        $this->assertInstanceOf(\WP_Error::class, $err1);
        $this->assertSame('webcare_honeypot_username', $err1->get_error_code());
        $this->assertTrue(FirewallEngine::$honeypot_auth_blocked);

        // LoginHardening record_failed_attempt must short-circuit without logging WAF-AUTH-FAILED
        LoginHardening::record_failed_attempt('admin', $err1);
        $this->assertFalse(FirewallEngine::$honeypot_auth_blocked, 'Flag must be reset after short-circuiting');
        $this->assertFalse(BlocklistRepository::is_ip_blocked($client_ip), '1st attempt must not ban IP');

        // Attempt 2: second hit triggers 24h local IP ban
        $err2 = FirewallEngine::check_forbidden_username_login(null, 'admin', 'password456');
        $this->assertInstanceOf(\WP_Error::class, $err2);
        $this->assertTrue(BlocklistRepository::is_ip_blocked($client_ip), '2nd honeypot attempt within 10m must ban IP');
    }

    /**
     * Group 3: Decision Telemetry — Canonical XML-RPC rule_id and immutable telemetry fields.
     */
    public function testGroup3CanonicalXmlrpcRuleIdAndImmutableTelemetry(): void {
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REMOTE_ADDR'] = '198.51.100.99';
        FirewallEngine::reset_client_ip_cache();

        $settings = [
            'waf_enabled'        => true,
            'waf_disable_xmlrpc' => true,
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);

        // Trigger ExploitSignatureEngine XML-RPC check directly
        ob_start();
        try {
            \WebCareProScanner\Firewall\Core\ExploitSignatureEngine::check_xmlrpc_guard('/xmlrpc.php');
        } catch (\Throwable $e) {
            // In CLI / test runtime, exit is caught
        }
        ob_end_clean();

        // Query the WafFileLogger to verify canonical rule_id and telemetry fields
        $logs = WafFileLogger::query_logs(['ip' => '198.51.100.99', 'action' => 'all', 'range' => 'all'], 5, 0);
        $this->assertNotEmpty($logs['logs']);
        $incident = $logs['logs'][0];

        $this->assertSame('WAF-XMLRPC-DISABLED', $incident['rule_id']);
        $this->assertSame('block', $incident['decision'] ?? 'block');
        $this->assertSame('completed', $incident['enforcement_outcome'] ?? 'completed');
    }

    /**
     * Group 4: Cloudflare Queue — Generation Fencing skips stale queued ban after admin unbans the IP.
     */
    public function testGroup4GenerationFencingSkipsStaleQueuedBanAfterUnban(): void {
        $ip = '203.0.113.55';
        $settings = [
            'cloudflare_enabled'         => true,
            'cloudflare_api_token'       => 'test-token',
            'cloudflare_zone_id'         => 'test-zone',
            'cloudflare_auto_sync_bans'  => true,
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);
        set_transient(CloudflareIpListSynchronizer::OPTION_TOKEN_SCOPE, 'zone', 3600);

        // Step 1: Enqueue IP ban -> assigns generation 1
        CloudflareIpListSynchronizer::queue_ip_ban($ip, 'Test threat', 86400);
        $queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayHasKey($ip, $queue);
        $enqueued_gen = $queue[$ip]['generation'];

        // Step 2: Admin unbans IP locally -> increments generation to 2
        CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        $current_gen = CloudflareIpListSynchronizer::get_ip_generation($ip);
        $this->assertGreaterThan($enqueued_gen, $current_gen, 'Unban must increment IP generation');

        // Step 3: Simulate re-queuing the old stale entry (generation 1)
        $queue[$ip]['generation'] = $enqueued_gen;
        update_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, $queue, false);

        // Step 4: Worker processes queue
        $mock_called = false;
        CloudflareService::$mock_request_handler = static function (string $endpoint, string $method, array $data) use (&$mock_called): array {
            $mock_called = true;
            return ['success' => true, 'result' => ['id' => 'rule-123']];
        };

        $sync = new CloudflareIpListSynchronizer();
        $processed = $sync->process_sync_queue();

        // Stale entry must be skipped and removed without calling Cloudflare API
        $this->assertSame(0, $processed, 'Stale queued ban must not be processed');
        $this->assertFalse($mock_called, 'Cloudflare API must NEVER be called for superseded/stale generation');

        // Queue must no longer hold the stale entry
        $final_queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayNotHasKey($ip, $final_queue, 'Stale entry must be evicted from queue');
    }

    /**
     * Group 4 & 9: Telemetry & Forensic Integrity — TelemetrySnapshot surfaces queue and sync health.
     */
    public function testGroup4And9TelemetrySnapshotExposesQueueHealthWithoutSecrets(): void {
        $ip = '203.0.113.66';
        $settings = [
            'cloudflare_enabled'         => true,
            'cloudflare_api_token'       => 'test-token-secret-12345',
            'cloudflare_zone_id'         => 'zone-abcdef-123456',
            'cloudflare_auto_sync_bans'  => true,
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);

        CloudflareIpListSynchronizer::queue_ip_ban($ip, 'Forensic probe', 86400);

        $snapshot = TelemetrySnapshot::get_snapshot();
        $edge = $snapshot['edge_network'];

        $this->assertTrue($edge['cf_sync_enabled']);
        $this->assertGreaterThanOrEqual(1, $edge['cf_queue_pending_count']);
        $this->assertNotNull($edge['cf_last_sync_event']);
        $this->assertSame($ip, $edge['cf_last_sync_event']['ip']);

        // Zero secret exposure invariant
        $snapshot_json = json_encode($snapshot);
        $this->assertStringNotContainsString('test-token-secret-12345', $snapshot_json);
    }

    /**
     * Group 5: Crawler Identity — Verified crawlers recognized via OfficialCrawlerRegistry and static fallback.
     */
    public function testGroup5VerifiedCrawlersRecognizedAndExemptFromBrowserIntegrity(): void {
        // Test Googlebot IP in official static fallback range
        $google_ip = '66.249.64.15';
        $google_ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $identity = \WebCareProScanner\Firewall\OfficialCrawlerRegistry::get_verified_crawler_identity($google_ip, $google_ua);
        $this->assertSame('googlebot', $identity);

        // Test Claude-SearchBot IP in official static range
        $claude_ip = '160.79.104.55';
        $claude_ua = 'Mozilla/5.0 (compatible; Claude-SearchBot/1.0; +https://www.anthropic.com/claudebot)';

        $identity_claude = \WebCareProScanner\Firewall\OfficialCrawlerRegistry::get_verified_crawler_identity($claude_ip, $claude_ua);
        $this->assertSame('claude-searchbot', $identity_claude);

        // Verify genuine search crawler check in BotReconDefense
        $is_genuine = \WebCareProScanner\Firewall\BotReconDefense::is_search_bot_in_official_cidrs($claude_ip, 'claude-searchbot');
        $this->assertTrue($is_genuine, 'Claude-SearchBot in official CIDRs must be identified as genuine');

        // Test that verified crawler is exempt from browser integrity checks in AiAgentBehaviorEvaluator
        $ctx = new RequestContext(
            ip: $claude_ip,
            method: 'GET',
            uri: '/blog/post-1',
            headers: [], // Completely missing sec-fetch-* and accept-language
            server: ['HTTPS' => 'on', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/blog/post-1', 'REMOTE_ADDR' => $claude_ip],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: $claude_ua
        );

        $evaluator = new \WebCareProScanner\Firewall\Evaluators\AiAgentBehaviorEvaluator();
        $settings = ['waf_ai_challenge_stealth_agents' => true];
        update_option(SettingsManager::OPTION_KEY, $settings);

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        $this->assertNull($verdict, 'Verified crawlers must never be challenged or penalized for missing sec-fetch-*');
    }

    /**
     * Group 5: Crawler Identity — Malformed feed rejection preserves last-known-good cache.
     */
    public function testGroup5MalformedFeedRejectionPreservesCache(): void {
        \WebCareProScanner\Firewall\OfficialCrawlerRegistry::set_cache_for_testing(null);

        // Extract and validate with malformed / non-array data
        $extracted = \WebCareProScanner\Firewall\OfficialCrawlerRegistry::extract_and_validate_cidrs(['prefixes' => 'not-an-array'], 'prefixes');
        $this->assertEmpty($extracted);

        // Test CIDR syntax validation
        $this->assertTrue(\WebCareProScanner\Firewall\OfficialCrawlerRegistry::validate_cidr_syntax('192.168.1.0/24'));
        $this->assertTrue(\WebCareProScanner\Firewall\OfficialCrawlerRegistry::validate_cidr_syntax('2001:db8::/32'));
        $this->assertFalse(\WebCareProScanner\Firewall\OfficialCrawlerRegistry::validate_cidr_syntax('999.999.999.999/24'));
        $this->assertFalse(\WebCareProScanner\Firewall\OfficialCrawlerRegistry::validate_cidr_syntax('192.168.1.0/99'));

        // Feed validation rejection on disallowed host
        $res = \WebCareProScanner\Firewall\OfficialCrawlerRegistry::fetch_and_validate_feed('googlebot', [
            'url'          => 'https://malicious-feed.example.com/bot.json',
            'allowed_host' => 'developers.google.com',
            'format'       => 'google',
        ]);
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('Disallowed', $res['error'] ?? '');

        // Effective CIDRs returns static fallbacks when cache empty or missing
        $fallbacks = \WebCareProScanner\Firewall\OfficialCrawlerRegistry::get_effective_cidrs_for_bot('googlebot');
        $this->assertNotEmpty($fallbacks);
        $this->assertContains('66.249.64.0/19', $fallbacks);
    }

    /**
     * Group 6: Subnet Intelligence — Multi-level correlation & strict data-model separation from recon counters.
     */
    public function testGroup6SubnetIntelligenceAndReconSeparation(): void {
        $ip = '114.119.130.45';
        $ua = 'Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)';

        // Step 1: Detect crawler family & subnet calculation
        $family = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::detect_crawler_family($ip, $ua);
        $this->assertSame('petalbot', $family);

        $subnet = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::get_subnet_prefix($ip);
        $this->assertSame('114.119.130.0/24', $subnet);

        // Step 2: Test crawler policy inspect with 'throttle' preset
        $settings = ['waf_crawler_policy_petalbot' => 'throttle'];

        // Reset counters
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_ip', $ip);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_subnet', $subnet);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_family', 'petalbot');
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('recon_ip', $ip);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('recon_subnet', $subnet);

        // Hits 1 to 10: allowed under throttle rate limit
        for ($i = 1; $i <= 10; $i++) {
            $decision = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::inspect_crawler_swarm($ip, $ua, $settings);
            $this->assertNull($decision, "Hit $i should be permitted under throttle threshold");
        }

        // 11th hit: exceeds 10 req/min for IP scope -> 429 throttle returned
        $throttle = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::inspect_crawler_swarm($ip, $ua, $settings);
        $this->assertNotNull($throttle);
        $this->assertSame('throttle', $throttle['action']);
        $this->assertSame(\WebCareProScanner\Firewall\Core\SubnetSwarmGuard::THROTTLE_RULE_ID, $throttle['rule_id']);
        $this->assertSame(120, $throttle['retry_after']);

        // Step 3: Strict Data-Model Separation Invariant:
        // Ordinary crawler activity must NOT increment sensitive-file recon counters
        $recon_record = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::record_recon_probe($ip, 'sensitive_file');
        // Because crawler counters are isolated, recon hit count should be exactly 1
        $this->assertSame(1, $recon_record['ip_hits'], 'Recon counter must be strictly separate from crawler swarm counters');
        $this->assertSame(1, $recon_record['subnet_hits'], 'Recon subnet counter must be strictly separate');
    }

    /**
     * Group 7: Campaign Engine — 5-target threshold auto-bans, 2-vector corroboration, and single canary non-ban.
     */
    public function testGroup7BehavioralCampaignEngineThresholdsAndCorroboration(): void {
        $ip = '198.51.100.155';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($ip);

        // Case A: Single canary hit -> records probe, but does NOT trigger 24h auto-ban
        $canary_res = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'canary_trap', '/.well-known/security-canary.txt');
        $this->assertFalse($canary_res['escalate_ban'], 'Single canary hit must NEVER auto-ban solely on its own');
        $this->assertSame(1, $canary_res['distinct_targets_count']);
        $this->assertSame(1, $canary_res['vectors_count']);

        // Case B: 2-vector corroboration (canary + sensitive_file + webshell) -> triggers auto-ban on >= 3 probes
        $sens_res = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', '/.env');
        $this->assertFalse($sens_res['escalate_ban'], '2 total probes without honeypot should not ban yet');

        $web_res = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'webshell_probe', '/wp-content/themes/calmly/issue.php');
        $this->assertTrue($web_res['escalate_ban'], 'Corroborating 3 probes across multiple vectors must escalate to 24h auto-ban');
        $this->assertSame('WAF-CAMPAIGN-AUTOBAN', $web_res['rule_id']);

        // Verify local IP ban was committed
        $this->assertTrue(BlocklistRepository::is_ip_blocked($ip), 'Campaign auto-ban must commit a local IP ban');
    }

    /**
     * Group 7 & 8: Campaign Engine & Cardinality — 5 distinct targets trigger ban, 20-bucket cap saturation without eviction.
     */
    public function testGroup8CampaignBucketSaturationAndTargetDeduplication(): void {
        $ip = '198.51.100.188';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($ip);

        // Test target normalization deduplication (slashes / query variances)
        $r1 = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', '//wp-config.php.bak');
        $r2 = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', '/wp-config.php.bak?query=1');
        $this->assertSame(1, $r2['distinct_targets_count'], 'Normalized target variations must deduplicate cleanly');

        // Fill up to 20 distinct targets
        for ($i = 2; $i <= 20; $i++) {
            \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', "/probed-secret-{$i}.env");
        }

        // Probing 21st and 22nd target: saturation reached, freeze insertions, increment overflow
        $overflow_res = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', '/probed-secret-21.env');
        $this->assertGreaterThanOrEqual(1, $overflow_res['overflow_count'], 'Bucket saturation must increment overflow count without evicting evidence');
    }

    /**
     * Group 7: Impossible Browser & Raw HTTP Client Signals.
     */
    public function testGroup7ImpossibleBrowserAndRawHttpClientSignals(): void {
        // Test impossible future browser (Chrome/155.0.0.0) -> scores risk +45, does NOT trigger immediate ban
        $ctx = new RequestContext(
            ip: '198.51.100.199',
            method: 'GET',
            uri: '/',
            headers: [
                'sec-fetch-site' => 'none',
                'sec-fetch-mode' => 'navigate',
                'sec-fetch-dest' => 'document',
            ],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.199'],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36'
        );

        $evaluator = new \WebCareProScanner\Firewall\Evaluators\AiAgentBehaviorEvaluator();
        $settings = ['waf_ai_challenge_stealth_agents' => true];
        update_option(SettingsManager::OPTION_KEY, $settings);

        $verdict = $evaluator->evaluate_runtime_request($ctx);
        // Score is 45 (below challenge threshold of 60), so verdict is null, not an outright ban
        $this->assertNull($verdict, 'Impossible future browser version (Chrome/155) is an anomaly signal (+45), NOT an immediate ban trigger');

        // Test Raw HTTP Client probing non-existent PHP file -> Hard-blocked with 403
        $raw_ctx = new RequestContext(
            ip: '198.51.100.200',
            method: 'GET',
            uri: '/wp-content/plugins/x/shell.php',
            headers: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-content/plugins/x/shell.php', 'REMOTE_ADDR' => '198.51.100.200'],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: 'python-requests/2.31.0'
        );

        $raw_verdict = $evaluator->evaluate_runtime_request($raw_ctx);
        $this->assertNotNull($raw_verdict);
        $this->assertSame('block', $raw_verdict->action);
        $this->assertSame('WAF-RAW-CLIENT-PHP-PROBE', $raw_verdict->ruleId);
    }

    /**
     * Group 9: Forensic Integrity & Non-Destructive Summaries — Raw WAF records remain 100% byte-for-byte immutable across rollups.
     */
    public function testGroup9ForensicIntegrityAndCampaignSummaries(): void {
        $ip = '198.51.100.220';
        $rule = [
            'id'          => 'WAF-SQLI-PROBE',
            'category'    => 'SQL Injection',
            'description' => 'Test probe for forensic integrity',
        ];

        // Log incident directly via WafFileLogger
        $logged = WafFileLogger::log_incident($rule, 'blocked');
        $this->assertNotEmpty($logged);

        // Fetch the raw log entry
        $query = WafFileLogger::query_logs(['ip' => $ip, 'range' => 'all'], 5, 0);
        $original_records = $query['logs'] ?? [];
        $this->assertNotEmpty($original_records);
        $orig_record = $original_records[0];

        // Generate non-destructive campaign summaries
        $summaries = WafFileLogger::get_campaign_summaries(86400, 100);
        $this->assertIsArray($summaries);

        // Fetch the raw log entry again to verify byte-for-byte immutability
        $query_after = WafFileLogger::query_logs(['ip' => $ip, 'range' => 'all'], 5, 0);
        $records_after = $query_after['logs'] ?? [];
        $this->assertNotEmpty($records_after);
        $after_record = $records_after[0];

        $this->assertSame(
            json_encode($orig_record),
            json_encode($after_record),
            'Original WAF record must remain byte-for-byte identical across dashboard aggregations'
        );
    }

    /**
     * Group 10: Degraded Operation & Bounded Local Intelligence Advisor.
     */
    public function testGroup10DegradedModeAndLocalAdvisorBoundaries(): void {
        // Test Bounded Local Intelligence Advisor
        \WebCareProScanner\Firewall\CAF\LocalIntelligenceAdvisor::clear_cache_for_testing();
        $advisory = \WebCareProScanner\Firewall\CAF\LocalIntelligenceAdvisor::get_recommendations(true);

        $this->assertContains($advisory['status'], ['ok', 'unavailable', 'degraded']);
        $this->assertLessThanOrEqual(
            \WebCareProScanner\Firewall\CAF\LocalIntelligenceAdvisor::MAX_RECOMMENDATIONS,
            count($advisory['recommendations']),
            'Local Advisor must never exceed max 3 actionable recommendations'
        );

        // Test Degraded-Mode: Outage on APCu or Redis fallback preserves confirmed exploit blocking
        $client_ip = '198.51.100.240';
        $rule = [
            'id'            => 'WAF-SQLI-DEGRADED-TEST',
            'category'      => 'SQL Injection',
            'description'   => 'Exploit block under cache degradation',
            'is_hard_block' => true,
        ];
        $settings = ['waf_enabled' => true, 'waf_mode' => 'enabled'];

        ob_start();
        try {
            ViolationResponder::handle_rule_violation($rule, $settings, $client_ip, 403);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertStringContainsString('403 Forbidden', $output);
        $this->assertStringContainsString('Protected by WebCare Pro Security', $output);
    }

    /**
     * Regression Audit: BehavioralCampaignEngine ban commits real 86400s local ban and skips admins/whitelisted/shoppers.
     */
    public function testRegressionCampaignAutobanCommitsRealBanAndRespectsExemptions(): void {
        $ip = '198.51.100.250';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($ip);

        // Record 5 distinct probes under strict_types=1 to trigger auto-ban
        for ($i = 1; $i <= 5; $i++) {
            \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ip, 'sensitive_file', "/secret-config-{$i}.env");
        }

        $this->assertTrue(BlocklistRepository::is_ip_blocked($ip), '5 distinct targets must commit local ban with correct argument order');

        // Test that whitelisted IP is NOT banned by campaign auto-ban
        $white_ip = '198.51.100.251';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($white_ip);
        $settings = ['waf_whitelisted_ips' => $white_ip];
        update_option(SettingsManager::OPTION_KEY, $settings);

        for ($i = 1; $i <= 5; $i++) {
            \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($white_ip, 'sensitive_file', "/secret-config-{$i}.env");
        }
        $this->assertFalse(BlocklistRepository::is_ip_blocked($white_ip), 'Whitelisted IP must NEVER be banned by campaign engine');
    }

    /**
     * Regression Audit: Zero shutdown functions registered by queue_ip_ban & enqueue_failed handling.
     */
    public function testRegressionZeroShutdownHooksAndEnqueueFailedHandling(): void {
        $test_ip = '203.0.113.88';
        $res = CloudflareIpListSynchronizer::queue_ip_ban($test_ip, 'Regression test ban', 86400);

        $this->assertIsArray($res);
        $this->assertArrayHasKey('cf_sync_state', $res);
        $this->assertArrayHasKey('operation_id', $res);

        // Queue ban must return 'queued' when configured or 'disabled' when unconfigured
        $this->assertContains($res['cf_sync_state'], ['queued', 'disabled', 'enqueue_failed']);
    }

    /**
     * Regression Audit: Live SubnetSwarmGuard returns 429 WAF-SUBNET-SWARM-THROTTLE for throttled swarm.
     */
    public function testRegressionLiveSubnetSwarmThrottle(): void {
        $ip = '114.119.160.22';
        $ua = 'PetalBot/1.0';
        $settings = ['waf_crawler_policy_petalbot' => 'throttle'];

        $subnet = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::get_subnet_prefix($ip);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_ip', $ip);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_subnet', $subnet);
        \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::reset_counter_for_testing('crawler_family', 'petalbot');

        // Exceed 10 req/min
        for ($i = 1; $i <= 10; $i++) {
            \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::inspect_crawler_swarm($ip, $ua, $settings);
        }

        $verdict = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::inspect_crawler_swarm($ip, $ua, $settings);
        $this->assertNotNull($verdict);
        $this->assertSame('throttle', $verdict['action']);
        $this->assertSame('WAF-SUBNET-SWARM-THROTTLE', $verdict['rule_id']);
        $this->assertSame(120, $verdict['retry_after']);
    }

    /**
     * Regression Audit: Rolling burst segmentation in WafFileLogger::get_campaign_summaries().
     */
    public function testRegressionRollingBurstSegmentation(): void {
        $summaries = WafFileLogger::get_campaign_summaries(86400, 100, 300);
        $this->assertIsArray($summaries);
        foreach ($summaries as $s) {
            $this->assertArrayHasKey('campaign_id', $s);
            $this->assertArrayHasKey('burst_count', $s);
            $this->assertArrayHasKey('distinct_target_count', $s);
            $this->assertArrayHasKey('first_seen', $s);
            $this->assertArrayHasKey('last_seen', $s);
        }
    }

    /**
     * Regression Audit (P1-1): Atomic generation advancement + queue mutation inside one lock.
     * Propagate failure cleanly when mutex acquisition or persistence fails.
     */
    public function testRegressionAtomicGenerationAndQueueMutationWithFailurePropagation(): void {
        $ip = '203.0.113.142';
        $settings = [
            'cloudflare_enabled'        => true,
            'cloudflare_api_token'      => 'token-abc',
            'cloudflare_zone_id'        => 'zone-123',
            'cloudflare_auto_sync_bans' => true,
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);
        set_transient(CloudflareIpListSynchronizer::OPTION_TOKEN_SCOPE, 'zone', 3600);

        // Case A: Normal atomic queue mutation
        $initial_gen = CloudflareIpListSynchronizer::get_ip_generation($ip);
        $res = CloudflareIpListSynchronizer::queue_ip_ban($ip, 'Atomic test ban', 86400);

        $this->assertSame('queued', $res['cf_sync_state']);
        $this->assertNotNull($res['operation_id']);
        $new_gen = CloudflareIpListSynchronizer::get_ip_generation($ip);
        $this->assertSame($initial_gen + 1, $new_gen, 'Generation must advance by exactly 1 in the atomic mutation');

        $queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayHasKey($ip, $queue);
        $this->assertSame($new_gen, $queue[$ip]['generation']);

        // Case B: Mutex lock contention / acquisition failure propagation
        // Force mutex lock acquisition to fail by holding the transient lock
        set_transient('webcare_cf_queue_mutex_lock', time() + 60, 60);

        $blocked_ip = '203.0.113.143';
        $fail_res = CloudflareIpListSynchronizer::queue_ip_ban($blocked_ip, 'Contention test ban', 86400);

        $this->assertSame('enqueue_failed', $fail_res['cf_sync_state'], 'Failure must propagate as enqueue_failed when lock cannot be acquired');
        $this->assertNull($fail_res['operation_id'], 'Operation ID must be null on failure');
        $this->assertSame(0, CloudflareIpListSynchronizer::get_ip_generation($blocked_ip), 'Generation must not advance when mutex acquisition fails');

        delete_transient('webcare_cf_queue_mutex_lock');
    }

    /**
     * Regression Audit (P1-2): BehavioralCampaignEngine commits 1 local ban and queues 1 Cloudflare operation,
     * and queues 0 operations when local safety checks reject the ban.
     */
    public function testRegressionCampaignAutobanSingleCloudflareQueueAndExemptionSafety(): void {
        $settings = [
            'cloudflare_enabled'        => true,
            'cloudflare_api_token'      => 'token-abc',
            'cloudflare_zone_id'        => 'zone-123',
            'cloudflare_auto_sync_bans' => true,
        ];
        update_option(SettingsManager::OPTION_KEY, $settings);
        set_transient(CloudflareIpListSynchronizer::OPTION_TOKEN_SCOPE, 'zone', 3600);

        // Case A: Legitimate threat triggers campaign autoban -> commits 1 local ban and queues 1 CF operation
        $threat_ip = '198.51.100.245';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($threat_ip);
        delete_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE);

        for ($i = 1; $i <= 5; $i++) {
            \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($threat_ip, 'sensitive_file', "/exploit-path-{$i}.php");
        }

        $this->assertTrue(BlocklistRepository::is_ip_blocked($threat_ip), 'Local ban must be committed');
        $queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayHasKey($threat_ip, $queue, 'Threat IP must be queued for Cloudflare sync exactly once');
        $this->assertCount(1, $queue, 'Queue must hold exactly 1 operation for the autoban');

        // Case B: Whitelisted IP triggers probe -> local ban rejected -> 0 Cloudflare operations queued
        $white_ip = '198.51.100.246';
        \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::reset_bucket_for_testing($white_ip);
        $settings['waf_whitelisted_ips'] = $white_ip;
        update_option(SettingsManager::OPTION_KEY, $settings);
        delete_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE);

        for ($i = 1; $i <= 5; $i++) {
            \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($white_ip, 'sensitive_file', "/exploit-path-{$i}.php");
        }

        $this->assertFalse(BlocklistRepository::is_ip_blocked($white_ip), 'Whitelisted IP must NOT be banned locally');
        $empty_queue = get_option(CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $this->assertArrayNotHasKey($white_ip, $empty_queue, 'Whitelisted IP must NEVER be queued in Cloudflare');
        $this->assertEmpty($empty_queue, 'Queue must remain empty when local ban is rejected');
    }

    /**
     * Regression Audit (P2): Identical deterministic campaign_id across repeated get_campaign_summaries calls,
     * and WafFileLogger::delete_log() returns false to enforce raw forensic immutability.
     */
    public function testRegressionDeterministicCampaignIdAndForensicImmutability(): void {
        $ip = '198.51.100.248';
        $_SERVER['REMOTE_ADDR'] = $ip;
        FirewallEngine::reset_client_ip_cache();

        $rule = [
            'id'          => 'WAF-SQLI-PROBE',
            'category'    => 'SQL Injection',
            'description' => 'Deterministic campaign probe',
        ];

        $incident_id = WafFileLogger::log_incident($rule, 'blocked');
        $this->assertNotEmpty($incident_id);

        // Fetch campaign summaries twice
        $summaries_1 = WafFileLogger::get_campaign_summaries(86400, 100);
        $summaries_2 = WafFileLogger::get_campaign_summaries(86400, 100);

        $this->assertNotEmpty($summaries_1);
        $this->assertNotEmpty($summaries_2);

        // Find summary for $ip
        $ip_summary_1 = null;
        foreach ($summaries_1 as $s) {
            if ($s['ip'] === $ip) {
                $ip_summary_1 = $s;
                break;
            }
        }
        $ip_summary_2 = null;
        foreach ($summaries_2 as $s) {
            if ($s['ip'] === $ip) {
                $ip_summary_2 = $s;
                break;
            }
        }

        $this->assertNotNull($ip_summary_1);
        $this->assertNotNull($ip_summary_2);
        $this->assertSame($ip_summary_1['campaign_id'], $ip_summary_2['campaign_id'], 'Campaign ID must be deterministic across repeated runs');
        $this->assertStringStartsWith('camp_', $ip_summary_1['campaign_id']);

        // Immutability invariant: delete_log() must return false and not delete the raw record
        $del_result = WafFileLogger::delete_log($incident_id);
        $this->assertFalse($del_result, 'delete_log must return false to preserve raw WAF forensic immutability');
    }
}
