<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Core\RouteClassifier;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\Core\AlwaysOnCoreGuard;
use WebCareProScanner\Firewall\Core\BehavioralCampaignEngine;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\Evaluators\AiAgentBehaviorEvaluator;
use WebCareProScanner\Firewall\Evaluators\ProtocolAndBotEvaluator;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\FormSpamProtectionEngine;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;
use WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine;
use WebCareProScanner\Firewall\OfficialCrawlerRegistry;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Security\SecretVault;
use WebCareProScanner\System\PluginConflictChecker;
use WebCareProScanner\System\SettingsManager;

final class WafLiveTelemetryHardeningTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        RuntimeSqlRaspEngine::reset_runtime_auth_state();
        RuntimeSqlRaspEngine::reset_query_shape_cache();
        OfficialCrawlerRegistry::set_cache_for_testing(null);
        FirewallEngine::reset_client_ip_cache();
    }

    public function testFormTimeGateTokenAvoidsVaultDlpFalsePositiveAndValidates(): void {
        $token = FormSpamProtectionEngine::generate_time_gate_token();
        $this->assertStringStartsWith('wctg1.', $token);
        $this->assertStringNotContainsString('webcare_gcm:', $token);

        // Embedding the token in inline public HTML must NEVER trigger ResponseDlpSentinel redaction
        $html = '<html><body><script>var cfg = {"hpName":"webcare_hp_12345678","token":"' . $token . '","gate":true};</script></body></html>';
        $dlp  = ResponseDlpSentinel::inspect_and_redact($html, true);
        $this->assertFalse($dlp['leaked'], 'Public form time-gate token must not trigger WEBCARE_VAULT_CIPHER DLP redaction.');
        $this->assertSame($html, $dlp['safe_body']);

        // Valid token after min_interaction_seconds passes submission validation
        $old_payload = (time() - 5) . '|' . bin2hex(random_bytes(8));
        $rm = new \ReflectionMethod(FormSpamProtectionEngine::class, 'get_time_gate_hmac_key');
        $rm->setAccessible(true);
        $key = (string) $rm->invoke(null);
        $valid_past_token = 'wctg1.' . rtrim(strtr(base64_encode($old_payload), '+/', '-_'), '=') . '.' . hash_hmac('sha256', $old_payload, $key);

        update_option(SettingsManager::OPTION_KEY, array_merge(SettingsManager::get_defaults(), [
            'form_spam_protection_enabled' => true,
            'form_speed_gate_enabled'      => true,
            'form_min_interaction_seconds' => 1,
        ]));
        SettingsManager::reset_settings_cache();

        $res = FormSpamProtectionEngine::evaluate_submission([
            'webcare_time_gate' => $valid_past_token,
        ], 'WordPress Comments / Reviews');
        $this->assertTrue($res);

        // Tampered HMAC signature must fail
        $tampered = substr($valid_past_token, 0, -4) . 'ffff';
        $bad_res  = FormSpamProtectionEngine::evaluate_submission([
            'webcare_time_gate' => $tampered,
        ], 'WordPress Comments / Reviews');
        $this->assertInstanceOf(\WP_Error::class, $bad_res);

        // Cached page with legacy SecretVault encrypted token still validates seamlessly
        $legacy_token = SecretVault::encrypt((time() - 5) . '|198.51.100.20');
        $legacy_res   = FormSpamProtectionEngine::evaluate_submission([
            'webcare_time_gate' => $legacy_token,
        ], 'WordPress Comments / Reviews');
        $this->assertTrue($legacy_res);
    }

    public function testSqlRaspAllowsSingleTableExistenceLookupWhileBlockingSchemaInjection(): void {
        // Benign single-table existence check used by plugins / DB drop-ins
        $safe = "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'wp_gf_entry'";
        $this->assertNull(RuntimeSqlRaspEngine::detect_sql_anomaly($safe));

        $safe_count = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'wp_db' AND table_name = 'wp_wfls_settings'";
        $this->assertNull(RuntimeSqlRaspEngine::detect_sql_anomaly($safe_count));

        // Malicious UNION SELECT against INFORMATION_SCHEMA.TABLES must still be blocked
        $union_sqli = "SELECT ID, post_title FROM wp_posts WHERE ID = 1 UNION SELECT table_name, table_type FROM information_schema.tables WHERE table_name = 'wp_users'";
        $this->assertSame('INFORMATION_SCHEMA_PROBE', RuntimeSqlRaspEngine::detect_sql_anomaly($union_sqli));

        // Wildcard enumeration of all tables (no literal TABLE_NAME = '') must be blocked
        $wildcard_dump = "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()";
        $this->assertSame('INFORMATION_SCHEMA_PROBE', RuntimeSqlRaspEngine::detect_sql_anomaly($wildcard_dump));

        // Column enumeration must always be blocked
        $col_probe = "SELECT column_name FROM information_schema.columns WHERE table_name = 'wp_users'";
        $this->assertSame('INFORMATION_SCHEMA_PROBE', RuntimeSqlRaspEngine::detect_sql_anomaly($col_probe));
    }

    public function testOfficialGoogleAdsBotMozDotBotAndModernChromeNoFalsePositive(): void {
        // AdsBot-Google-Mobile from official Google range 72.14.192.0/18 with Chrome/157
        $ads_ip = '72.14.199.163';
        $ads_ua = 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.8103.78 Mobile Safari/537.36 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)';

        $this->assertSame('google-special', OfficialCrawlerRegistry::get_verified_crawler_identity($ads_ip, $ads_ua));

        // Moz DotBot from official CIDR 216.244.64.0/19
        $this->assertTrue(BotReconDefense::is_search_bot_in_official_cidrs('216.244.66.243', 'dotbot'));

        update_option(SettingsManager::OPTION_KEY, array_merge(SettingsManager::get_defaults(), [
            'waf_ai_challenge_stealth_agents' => true,
        ]));
        SettingsManager::reset_settings_cache();

        $evaluator = new AiAgentBehaviorEvaluator();

        // AdsBot-Google-Mobile on HTTPS without Sec-Fetch headers must NOT be challenged
        $ads_ctx = new RequestContext(
            ip: $ads_ip,
            method: 'GET',
            uri: '/services/',
            headers: [],
            server: ['HTTPS' => 'on', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/services/', 'REMOTE_ADDR' => $ads_ip],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: $ads_ua
        );
        $this->assertNull($evaluator->evaluate_runtime_request($ads_ctx));

        // Modern Chrome/158 on HTTPS with Sec-Fetch must NOT score impossible_browser_version_future
        $chrome_ctx = new RequestContext(
            ip: '198.51.100.77',
            method: 'GET',
            uri: '/',
            headers: ['sec-fetch-site' => 'none', 'sec-fetch-mode' => 'navigate', 'sec-fetch-dest' => 'document'],
            server: ['HTTPS' => 'on', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.77'],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36'
        );
        $this->assertNull($evaluator->evaluate_runtime_request($chrome_ctx));

        // /robots.txt read-only request without Sec-Fetch or UA must pass cleanly
        $robots_ctx = new RequestContext(
            ip: '198.51.100.78',
            method: 'GET',
            uri: '/robots.txt',
            headers: [],
            server: ['HTTPS' => 'on', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/robots.txt', 'REMOTE_ADDR' => '198.51.100.78'],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: ''
        );
        $this->assertNull($evaluator->evaluate_runtime_request($robots_ctx));
    }

    public function testSubdirectoryXmlRpcSensitiveArchivesRawPhpProbesAndCloudflareSelfBanGuard(): void {
        // 1. RouteClassifier maps subdirectory xmlrpc.php to AuthLogin
        $this->assertSame(
            RouteClass::AuthLogin,
            RouteClassifier::classify(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/old/xmlrpc.php'])
        );

        // 2. Expanded sensitive archive & webshell probes caught, while uploads/*.zip remains safe
        $settings = array_merge(SettingsManager::get_defaults(), [
            'waf_enabled'                     => true,
            'waf_mode'                        => 'enabled',
            'waf_disable_xmlrpc'              => true,
            'waf_block_sensitive_file_probes' => true,
            'waf_block_empty_user_agent'      => true,
            'waf_ai_challenge_stealth_agents' => true,
        ]);
        update_option(SettingsManager::OPTION_KEY, $settings);
        SettingsManager::reset_settings_cache();

        foreach (['/site.zip', '/www.zip', '/website.zip', '/wwwroot.jar', '/ALFA_DATA/', '/wp-conflg.php', '/wp-admin.php', '/wp-includes/blocks/button/admiin.php'] as $mal_uri) {
            $hit = ExploitSignatureEngine::check_sensitive_file_probe($mal_uri, $settings);
            $this->assertNotNull($hit, "Expected sensitive probe match for {$mal_uri}");
        }
        $this->assertNull(
            ExploitSignatureEngine::check_sensitive_file_probe('/wp-content/uploads/2026/11/brochure.zip', $settings),
            'Legitimate downloadable media archive under /wp-content/uploads/ must not be blocked.'
        );

        // 3. Go-http-client probing /wp-includes/*.php and missing root webshells is hard-blocked (403)
        $ai_eval = new AiAgentBehaviorEvaluator();
        $go_ctx  = new RequestContext(
            ip: '203.0.113.201',
            method: 'GET',
            uri: '/wp-includes/author-template-object.php',
            headers: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-includes/author-template-object.php', 'REMOTE_ADDR' => '203.0.113.201'],
            cookies: [],
            params: [],
            formParams: [],
            userAgent: 'Go-http-client/2.0'
        );
        $go_verdict = $ai_eval->evaluate_runtime_request($go_ctx);
        $this->assertNotNull($go_verdict);
        $this->assertSame('block', $go_verdict->action);
        $this->assertSame('WAF-RAW-CLIENT-PHP-PROBE', $go_verdict->ruleId);

        // 4. Blank UA probing /wp-admin/meta/ (even with spoofed ?doing_wp_cron=1) is hard-blocked (403), whereas GET /robots.txt is allowed
        $bot_eval = new ProtocolAndBotEvaluator();
        $empty_admin_ctx = new RequestContext(
            ip: '203.0.113.202',
            method: 'GET',
            uri: '/wp-admin/meta/?doing_wp_cron=1',
            headers: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-admin/meta/?doing_wp_cron=1', 'REMOTE_ADDR' => '203.0.113.202'],
            cookies: [],
            params: ['doing_wp_cron' => '1'],
            formParams: [],
            queryParams: ['doing_wp_cron' => '1'],
            userAgent: ''
        );
        $empty_verdict = $bot_eval->evaluate_runtime_request($empty_admin_ctx);
        $this->assertNotNull($empty_verdict);
        $this->assertSame('block', $empty_verdict->action);
        $this->assertSame('WAF-EMPTY-USER-AGENT', $empty_verdict->ruleId);

        // 5. Subdirectory XML-RPC brute-force escalates to 24h campaign auto-ban after 5 distinct targets
        $botnet_ip = '203.0.113.209';
        BehavioralCampaignEngine::reset_bucket_for_testing($botnet_ip);
        BlocklistRepository::remove_blocked_ip($botnet_ip);

        $core_guard = new AlwaysOnCoreGuard();
        $valid_host = (string) (wp_parse_url(home_url(), PHP_URL_HOST) ?: 'example.org');
        foreach (['/new/xmlrpc.php', '/old/xmlrpc.php', '/cms/xmlrpc.php', '/wpsite/xmlrpc.php', '/blog/xmlrpc.php'] as $x_path) {
            $x_ctx = new RequestContext(
                ip: $botnet_ip,
                method: 'POST',
                uri: $x_path,
                headers: ['host' => $valid_host],
                server: ['HTTP_HOST' => $valid_host, 'REQUEST_METHOD' => 'POST', 'REQUEST_URI' => $x_path, 'REMOTE_ADDR' => $botnet_ip],
                cookies: [],
                params: [],
                formParams: [],
                userAgent: 'Mozilla/5.0'
            );
            $x_verdict = $core_guard->evaluate_runtime_request($x_ctx);
            $this->assertNotNull($x_verdict);
            $this->assertSame('WAF-XMLRPC-DISABLED', $x_verdict->ruleId);
        }
        $this->assertTrue(BlocklistRepository::is_ip_blocked($botnet_ip), '5 distinct subdirectory XML-RPC probes must auto-ban attacker IP.');
        BlocklistRepository::remove_blocked_ip($botnet_ip);

        // 6. Cloudflare Anycast Edge IP can NEVER be added to local IP ban list
        $cf_edge_ip = '172.71.155.152';
        $this->assertFalse(BlocklistRepository::add_blocked_ip($cf_edge_ip, 'Test edge ban guard', 3600));
        $this->assertFalse(BlocklistRepository::is_ip_blocked($cf_edge_ip));

        // 7. PluginConflictChecker surfaces calm warning when Cloudflare is active with proxy trust disabled
        update_option(SettingsManager::OPTION_KEY, array_merge($settings, [
            'cloudflare_enabled'              => true,
            'waf_cloudflare_proxy_trust_mode' => 'disabled',
        ]));
        SettingsManager::reset_settings_cache();
        $compat = PluginConflictChecker::run_check();
        $ids    = array_column($compat['conflicts'], 'id');
        $this->assertContains('env_cloudflare_proxy_trust_disabled', $ids);

        // 8. WafFileLogger reports cf_sync_state = 'not_queued' (never 'queued') on non-ban detections
        $_SERVER['REMOTE_ADDR'] = '198.51.100.230';
        FirewallEngine::reset_client_ip_cache();
        update_option(SettingsManager::OPTION_KEY, array_merge($settings, [
            'cloudflare_enabled'        => true,
            'cloudflare_auto_sync_bans' => true,
        ]));
        SettingsManager::reset_settings_cache();
        WafFileLogger::log_incident([
            'id'          => 'WAF-TEST-DETECT-ONLY',
            'category'    => 'Test Telemetry',
            'description' => 'Non-ban detection check',
        ], 'detected');
        $q = WafFileLogger::query_logs(['ip' => '198.51.100.230', 'action' => 'all', 'range' => 'all'], 5, 0);
        $this->assertNotEmpty($q['logs']);
        $this->assertSame('not_queued', $q['logs'][0]['cf_sync_state']);
    }

    public function testAsyncCrawlerDnsCampaignIdempotencyCloudflareCidrGuardAndBoundedXmlRpcRoute(): void {
        // 1. P1: Async tri-state crawler DNS — unknown IP is never treated as verified and queues bounded background lookup
        $unknown_ip = '203.0.113.241';
        delete_transient('webcareproscan_bot_dns_v2_' . md5($unknown_ip . '_googlebot'));
        delete_option(BotReconDefense::OPTION_DNS_QUEUE);
        $this->assertSame('unknown', BotReconDefense::get_cached_bot_dns_state($unknown_ip, 'googlebot'));
        $this->assertFalse(BotReconDefense::verify_search_bot_reverse_dns($unknown_ip, 'googlebot'));
        $dns_queue = get_option(BotReconDefense::OPTION_DNS_QUEUE, []);
        $this->assertNotEmpty($dns_queue);

        // Cached 'conflicting' state triggers BOT-FAKE-CRAWLER-SPOOF without synchronous DNS
        set_transient('webcareproscan_bot_dns_v2_' . md5($unknown_ip . '_googlebot'), 'conflicting', 300);
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';
        $spoof_hit = BotReconDefense::inspect_bot($unknown_ip, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', [
            'waf_block_fake_bots' => true,
        ]);
        $this->assertNotNull($spoof_hit);
        $this->assertSame('BOT-FAKE-CRAWLER-SPOOF', $spoof_hit['id']);

        // 2. P2: Campaign escalation is idempotent within the 60s window and preserves cf_sync_state
        $camp_ip = '203.0.113.242';
        BehavioralCampaignEngine::reset_bucket_for_testing($camp_ip);
        BlocklistRepository::remove_blocked_ip($camp_ip);
        $res5 = null;
        for ($i = 1; $i <= 5; $i++) {
            $res5 = BehavioralCampaignEngine::record_probe($camp_ip, 'sensitive_file', "/probe-{$i}.zip");
        }
        $this->assertTrue($res5['escalate_ban']);
        $this->assertArrayHasKey('cf_sync_state', $res5);
        $meta_after_5 = FirewallEngine::get_ip_block_meta($camp_ip);
        $res6 = BehavioralCampaignEngine::record_probe($camp_ip, 'sensitive_file', '/probe-6.zip');
        $this->assertTrue($res6['escalate_ban']);
        $meta_after_6 = FirewallEngine::get_ip_block_meta($camp_ip);
        $this->assertSame($meta_after_5['blocked_at'] ?? null, $meta_after_6['blocked_at'] ?? null, '6th probe in same campaign window must not re-commit local ban.');
        BlocklistRepository::remove_blocked_ip($camp_ip);

        // 3. P2: Overlapping Cloudflare Anycast CIDRs (IPv4 & IPv6) are rejected by BlocklistRepository
        $this->assertFalse(BlocklistRepository::add_blocked_ip('172.64.0.0/12', 'Superset CF range', 3600));
        $this->assertFalse(BlocklistRepository::add_blocked_ip('172.71.155.0/24', 'Subnet CF range', 3600));
        $this->assertFalse(BlocklistRepository::add_blocked_ip('2606:4700::/32', 'CF IPv6 range', 3600));
        $this->assertTrue(BlocklistRepository::add_blocked_ip('198.51.100.0/24', 'Non-CF test CIDR', 3600));
        BlocklistRepository::remove_blocked_ip('198.51.100.0/24');

        // 4. Minor: RouteClassifier uses bounded path-segment matching for xmlrpc.php
        $this->assertSame(
            RouteClass::PublicGet,
            RouteClassifier::classify(['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/blog/how-to-disable-xmlrpc.php-guide'])
        );
        $this->assertSame(
            RouteClass::AuthLogin,
            RouteClassifier::classify(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/sub/xmlrpc.php'])
        );
    }

    /**
     * Verify rapid 2-target webshell escalation, canonical CF Ban log enrichment,
     * zero-SQL filesystem lockout indexing, and mobile single-hit empty-AJAX noise suppression.
     */
    public function testRapidWebshellAutobanCfBanLogSyncAndFilesystemLockoutIndex(): void {
        update_option(SettingsManager::OPTION_KEY, [
            'waf_enabled'                     => true,
            'waf_mode'                        => 'enabled',
            'waf_enable_progressive_warnings' => true,
            'waf_block_empty_user_agent'      => true,
            'cloudflare_enabled'              => true,
            'cloudflare_api_token'            => 'cf_test_tok',
            'cloudflare_zone_id'              => 'cf_test_zone',
            'cloudflare_auto_sync_bans'       => true,
        ]);

        // 1. Blank-UA sensitive PHP probe carries is_hard_block => true (never downgraded to progressive warning)
        $bot_eval = new ProtocolAndBotEvaluator();
        $ws_ip    = '203.0.113.215';
        BehavioralCampaignEngine::reset_bucket_for_testing($ws_ip);
        BlocklistRepository::remove_blocked_ip($ws_ip);
        delete_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_BAN_QUEUE);

        $hit1 = $bot_eval->evaluate_runtime_request(new RequestContext(
            ip: $ws_ip,
            method: 'GET',
            uri: '/wp-content/plugins/hellopress/wp_filemanager.php',
            headers: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-content/plugins/hellopress/wp_filemanager.php', 'REMOTE_ADDR' => $ws_ip],
            userAgent: ''
        ));
        $this->assertNotNull($hit1);
        $this->assertTrue($hit1->context['is_hard_block'] ?? false);
        $this->assertFalse(
            \WebCareProScanner\Firewall\Core\ViolationResponder::is_progressive_warning_rule(
                ['id' => 'WAF-EMPTY-USER-AGENT', 'category' => 'Bot Defense', 'is_hard_block' => true],
                ['waf_enable_progressive_warnings' => true]
            ),
            'Sensitive PHP probe with blank UA must never receive a progressive warning pass.'
        );

        // 2nd distinct webshell probe from same IP immediately triggers 24h local ban + Cloudflare queue
        $hit2 = $bot_eval->evaluate_runtime_request(new RequestContext(
            ip: $ws_ip,
            method: 'GET',
            uri: '/ccc.php',
            headers: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/ccc.php', 'REMOTE_ADDR' => $ws_ip],
            userAgent: ''
        ));
        $this->assertNotNull($hit2);
        $this->assertTrue(BlocklistRepository::is_ip_blocked($ws_ip), '2nd distinct webshell probe must auto-ban immediately.');
        $this->assertSame('queued', $hit2->context['cf_sync_state'] ?? null);

        // 2. WafFileLogger::query_logs accurately marks cf_synced = true & ban_scope = 'edge_synced' from canonical OPTION_ACTIVE_EDGE_BANS
        $tmp_dir = sys_get_temp_dir() . '/wcp_cfban_test_' . bin2hex(random_bytes(4));
        \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = $tmp_dir;
        $_SERVER['REMOTE_ADDR']    = $ws_ip;
        $_SERVER['REQUEST_URI']    = '/ccc.php';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        FirewallEngine::reset_client_ip_cache();
        $GLOBALS['wp_mock_transients'] = [];

        \WebCareProScanner\Firewall\WafFileLogger::log_incident([
            'id'          => 'WAF-EMPTY-USER-AGENT',
            'category'    => 'Bot Defense',
            'description' => 'Blank UA webshell probe',
        ], 'blocked');

        // While still in queue -> edge_queued
        $q_res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['ip' => $ws_ip], 10, 0);
        $this->assertNotEmpty($q_res['logs']);
        $this->assertTrue($q_res['logs'][0]['cf_queued']);
        $this->assertSame('edge_queued', $q_res['logs'][0]['ban_scope']);

        // Once synced into CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS -> cf_synced = true & ban_scope = 'edge_synced'
        update_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS, [
            $ws_ip => [
                'target'     => $ws_ip,
                'mode'       => 'zone',
                'item_id'    => 'cf_rule_999',
                'state'      => 'active',
                'expires_at' => time() + 86400,
            ],
        ]);
        $s_res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['ip' => $ws_ip], 10, 0);
        $this->assertTrue($s_res['logs'][0]['cf_synced'], 'Synced Cloudflare Edge ban must set cf_synced = true.');
        $this->assertSame('edge_synced', $s_res['logs'][0]['ban_scope']);

        // 3. Zero-SQL filesystem lockout index stores and resolves Support Reference Code cleanly
        \WebCareProScanner\Firewall\WafFileLogger::record_lockout_index('WEBCARE-9X9X', 'WEBCARE-11223344', $ws_ip, [
            'ref_code'    => 'WEBCARE-9X9X',
            'incident_id' => 'WEBCARE-11223344',
            'client_ip'   => $ws_ip,
            'timestamp'   => time(),
        ]);
        $found_lock = \WebCareProScanner\Firewall\WafFileLogger::lookup_lockout_index('WEBCARE-9X9X');
        $this->assertIsArray($found_lock);
        $this->assertSame($ws_ip, $found_lock['client_ip']);

        // 4. Single-hit mobile browser missing-action admin-ajax POST is NOT logged in monitor mode (noise suppressed)
        $ajax_eval = new \WebCareProScanner\Firewall\Evaluators\AuthAndAjaxSurfaceEvaluator();
        $mob_ip    = '198.51.100.77';
        $_SERVER['REMOTE_ADDR'] = $mob_ip;
        FirewallEngine::reset_client_ip_cache();
        $GLOBALS['wp_mock_transients'] = [];
        update_option(SettingsManager::OPTION_KEY, [
            'waf_enabled'           => true,
            'waf_mode'              => 'enabled',
            'waf_guest_ajax_policy' => 'monitor',
        ]);
        $mob_ctx = new RequestContext(
            ip: $mob_ip,
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            headers: [],
            server: ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-admin/admin-ajax.php', 'SCRIPT_NAME' => '/wp-admin/admin-ajax.php', 'REMOTE_ADDR' => $mob_ip],
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) CriOS/155.0.7632.162 Mobile/15E148 Safari/604.1'
        );
        $this->assertNull($ajax_eval->evaluate_runtime_request($mob_ctx));
        $mob_logs_1 = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['ip' => $mob_ip], 10, 0);
        $this->assertCount(0, $mob_logs_1['logs'], 'Isolated single-hit mobile empty-action AJAX request must not clutter WAF logs.');

        // Cleanup
        \WebCareProScanner\Firewall\WafFileLogger::$custom_storage_dir = null;
        BlocklistRepository::remove_blocked_ip($ws_ip);
        delete_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_ACTIVE_EDGE_BANS);
        delete_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_BAN_QUEUE);
    }
}
