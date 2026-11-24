<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer;
use WebCareProScanner\Firewall\Core\AllowlistManager;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\Core\ViolationResponder;
use WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\FormSpamProtectionEngine;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Hardening\SecurityHeadersEngine;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\SystemDoctor;

class Phase3WafAndRaspHardeningTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        if (function_exists('webcare_purge_test_storage')) {
            webcare_purge_test_storage();
        }
        $GLOBALS['wp_mock_options']        = [];
        $GLOBALS['wp_mock_transients']     = [];
        $GLOBALS['wp_mock_users']          = [];
        $GLOBALS['wp_mock_user_meta']      = [];
        $GLOBALS['wp_mock_current_user']   = null;
        $GLOBALS['WEBCARE_TEST_RAW_INPUT'] = null;
        $_GET                           = [];
        $_POST                          = [];
        $_FILES                         = [];
        $_REQUEST                       = [];
        $_COOKIE                        = [];
        $_SERVER['REQUEST_METHOD']      = 'GET';
        $_SERVER['REQUEST_URI']         = '/';
        $_SERVER['QUERY_STRING']        = '';
        $_SERVER['REMOTE_ADDR']         = '198.51.100.10';
        unset($_SERVER['HTTP_TRANSFER_ENCODING'], $_SERVER['SERVER_PROTOCOL'], $_SERVER['HTTP_X_LSCACHE_VARY']);

        FirewallEngine::reset_client_ip_cache();
        SettingsManager::reset_settings_cache();
        RuntimeSqlRaspEngine::reset_runtime_auth_state();
        RuntimeSqlRaspEngine::reset_query_shape_cache();
    }

    public function testRawJsonUnicodeEscapeNotStrippedByUnslashAndHttp2MultipartAllowed(): void {
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'waf_enabled' => true,
            'waf_mode'    => 'enabled',
        ]));
        SettingsManager::reset_settings_cache();

        // Raw php://input JSON containing \u003cscript\u003e must preserve backslashes for decoding
        $_SERVER['REQUEST_METHOD']         = 'POST';
        $_SERVER['REQUEST_URI']            = '/wp-json/custom/v1/comment';
        $_SERVER['CONTENT_TYPE']           = 'application/json';
        $GLOBALS['WEBCARE_TEST_RAW_INPUT'] = '{"note":"\u003cscript\u003ealert(1)\u003c/script\u003e"}';

        $hit = ExploitSignatureEngine::evaluate_rules(SettingsManager::get_settings(), false);
        $this->assertNotNull($hit, 'JSON \u003cscript\u003e payload must be decoded intact and blocked.');

        // HTTP/2 multipart upload missing CONTENT_LENGTH should not false-positive WAF-MULTIPART-MISSING-CONTENT-LENGTH
        $GLOBALS['WEBCARE_TEST_RAW_INPUT'] = null;
        $_SERVER['CONTENT_TYPE']           = 'multipart/form-data; boundary=----abc';
        $_SERVER['SERVER_PROTOCOL']        = 'HTTP/2.0';
        $_POST                             = ['comment' => 'Hello world'];
        $h2_hit                            = ExploitSignatureEngine::evaluate_rules(SettingsManager::get_settings(), false);
        $this->assertNull($h2_hit, 'Benign HTTP/2 multipart request without Content-Length must not trigger false block.');
    }

    public function testSvgUploadScannerBlocksHandlerUseAndEntityEncodedPayloads(): void {
        $tmp_svg = sys_get_temp_dir() . '/wcp_test_evil_' . uniqid() . '.svg';
        file_put_contents($tmp_svg, '<svg xmlns="http://www.w3.org/2000/svg"><handler ev:event="load">alert(1)</handler><use href="data:image/svg+xml;base64,PHNjcmlwdD4="/></svg>');
        try {
            $res = ExploitSignatureEngine::inspect_uploaded_file([
                'name'     => 'evil.svg',
                'type'     => 'image/svg+xml',
                'tmp_name' => $tmp_svg,
                'error'    => 0,
                'size'     => 140,
            ]);
            $this->assertArrayHasKey('error', $res, 'SVG with <handler>/<use href="data:"> must be rejected.');

            // Also verify HTML entity-encoded event handler payload is blocked
            file_put_contents($tmp_svg, '<svg xmlns="http://www.w3.org/2000/svg" onfocus="&#x6a;avascript:alert(1)"/>');
            $res2 = ExploitSignatureEngine::inspect_uploaded_file([
                'name'     => 'encoded.svg',
                'type'     => 'image/svg+xml',
                'tmp_name' => $tmp_svg,
                'error'    => 0,
                'size'     => 100,
            ]);
            $this->assertArrayHasKey('error', $res2, 'SVG with arbitrary on* attribute or HTML entity-encoded script must be rejected.');
        } finally {
            @unlink($tmp_svg);
        }
    }

    public function testXmlRpcHardeningStripsPingbackAndBlocksSsrf(): void {
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'waf_enabled'        => true,
            'waf_disable_xmlrpc' => false,
        ]));
        SettingsManager::reset_settings_cache();

        $filtered = ExploitSignatureEngine::filter_xmlrpc_methods([
            'wp.getUsersBlogs'                 => 'cb1',
            'pingback.ping'                    => 'cb2',
            'pingback.extensions.getPingbacks' => 'cb3',
        ]);
        $this->assertArrayHasKey('wp.getUsersBlogs', $filtered);
        $this->assertArrayNotHasKey('pingback.ping', $filtered);
        $this->assertArrayNotHasKey('pingback.extensions.getPingbacks', $filtered);

        $ssrf = ExploitSignatureEngine::guard_xmlrpc_pingback_ssrf(false, [], 'http://169.254.169.254/latest/meta-data/');
        $this->assertInstanceOf(\WP_Error::class, $ssrf, 'Metadata IP must be blocked in XML-RPC pingback SSRF guard.');
    }

    public function testEditorBuilderRequiresUnfilteredHtmlAndRestBatchBlocksUserEnum(): void {
        // Author / Shop Manager lacking unfiltered_html must NOT qualify for verified builder exemption
        $author_user = new class {
            public int $ID = 77;
            /** @var array<string, bool> */
            public array $caps = ['edit_posts' => true, 'manage_woocommerce' => true];
            public function has_cap(string $cap): bool { return !empty($this->caps[$cap]); }
        };
        $GLOBALS['wp_mock_users'][77]    = $author_user;
        $GLOBALS['wp_mock_current_user'] = $author_user;
        $this->assertFalse(
            FirewallEngine::is_verified_editor_builder_request('/wp-json/wp/v2/posts/1'),
            'Users lacking unfiltered_html or manage_options must not bypass WAF builder checks.'
        );

        // Guest REST batch smuggling GET /wp/v2/users inside POST /wp/v2/batch must be blocked
        $GLOBALS['wp_mock_current_user'] = null;
        $_SERVER['REMOTE_ADDR']       = '198.51.100.88';
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'waf_enabled'              => true,
            'waf_guest_rest_policy'    => 'block',
            'waf_block_rest_user_enum' => true,
        ]));
        SettingsManager::reset_settings_cache();

        $req = new class('/wp/v2/batch', 'POST', ['requests' => [['method' => 'GET', 'path' => '/wp/v2/users']]]) {
            public function __construct(private string $r, private string $m, private array $p) {}
            public function get_route(): string { return $this->r; }
            public function get_method(): string { return $this->m; }
            public function get_json_params(): array { return $this->p; }
        };
        $dispatch = FirewallEngine::inspect_guest_rest_dispatch(null, new \stdClass(), $req);
        $this->assertInstanceOf(\WP_Error::class, $dispatch, 'Unauthenticated GET /wp/v2/users inside REST batch must be blocked.');

        // Sitemap & oEmbed enumeration protection for guests
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'block_user_enumeration' => true,
        ]));
        SettingsManager::reset_settings_cache();
        $this->assertFalse(SecurityHeadersEngine::filter_users_sitemap_provider(new \stdClass(), 'users'));
        $oembed = SecurityHeadersEngine::filter_oembed_author_metadata([
            'title'       => 'Post',
            'author_name' => 'admin_secret',
            'author_url'  => 'https://example.com/author/admin_secret/',
        ]);
        $this->assertArrayNotHasKey('author_name', $oembed);
        $this->assertArrayNotHasKey('author_url', $oembed);
    }

    public function testAllowlistCanonicalizesDotSegmentsAndEncodedTraversal(): void {
        $whitelist = "/whitelisted-endpoint\n/public-webhook";

        $this->assertTrue(AllowlistManager::is_url_whitelisted('/whitelisted-endpoint/callback', $whitelist));
        $this->assertFalse(
            AllowlistManager::is_url_whitelisted('/whitelisted-endpoint/../wp-login.php', $whitelist),
            'Dot-segment traversal out of whitelisted prefix must fail allowlist check.'
        );
        $this->assertFalse(
            AllowlistManager::is_url_whitelisted('/whitelisted-endpoint/%2e%2e/wp-admin/admin-ajax.php', $whitelist),
            'URL-encoded dot-segment traversal out of whitelisted prefix must fail allowlist check.'
        );
        $this->assertFalse(
            AllowlistManager::is_url_whitelisted('/whitelisted-endpoint/%252e%252e/secret', $whitelist),
            'Double-encoded dot-segment traversal out of whitelisted prefix must fail allowlist check.'
        );
    }

    public function testSqlRaspLexerDefeatsQuoteCommentSmugglingAndCoversExtendedTables(): void {
        // String literal containing '/*' followed by another '*/' previously swallowed everything between them
        $smuggled = "SELECT * FROM wp_posts WHERE post_title = '/*' UNION SELECT user_login, user_pass FROM wp_users WHERE b = '*/'";
        $this->assertSame(
            'UNION_SELECT_CREDENTIAL_TABLE',
            RuntimeSqlRaspEngine::detect_sql_anomaly($smuggled),
            'Single-pass SQL lexer must mask quotes before stripping comments so UNION SELECT cannot hide between two literals.'
        );

        // UNION DISTINCT SELECT + wp_wc_orders coverage
        $wc_sqli = 'SELECT * FROM wp_posts WHERE ID = 1 UNION DISTINCT SELECT id, billing_email FROM wp_wc_orders';
        $this->assertSame('UNION_SELECT_CREDENTIAL_TABLE', RuntimeSqlRaspEngine::detect_sql_anomaly($wc_sqli));

        // Benign query containing SQL-looking comment inside string literal remains clean
        $benign = "SELECT * FROM wp_posts WHERE post_title = 'How /* UNION SELECT */ works in SQL'";
        $this->assertNull(RuntimeSqlRaspEngine::detect_sql_anomaly($benign));
    }

    public function testVirtualPatchFixesNamespacedGadgetsHeadersContinuationAndFiles(): void {
        update_option(VirtualPatchManager::OPTION_PATCHES, [
            'CVE-2024-28000' => [
                'patch_id' => 'CVE-2024-28000',
                'enabled'  => true,
                'component' => 'generic',
                'php_rule' => [
                    'target_uris' => ['/wp-json/litespeed/', 'action=async_litespeed'],
                    'headers'     => ['X-LSCACHE-VARY'],
                    'regex'       => '/(litespeed_role|litespeed_hash|user_id=1)/i',
                ],
            ],
            'CVE-2024-5654' => [
                'patch_id' => 'CVE-2024-5654',
                'enabled'  => true,
                'component' => 'generic',
                'php_rule' => [
                    'target_uris' => ['give_action'],
                    'regex'       => '/(O:[0-9]+:"[a-zA-Z0-9_\\\\]+":|a:[0-9]+:\{|give_title)/i',
                ],
            ],
            'VPATCH-FILE-UPLOAD' => [
                'patch_id' => 'VPATCH-FILE-UPLOAD',
                'enabled'  => true,
                'component' => 'generic',
                'php_rule' => [
                    'target_uris' => ['/wp-json/'],
                    'methods'     => ['POST'],
                    'regex'       => '/(?:filename=[\'"][^\'"]+\.(php[0-9]?|phar|phtml|pht|sh|bash|cgi|exe|htaccess|user\.ini)(?:[\'"]|\.)|application\/x-php|text\/x-php)/i',
                ],
            ],
        ]);

        // CVE-2024-28000 without header must STILL match query string
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['QUERY_STRING']   = 'user_id=1&litespeed_hash=deadbeef';
        $hit_lsc = VirtualPatchManager::evaluate_request('198.51.100.1', '/wp-json/litespeed/v1/token?user_id=1&litespeed_hash=deadbeef');
        $this->assertNotNull($hit_lsc, 'CVE-2024-28000 query params must still evaluate when header is absent.');

        // CVE-2024-5654 namespaced PHP Object Injection
        $_SERVER['QUERY_STRING'] = 'give_action=purchase&data=' . urlencode('O:16:"Give\\Evil\\Gadget":1:{s:1:"x";i:1;}');
        $hit_give = VirtualPatchManager::evaluate_request('198.51.100.1', '/?give_action=purchase');
        $this->assertNotNull($hit_give, 'Namespaced serialized PHP object gadget must trigger CVE-2024-5654.');

        // VPATCH-FILE-UPLOAD $_FILES inspection
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['QUERY_STRING']   = '';
        $_FILES                    = [
            'file' => ['name' => 'avatar.php7.jpg', 'type' => 'image/jpeg'],
        ];
        $hit_upload = VirtualPatchManager::evaluate_request('198.51.100.1', '/wp-json/custom/v1/upload');
        $this->assertNotNull($hit_upload, 'VPATCH-FILE-UPLOAD must inspect $_FILES for executable double extensions.');
    }

    public function testViolationResponderDoesNotDoubleBanOnFirstStrike(): void {
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'waf_enabled'                     => true,
            'waf_mode'                        => 'enabled',
            'waf_enable_progressive_warnings' => true,
        ]));
        SettingsManager::reset_settings_cache();
        FirewallEngine::reset_client_ip_cache();

        // Simulate progressive warning rule reaching terminal strike -> check stored ban TTL = 3600 (NOT 86400 double-ban)
        if (!defined('WEBCAREPROSCAN_TESTING')) {
            define('WEBCAREPROSCAN_TESTING', true);
        }
        ob_start();
        ViolationResponder::handle_rule_violation([
            'id'          => 'WAF-BRUTE-TEST',
            'name'        => 'Progressive Strike Test',
            'category'    => 'Auth',
            'description' => 'Test warning strike',
            'severity'    => 'warning',
            'strike_info' => ['is_terminal_ban' => true],
        ], SettingsManager::get_settings(), '203.0.113.55', 403);
        ob_end_clean();

        $meta = FirewallEngine::get_ip_block_meta('203.0.113.55');
        $this->assertIsArray($meta);
        $ttl = (int) (($meta['expires_at'] ?? 0) - time());
        $this->assertGreaterThan(3000, $ttl);
        $this->assertLessThanOrEqual(3605, $ttl, 'First strike ban must remain 1h (3600s) instead of double-escalating to 24h in one violation.');
    }

    public function testFormSpamBotReconGhostTrapAndCloudflareEdgeHardening(): void {
        // FormSpam: forged base64 time_gate rejected
        update_option('webcareproscan_settings', array_merge(SettingsManager::get_defaults(), [
            'form_spam_protection_enabled' => true,
            'form_speed_gate_enabled'      => true,
        ]));
        SettingsManager::reset_settings_cache();
        $spam_res = FormSpamProtectionEngine::evaluate_submission([
            'webcare_time_gate' => base64_encode((time() - 30) . '|198.51.100.10'),
        ], 'WordPress Comments / Reviews');
        $this->assertInstanceOf(\WP_Error::class, $spam_res, 'Plain base64 forged time_gate must be rejected.');

        $raw_forged = FormSpamProtectionEngine::evaluate_submission([
            'webcare_time_gate' => (time() - 30) . '|198.51.100.10',
        ], 'WordPress Comments / Reviews');
        $this->assertInstanceOf(\WP_Error::class, $raw_forged, 'Unencrypted timestamp|ip plaintext time_gate must be rejected.');

        // FormSpam: missing time_gate on WordPress Comments / Reviews & WooCommerce Registration
        $missing_comment = FormSpamProtectionEngine::evaluate_submission([], 'WordPress Comments / Reviews');
        $this->assertInstanceOf(\WP_Error::class, $missing_comment);
        $this->assertSame('webcare_spam_missing_gate', $missing_comment->get_error_code());

        // BotReconDefense: spoofed PerplexityBot UA from random IP is NOT allowed as verified search citation bot
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $spoofed = BotReconDefense::inspect_bot('203.0.113.44', 'PerplexityBot/1.0 (+https://perplexity.ai/bot)', [
            'waf_block_ai_scrapers'         => true,
            'waf_ai_allow_search_citations' => true,
        ]);
        $this->assertNotNull($spoofed, 'Spoofed PerplexityBot UA from unverified IP must be blocked, not exempted.');

        // VisualRuleExpressionEngine: hybrid AND rule mixing IP + wp.user.is_logged_in refuses partial Edge compile
        $edge = VisualRuleExpressionEngine::to_cloudflare_edge_wirefilter([
            [
                'logic' => 'AND',
                'rules' => [
                    ['field' => 'http.request.uri.path', 'op' => 'contains', 'value' => '/wp-json/'],
                    ['field' => 'wp.user.is_logged_in', 'op' => 'is_false', 'value' => ''],
                ],
            ],
        ], 'OR');
        $this->assertSame('', $edge['expression'], 'Hybrid AND group with WP predicate must never drop the WP predicate at Cloudflare Edge.');

        // CloudflareSlotOptimizer: no spoofable cookie or substring /paypal /wc-api bypasses on Rule 4 SQLi
        $opt = new CloudflareSlotOptimizer();
        $r4  = $opt->compile_rule4_sqli_lfi_expression();
        $this->assertStringNotContainsString('wordpress_logged_in', $r4);
        $this->assertStringNotContainsString('/paypal', $r4);
        $this->assertStringNotContainsString('/wc-api', $r4);

        // SystemDoctor: flags 127.0.0.1 peer + forwarding headers without trusted proxies
        $_SERVER['REMOTE_ADDR']         = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
        update_option('webcareproscan_settings', SettingsManager::get_defaults());
        SettingsManager::reset_settings_cache();
        $diag   = SystemDoctor::run_diagnostics();
        $checks = array_column($diag['checks'], null, 'id');
        $this->assertArrayHasKey('proxy_ip_integrity', $checks);
        $this->assertSame('warn', $checks['proxy_ip_integrity']['status']);
    }

    public function testMicroWafCompilerRemovesSubscriberBypassAddsCacheHeadersAndLowercasesUri(): void {
        $rm = new \ReflectionMethod(MicroWafCompiler::class, 'generate_standalone_code');
        $rm->setAccessible(true);
        $code = (string) $rm->invokeArgs(null, [[], [], sys_get_temp_dir() . '/wcp_f2b.log', 'bypass_tok']);

        $this->assertStringContainsString('$auth_bypass_body = $mod_is_admin_user;', $code);
        $this->assertStringNotContainsString('$auth_bypass_body = $is_direct_script_target', $code);
        $this->assertStringContainsString('if (!$mod_is_admin_user && !empty($mod_rules[\'custom_rules_enforced\']))', $code);
        $this->assertStringContainsString('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $code);
        $this->assertStringContainsString('X-LiteSpeed-Cache-Control: no-cache', $code);
        $this->assertStringContainsString('$mod_clean_uri_lc = strtolower($mod_clean_uri);', $code);
    }
}
