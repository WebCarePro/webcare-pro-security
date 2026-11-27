<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Security\SecretVault;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AiAgentBehaviorEvaluator
 *
 * 2026–2027 Browser Integrity & Behavioral AI-Agent Evaluator.
 * Scores incoming requests on high-signal browser integrity heuristics to distinguish
 * real interactive browser sessions from automated headless AI scrapers and HTTP agents.
 *
 * Evaluates:
 * 1. HTTPS Sec-Fetch-* Absence (+35 risk): Real browsers on HTTPS always send Sec-Fetch-Site/Mode/Dest.
 * 2. Sec-CH-UA vs User-Agent Contradiction (+40 risk): Mismatched platform/architecture/brand claims.
 * 3. Sub-250ms Form-Submit Velocity (+35 risk): Fast automated form submission without human typing latency.
 * 4. Zero-Asset Crawl Pattern (+25 risk): High-velocity HTML/API hits with zero static asset fetches.
 *
 * Invariant: If risk score >= 60, triggers an invisible WebCrypto PoW challenge (<150ms solve time).
 * NEVER hard-bans shared CGNAT IPs, verified customers, or active membership sessions.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Evaluators
 */
final readonly class AiAgentBehaviorEvaluator implements WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'ai-agent-behavior';
    }

    public function is_required(): bool {
        return false;
    }

    public function get_route_classes(): array {
        return [
            RouteClass::PublicGet,
            RouteClass::PublicMutation,
            RouteClass::Commerce,
            RouteClass::RestApi,
        ];
    }

    public function get_required_capabilities(): array {
        return [];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::DegradedLog;
    }

    /**
     * Stateless rules compilable into micro-waf-compiled.php.
     *
     * @return array<string, mixed>
     */
    public function compile_preload_ast(): array {
        return [
            'id'       => 'WAF-AI-AGENT-BEHAVIOR',
            'category' => 'AI Threat Defense',
            'evaluator' => self::class,
        ];
    }

    /**
     * Evaluate incoming request at plugins_loaded runtime.
     *
     * @param RequestContext $ctx
     * @return WafVerdict|null
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        $settings = SettingsManager::get_settings();

        // Check if stealth agent challenge or AI bot defense is active
        $challenge_stealth = !empty($settings['waf_ai_challenge_stealth_agents']) || !empty($settings['waf_block_ai_scrapers']);
        if (!$challenge_stealth) {
            return null;
        }

        // 1. Exemption: Authenticated administrators, editors, builders, and loopbacks
        if (
            FirewallEngine::is_authenticated_administrator() ||
            FirewallEngine::is_authenticated_editor_or_builder() ||
            ClientIpResolver::is_server_origin_or_loopback($ctx->ip)
        ) {
            return null;
        }

        // 1b. Exemption: Logged in WordPress users, active WooCommerce shoppers, and JSON/AJAX API requests
        if (self::is_exempt_session($ctx)) {
            return null;
        }

        // 1c. Exemption: Standard read-only public crawl metadata files (/robots.txt, /.well-known/security.txt)
        $req_path_early = strtolower((string) (wp_parse_url($ctx->uri, PHP_URL_PATH) ?: $ctx->uri));
        if (
            in_array($ctx->method, ['GET', 'HEAD'], true)
            && empty($ctx->queryParams)
            && in_array($req_path_early, ['/robots.txt', '/.well-known/security.txt'], true)
        ) {
            return null;
        }

        // 2. Exemption: Already solved WebCrypto PoW in current session
        $ua = $ctx->userAgent;
        if (class_exists(BotReconDefense::class)) {
            if (BotReconDefense::has_valid_clearance_cookie($ctx->ip, $ua)) {
                return null;
            }
        }

        // 3. Exemption: Genuine reverse-DNS verified search engine crawlers (Google, Bing, DuckDuckGo) or allowed citation bots
        if (class_exists(BotReconDefense::class)) {
            if (BotReconDefense::is_genuine_search_engine($ctx->ip, $ua)) {
                return null;
            }
            if (!empty($settings['waf_ai_allow_search_citations'])) {
                if (BotReconDefense::is_verified_ai_citation_bot($ctx->ip, $ua)) {
                    return null;
                }
            }
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\OfficialCrawlerRegistry')) {
            if (\WebCareProScanner\Firewall\OfficialCrawlerRegistry::get_verified_crawler_identity($ctx->ip, $ua) !== null) {
                return null;
            }
        }

        // 3b. Check Commercial / SEO Crawler Swarm Guard (PetalBot, Bytespider, Semrush, etc.)
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\SubnetSwarmGuard')) {
            $swarm_check = \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::inspect_crawler_swarm($ctx->ip, $ua, $settings);
            if ($swarm_check !== null) {
                if ($swarm_check['action'] === 'block') {
                    return new WafVerdict(
                        'block',
                        $swarm_check['rule_id'] ?? \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::BLOCK_RULE_ID,
                        $swarm_check['message'] ?? 'Commercial crawler blocked by policy.',
                        ['category' => 'Bot Recon Defense', 'status_code' => 403]
                    );
                }
                if ($swarm_check['action'] === 'throttle') {
                    return new WafVerdict(
                        'rate_limit',
                        $swarm_check['rule_id'] ?? \WebCareProScanner\Firewall\Core\SubnetSwarmGuard::THROTTLE_RULE_ID,
                        $swarm_check['message'] ?? 'Commercial crawler subnet swarm throttled.',
                        [
                            'category'    => 'Bot Recon Defense',
                            'status_code' => 429,
                            'retry_after' => $swarm_check['retry_after'] ?? 120,
                        ]
                    );
                }
            }
        }
        $risk_score = 0;
        $signals = [];

        // Heuristic 1: HTTPS Sec-Fetch-* Absence (+35 risk)
        if (array_key_exists('HTTPS', $ctx->server)) {
            $is_https = !empty($ctx->server['HTTPS']) && strtolower((string) $ctx->server['HTTPS']) !== 'off';
        } else {
            $is_https = function_exists('is_ssl') && is_ssl();
        }

        $has_sec_fetch = isset($ctx->headers['sec-fetch-site']) || isset($ctx->headers['sec-fetch-mode']) || isset($ctx->headers['sec-fetch-dest'])
            || isset($ctx->server['HTTP_SEC_FETCH_SITE']) || isset($ctx->server['HTTP_SEC_FETCH_MODE']) || isset($ctx->server['HTTP_SEC_FETCH_DEST']);
        if ($is_https && !$has_sec_fetch && $ua !== '') {
            // Modern desktop & mobile browsers (Chrome, Edge, Safari, Firefox) support Fetch Metadata.
            // Exclude common iOS & Android in-app WebViews and declared non-JS crawlers (governed by BotReconDefense / SubnetSwarmGuard).
            $is_inapp_webview = preg_match('/\b(?:FBAN|FBAV|Instagram|BytedanceWebview|TikTok|Line\/|Snapchat|LinkedInApp|MicroMessenger|Pinterest)\b/i', $ua) === 1;
            $is_declared_crawler = preg_match('/\b(?:PetalBot|Bytespider|Sogou|YandexBot|Baiduspider|SemrushBot|AhrefsBot|DotBot|MJ12bot|BLEXBot|AdsBot-Google|Mediapartners-Google|Google-InspectionTool|GoogleOther|Applebot|BingPreview|facebookexternalhit|meta-externalagent|Twitterbot|LinkedInBot|Slackbot|WhatsApp)\b/i', $ua) === 1;

            $is_desktop_or_mobile_ua = (
                str_contains($ua, 'Mozilla/') &&
                (str_contains($ua, 'Chrome/') || str_contains($ua, 'Safari/') || str_contains($ua, 'Firefox/'))
            );

            if ($is_desktop_or_mobile_ua && !$is_inapp_webview && !$is_declared_crawler) {
                $risk_score += 35;
                $signals[] = 'missing_sec_fetch_on_https';
            }
        }

        // Heuristic 2: Sec-CH-UA vs User-Agent Contradiction (+40 risk)
        $sec_ch_ua = (string) ($ctx->headers['sec-ch-ua'] ?? ($ctx->server['HTTP_SEC_CH_UA'] ?? ''));
        $sec_ch_mobile = (string) ($ctx->headers['sec-ch-ua-mobile'] ?? ($ctx->server['HTTP_SEC_CH_UA_MOBILE'] ?? ''));
        $sec_ch_platform = strtolower((string) ($ctx->headers['sec-ch-ua-platform'] ?? ($ctx->server['HTTP_SEC_CH_UA_PLATFORM'] ?? '')));

        if ($sec_ch_ua !== '' && $ua !== '') {
            $ua_lower = strtolower($ua);
            // Mobile contradiction: Sec-CH-UA-Mobile says "?1" but UA says Windows/Macintosh/Linux
            if ($sec_ch_mobile === '?1' && (str_contains($ua_lower, 'windows') || str_contains($ua_lower, 'macintosh'))) {
                $risk_score += 40;
                $signals[] = 'sec_ch_mobile_mismatch';
            }
            // Platform contradiction: Sec-CH-UA-Platform says "Windows" but UA says iPhone/Android
            if (str_contains($sec_ch_platform, 'windows') && (str_contains($ua_lower, 'iphone') || str_contains($ua_lower, 'android'))) {
                $risk_score += 40;
                $signals[] = 'sec_ch_platform_mismatch';
            }
        }

        // Heuristic 2b: Impossible Future Browser Major Version (Signal +45 risk ONLY — never independent ban trigger)
        // Calendar-aware ceiling: accounts for ~15 Chromium milestones/year + Canary margin so current browsers never false-positive
        $max_plausible_chrome = 145 + max(0, ((int) gmdate('Y') - 2025) * 15) + 15;
        if ($ua !== '' && preg_match('/Chrome\/(\d+)\./i', $ua, $chrome_matches)) {
            $major_ver = (int) ($chrome_matches[1] ?? 0);
            if ($major_ver >= $max_plausible_chrome) {
                $risk_score += 45;
                $signals[] = 'impossible_browser_version_future';
            }
        }

        // Heuristic 2c: Hard-block raw HTTP clients probing PHP subsystems or non-existent webshell scripts
        if ($ua !== '' && preg_match('/^(?:Go-http-client|python-requests|python-urllib|python-httpx|curl|libwww-perl|Wget|aiohttp|httpx|Java\/|okhttp|fasthttp|zgrab|Nuclei)(?:\/|\s|$)/i', $ua)) {
            $req_path = strtolower((string) (wp_parse_url($ctx->uri, PHP_URL_PATH) ?: $ctx->uri));
            if (str_ends_with($req_path, '.php')) {
                $is_protected_wp_php = str_starts_with($req_path, '/wp-content/')
                    || str_starts_with($req_path, '/wp-includes/')
                    || (
                        str_starts_with($req_path, '/wp-admin/')
                        && !in_array($req_path, ['/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php'], true)
                    );

                $is_missing_webshell_probe = !$is_protected_wp_php
                    && !in_array($req_path, ['/index.php', '/wp-login.php', '/wp-cron.php', '/xmlrpc.php'], true)
                    && !str_contains($req_path, '..')
                    && defined('ABSPATH')
                    && !is_file(rtrim(ABSPATH, '/\\') . '/' . ltrim($req_path, '/'));

                if ($is_protected_wp_php || $is_missing_webshell_probe) {
                    $camp_meta = [];
                    if (class_exists('\\WebCareProScanner\\Firewall\\Core\\BehavioralCampaignEngine')) {
                        $camp_res = \WebCareProScanner\Firewall\Core\BehavioralCampaignEngine::record_probe($ctx->ip, 'webshell_probe', $req_path);
                        if (!empty($camp_res['escalate_ban'])) {
                            $camp_meta['cf_sync_state']   = $camp_res['cf_sync_state'] ?? null;
                            $camp_meta['cf_operation_id'] = $camp_res['cf_operation_id'] ?? null;
                        }
                    }
                    return new WafVerdict(
                        'block',
                        'WAF-RAW-CLIENT-PHP-PROBE',
                        'Direct scripted HTTP client reconnaissance against PHP subsystem forbidden.',
                        array_merge([
                            'category'      => 'Exploit Reconnaissance',
                            'status_code'   => 403,
                            'user_agent'    => $ua,
                            'path'          => $req_path,
                            'is_hard_block' => true,
                        ], $camp_meta)
                    );
                }
            }
        }

        // Heuristic 3: Sub-250ms Form-Submit Velocity (+35 risk)
        // Validates HMAC-signed webcare_render_ts (ts:sig) to verify genuine human elapsed submit time
        if ($ctx->method === 'POST') {
            $render_field = (string) ($ctx->formParams['webcare_render_ts'] ?? ($ctx->params['webcare_render_ts'] ?? ''));
            if ($render_field !== '') {
                $post_ts = self::verify_render_timestamp($render_field);
                if ($post_ts > 0.0) {
                    $elapsed_ms = (microtime(true) - $post_ts) * 1000;
                    if ($elapsed_ms > 0 && $elapsed_ms < 250.0) {
                        $risk_score += 35;
                        $signals[] = 'sub_250ms_form_velocity';
                    }
                }
            } else {
                // Automated bot POST without render timestamp.
                // Only soften weight (+15 instead of +25) when the request has BOTH a plausible browser UA
                // AND a Referer matching the site's configured canonical origin (never trusting client-supplied HTTP_HOST).
                $referer        = (string) ($ctx->headers['referer'] ?? ($ctx->server['HTTP_REFERER'] ?? ''));
                $referer_host   = $referer !== '' ? strtolower((string) parse_url($referer, PHP_URL_HOST)) : '';
                $canonical_url  = function_exists('home_url') ? (string) home_url() : '';
                $canonical_host = $canonical_url !== '' ? strtolower((string) parse_url($canonical_url, PHP_URL_HOST)) : '';

                $is_plausible_browser_ua = $ua !== ''
                    && str_contains($ua, 'Mozilla/')
                    && (str_contains($ua, 'Chrome/') || str_contains($ua, 'Safari/') || str_contains($ua, 'Firefox/') || str_contains($ua, 'OPR/') || str_contains($ua, 'Edg/'));

                $has_trusted_same_site_referer = $is_plausible_browser_ua
                    && $referer_host !== ''
                    && $canonical_host !== ''
                    && $referer_host === $canonical_host;

                $risk_score += $has_trusted_same_site_referer ? 15 : 25;
                $signals[] = 'missing_render_timestamp';
            }
        }

        // Heuristic 4: Zero-Asset Crawl Pattern (+25 risk)
        // High-frequency hits against PHP endpoints using fast APCu memory counter without hitting MySQL wp_options.
        // Threshold raised to > 30 hits/60s (or > 15 if missing Accept-Language) to avoid false positives on CDN/Cloudflare-cached static stores.
        $session_key = 'ai_hit_' . substr(hash('xxh128', $ctx->ip . ($ctx->userAgent ?: '')), 0, 16);
        $hits = self::increment_session_hits($session_key, 60);
        $has_accept_lang = !empty($ctx->headers['accept-language']) || !empty($ctx->server['HTTP_ACCEPT_LANGUAGE']);
        if ($hits > 30 || (!$has_accept_lang && $hits > 15)) {
            $risk_score += 25;
            $signals[] = 'zero_asset_high_velocity';
        }

        // Action Decision: If risk score >= 60, evaluate API-native 429 vs browser WebCrypto PoW
        if ($risk_score >= 60) {
            $can_translate = function_exists('did_action') && did_action('init');
            /* translators: %s: Comma-separated list of behavioral threat signals */
            $challenge_fmt = $can_translate
                /* translators: %s: Comma-separated list of behavioral threat signals */
                ? __('Browser integrity validation required (signals: %s).', 'webcare-pro-security')
                : 'Browser integrity validation required (signals: %s).';

            // Check if this is an API / REST / AJAX call or a declared non-JS crawler (which cannot solve WebCrypto PoW)
            $is_api_or_rest = str_contains($ctx->uri, '/wp-json/') || str_contains($ctx->uri, 'rest_route=') || (function_exists('wp_doing_ajax') && wp_doing_ajax());
            $is_non_js_crawler = $ua !== '' && preg_match('/\b(?:PetalBot|Bytespider|Sogou|YandexBot|Baiduspider|SemrushBot|AhrefsBot|DotBot|MJ12bot|BLEXBot)\b/i', $ua) === 1;
            if ($is_api_or_rest || $is_non_js_crawler) {
                // Return lightweight 429 rate limit verdict instead of rendering HTML PoW challenge
                return new WafVerdict(
                    'rate_limit',
                    $is_non_js_crawler ? 'WAF-CRAWLER-VELOCITY-THROTTLE' : 'WAF-AI-AGENT-API-RATELIMIT',
                    $is_non_js_crawler ? 'Automated crawler velocity throttled.' : 'Automated high-velocity API access pattern restricted.',
                    [
                        'category'    => 'AI Threat Defense',
                        'risk_score'  => $risk_score,
                        'signals'     => $signals,
                        'status_code' => 429,
                        'retry_after' => 120,
                    ]
                );
            }

            return WafVerdict::challenge(
                'WAF-AI-AGENT-STEPUP',
                sprintf(
                    /* translators: %s: Comma-separated behavioral signals */
                    $challenge_fmt,
                    implode(', ', $signals)
                ),
                [
                    'category'    => 'AI Threat Defense',
                    'risk_score'  => $risk_score,
                    'signals'     => $signals,
                    'status_code' => 403,
                ]
            );
        }

        return null;
    }

    /**
     * Check if request belongs to an authenticated user, verified shopper, or machine API/AJAX call.
     */
    private static function is_exempt_session(RequestContext $ctx): bool {
        // 1. Logged-in WordPress user
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return true;
        }

        // 2. Cookie check for logged-in user: Must validate cryptographic auth cookie to prevent forgery
        if (!empty($ctx->cookies)) {
            foreach ($ctx->cookies as $name => $val) {
                if (str_starts_with((string) $name, 'wordpress_logged_in_')) {
                    if (function_exists('wp_validate_auth_cookie')) {
                        $user_id = wp_validate_auth_cookie((string) $val, 'logged_in');
                        if (!empty($user_id)) {
                            return true;
                        }
                    }
                }
            }
        }

        // 3. Active WooCommerce or Membership shopper session
        if (class_exists(CommerceSessionGuard::class) && CommerceSessionGuard::has_active_shopper_session()) {
            return true;
        }

        // 4. AJAX or WooCommerce JSON endpoints (strictly validate wc-ajax against known WooCommerce actions or require valid WC session)
        $wc_ajax_act = !empty($ctx->queryParams['wc-ajax'])
            ? sanitize_key((string) $ctx->queryParams['wc-ajax'])
            : (!empty($ctx->formParams['wc-ajax']) ? sanitize_key((string) $ctx->formParams['wc-ajax']) : '');

        if ($wc_ajax_act !== '') {
            $allowed_wc_ajax = [
                'get_refreshed_fragments', 'apply_coupon', 'remove_coupon', 'update_shipping_method',
                'checkout', 'get_cart_totals', 'add_to_cart', 'remove_from_cart',
            ];
            if (in_array($wc_ajax_act, $allowed_wc_ajax, true) || (class_exists(CommerceSessionGuard::class) && CommerceSessionGuard::has_active_shopper_session())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify HMAC-signed render timestamp (ts:sig).
     *
     * @param string $field Raw field value in format "timestamp:signature".
     * @return float Verified timestamp or 0.0 on mismatch.
     */
    public static function verify_render_timestamp(string $field): float {
        if ($field === '' || !str_contains($field, ':')) {
            return 0.0;
        }

        $parts = explode(':', $field, 2);
        if (count($parts) !== 2) {
            return 0.0;
        }

        [$ts_str, $sig] = $parts;
        $ts = (float) $ts_str;
        if ($ts <= 0.0) {
            return 0.0;
        }

        $secret = class_exists(SecretVault::class)
            ? SecretVault::get_key()
            : (defined('AUTH_KEY') && AUTH_KEY !== '' ? AUTH_KEY : '');
        if ($secret === '') {
            return 0.0;
        }

        $expected = hash_hmac('sha256', "render_ts:{$ts_str}", $secret);
        if (!hash_equals($expected, $sig)) {
            return 0.0;
        }

        return $ts;
    }

    /**
     * Generate an HMAC-signed render timestamp string for hidden form inputs.
     *
     * @return string "timestamp:signature"
     */
    public static function generate_render_timestamp(): string {
        $now = (string) microtime(true);
        $secret = class_exists(SecretVault::class)
            ? SecretVault::get_key()
            : (defined('AUTH_KEY') && AUTH_KEY !== '' ? AUTH_KEY : '');
        $sig = $secret !== '' ? hash_hmac('sha256', "render_ts:{$now}", $secret) : '';
        return "{$now}:{$sig}";
    }

    /**
     * Memory-efficient session hit counter with cross-request durability.
     * Hierarchy:
     * 1. Fast APCu in-memory counter.
     * 2. Persistent WP Object Cache (Redis / Memcached via wp_cache_add / wp_cache_incr / wp_cache_set).
     * 3. Bounded transient fallback (never a PHP static array that resets across HTTP requests).
     *
     * @param string $key Cache key.
     * @param int $ttl Time to live in seconds.
     * @return int Current hit count.
     */
    private static function increment_session_hits(string $key, int $ttl = 60): int {
        // 1. Fast APCu in-memory counter
        if (function_exists('apcu_inc') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'))) {
            $success = false;
            $val = apcu_inc($key, 1, $success, $ttl);
            if ($success) {
                return (int) $val;
            }
            if (function_exists('apcu_store')) {
                apcu_store($key, 1, $ttl);
                return 1;
            }
        }

        // 2. Persistent External Object Cache (Redis / Memcached) if configured
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            if (function_exists('wp_cache_incr')) {
                $val = wp_cache_incr($key, 1, 'webcare_ai_sess');
                if ($val !== false) {
                    return (int) $val;
                }
            }
            $val = function_exists('wp_cache_get') ? wp_cache_get($key, 'webcare_ai_sess') : false;
            $count = ($val !== false) ? ((int) $val + 1) : 1;
            if (function_exists('wp_cache_set')) {
                wp_cache_set($key, $count, 'webcare_ai_sess', $ttl);
            }
            return $count;
        }

        // 3. Durable bounded transient fallback (cross-request tracking)
        $transient_key = 'wc_ai_h_' . substr(hash('xxh128', $key), 0, 16);
        $val = get_transient($transient_key);
        $count = ($val !== false && is_numeric($val)) ? ((int) $val + 1) : 1;
        set_transient($transient_key, $count, $ttl);
        return $count;
    }
}
