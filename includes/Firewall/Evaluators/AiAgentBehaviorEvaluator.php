<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Core\SecretVault;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\FirewallEngine;
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

        // 2. Exemption: Already solved WebCrypto PoW in current session
        $ua = $ctx->userAgent;
        if (class_exists(BotReconDefense::class)) {
            if (BotReconDefense::has_valid_clearance_cookie($ctx->ip, $ua)) {
                return null;
            }
        }

        // 3. Exemption: Genuine reverse-DNS verified search engine crawlers (Google, Bing, DuckDuckGo) or allowed citation bots
        if (class_exists(BotReconDefense::class)) {
            $ua_lower = strtolower($ua);
            if (BotReconDefense::is_genuine_search_engine($ctx->ip, $ua)) {
                return null;
            }
            if (!empty($settings['waf_ai_allow_search_citations'])) {
                $citation_bots = ['oai-searchbot', 'perplexitybot', 'claude-searchbot'];
                foreach ($citation_bots as $cit_bot) {
                    if (str_contains($ua_lower, $cit_bot)) {
                        return null;
                    }
                }
            }
        }

        // Calculate heuristic risk score
        $risk_score = 0;
        $signals = [];

        // Heuristic 1: HTTPS Sec-Fetch-* Absence (+35 risk)
        $is_https = function_exists('is_ssl') ? is_ssl() : (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off');

        $has_sec_fetch = isset($_SERVER['HTTP_SEC_FETCH_SITE']) || isset($_SERVER['HTTP_SEC_FETCH_MODE']) || isset($_SERVER['HTTP_SEC_FETCH_DEST']);
        if ($is_https && !$has_sec_fetch && $ua !== '') {
            // Modern desktop & mobile browsers (Chrome, Edge, Safari, Firefox) support Fetch Metadata
            $is_desktop_or_mobile_ua = (
                str_contains($ua, 'Mozilla/') &&
                (str_contains($ua, 'Chrome/') || str_contains($ua, 'Safari/') || str_contains($ua, 'Firefox/'))
            );

            if ($is_desktop_or_mobile_ua) {
                $risk_score += 35;
                $signals[] = 'missing_sec_fetch_on_https';
            }
        }

        // Heuristic 2: Sec-CH-UA vs User-Agent Contradiction (+40 risk)
        $sec_ch_ua = isset($_SERVER['HTTP_SEC_CH_UA']) ? (string) wp_unslash($_SERVER['HTTP_SEC_CH_UA']) : '';
        $sec_ch_mobile = isset($_SERVER['HTTP_SEC_CH_UA_MOBILE']) ? (string) wp_unslash($_SERVER['HTTP_SEC_CH_UA_MOBILE']) : '';
        $sec_ch_platform = isset($_SERVER['HTTP_SEC_CH_UA_PLATFORM']) ? strtolower((string) wp_unslash($_SERVER['HTTP_SEC_CH_UA_PLATFORM'])) : '';

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

        // Heuristic 3: Sub-250ms Form-Submit Velocity (+35 risk)
        // Validates HMAC-signed webcare_render_ts (ts:sig) to verify genuine human elapsed submit time
        if ($ctx->method === 'POST') {
            $render_field = isset($_POST['webcare_render_ts']) ? (string) wp_unslash($_POST['webcare_render_ts']) : '';
            $post_ts = self::verify_render_timestamp($render_field);
            if ($post_ts > 0.0) {
                $elapsed_ms = (microtime(true) - $post_ts) * 1000;
                if ($elapsed_ms > 0 && $elapsed_ms < 250.0) {
                    $risk_score += 35;
                    $signals[] = 'sub_250ms_form_velocity';
                }
            }
        }

        // Heuristic 4: Zero-Asset Crawl Pattern (+25 risk)
        // High-frequency hits against PHP endpoints using fast APCu memory counter without hitting MySQL wp_options
        $session_key = 'ai_hit_' . substr(hash('xxh128', $ctx->ip . ($ctx->userAgent ?: '')), 0, 16);
        $hits = self::increment_session_hits($session_key, 60);
        if ($hits > 15) {
            $risk_score += 25;
            $signals[] = 'zero_asset_high_velocity';
        }

        // Action Decision: If risk score >= 60, challenge legitimate browser with invisible WebCrypto PoW
        if ($risk_score >= 60) {
            return WafVerdict::challenge(
                'WAF-AI-AGENT-STEPUP',
                sprintf(
                    /* translators: %s: Comma-separated behavioral signals */
                    __('Browser integrity validation required (signals: %s).', 'webcare-pro-security'),
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

        // 2. Cookie check for logged-in user (WordPress appends COOKIEHASH to 'wordpress_logged_in_')
        if (!empty($_COOKIE)) {
            foreach ($_COOKIE as $name => $val) {
                if (str_starts_with((string) $name, 'wordpress_logged_in_')) {
                    return true;
                }
            }
        }

        // 3. Active WooCommerce or Membership shopper session
        if (class_exists(CommerceSessionGuard::class) && CommerceSessionGuard::has_active_shopper_session()) {
            return true;
        }

        // 4. AJAX or WooCommerce JSON endpoints (never return an HTML PoW challenge to JSON callers)
        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) {
            return true;
        }
        if (isset($_GET['wc-ajax']) || isset($_POST['wc-ajax'])) {
            return true;
        }
        if (str_contains($ctx->uri, '/wp-json/') || str_contains($ctx->uri, 'rest_route=')) {
            return true;
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
     * Memory-efficient session hit counter using APCu with local memory fallback (zero MySQL writes).
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

        // 2. External Object Cache (Redis / Memcached) if configured
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            $val = wp_cache_get($key, 'webcare_ai_sess');
            $count = $val !== false ? ((int) $val + 1) : 1;
            wp_cache_set($key, $count, 'webcare_ai_sess', $ttl);
            return $count;
        }

        // 3. Static in-memory execution cache fallback (avoids hitting wp_options)
        static $in_mem_counts = [];
        $in_mem_counts[$key] = ($in_mem_counts[$key] ?? 0) + 1;
        return $in_mem_counts[$key];
    }
}
