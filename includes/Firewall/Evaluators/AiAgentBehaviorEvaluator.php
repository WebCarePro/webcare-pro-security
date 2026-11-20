<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
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

        // 2. Exemption: Already solved WebCrypto PoW in current session
        $ua = $ctx->userAgent;
        if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            if (\WebCareProScanner\Firewall\BotReconDefense::has_valid_clearance_cookie($ctx->ip, $ua)) {
                return null;
            }
        }

        // 3. Exemption: Verified search engine crawlers (Google, Bing, DuckDuckGo) or allowed citation bots
        if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            $ua_lower = strtolower($ua);
            if (\WebCareProScanner\Firewall\BotReconDefense::detect_claimed_search_bot($ua_lower) !== null) {
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
        $is_https = (
            (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
            || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
        );

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
        // Checks public POST forms where WebCare hidden timestamp token or WooCommerce checkout is submitted faster than humanly possible
        if ($ctx->method === 'POST') {
            $post_ts = isset($_POST['webcare_render_ts']) ? (float) $_POST['webcare_render_ts'] : 0.0;
            if ($post_ts > 0.0) {
                $elapsed_ms = (microtime(true) - $post_ts) * 1000;
                if ($elapsed_ms > 0 && $elapsed_ms < 250.0) {
                    $risk_score += 35;
                    $signals[] = 'sub_250ms_form_velocity';
                }
            }
        }

        // Heuristic 4: Zero-Asset Crawl Pattern (+25 risk)
        // High-frequency hits against PHP endpoints without any CSS/JS/image asset requests from the same session
        $session_key = 'webcare_sess_hits_' . md5($ctx->ip . ($ctx->userAgent ?: ''));
        $hits = (int) get_transient($session_key);
        set_transient($session_key, $hits + 1, 60);
        if ($hits > 15 && empty($_COOKIE['wordpress_logged_in_'])) {
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
}
