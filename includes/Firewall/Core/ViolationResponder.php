<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ViolationResponder
 *
 * Terminal response engine handling rule violations, incident logging,
 * PoW clearance verification, and custom block page rendering.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ViolationResponder {

    /**
     * Generate a short, unambiguous Customer Support Reference Code (#WEBCARE-XXXX).
     */
    public static function generate_ref_code(): string {
        $charset = '23456789ABCDEFGHJKMNPQRSTVWXYZ';
        $max_idx = strlen($charset) - 1;
        $ref_code = 'WEBCARE-';
        for ($i = 0; $i < 4; $i++) {
            $ref_code .= $charset[wp_rand(0, $max_idx)];
        }
        return $ref_code;
    }

    /**
     * Log firewall incident to database or partitioned JSON storage
     */
    public static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        global $wpdb;
        $table = ($wpdb !== null && isset($wpdb->prefix)) ? $wpdb->prefix . 'webcareproscan_firewall_logs' : 'wp_webcareproscan_firewall_logs';

        $ip = FirewallEngine::get_client_ip();
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $uri = substr($raw_uri, 0, 500);

        $raw_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $method = substr($raw_method, 0, 10);

        $raw_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $user_agent = substr($raw_ua, 0, 300);

        // Red Team Synthetic Attack Drill: NEVER log synthetic simulation probes to persistent incident table
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            return null;
        }

        // Server Origin IP Safety: Never log server's own outbound IP as an offending attacker
        $server_ip = class_exists('\\WebCareProScanner\\System\\ServerInfo') ? \WebCareProScanner\System\ServerInfo::get_server_ip() : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '');
        if (!empty($server_ip) && $ip === $server_ip) {
            return null;
        }

        $raw_referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $referer = substr($raw_referer, 0, 500);

        if (empty($incident_id)) {
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        }
        FirewallEngine::$last_incident_id = $incident_id;

        if ($action === 'blocked' && empty($rule['ref_code'])) {
            $rule['ref_code'] = self::generate_ref_code();
        }
        if (!empty($rule['ref_code'])) {
            FirewallEngine::$last_ref_code = strtoupper(sanitize_text_field($rule['ref_code']));
        }

        // Determine HTTP Status Code
        $status_code = 403;
        if ($action === 'detected' || $action === 'bypassed' || $action === 'allowed' || $action === 'monitored') {
            $status_code = 200;
        } elseif (isset($rule['category']) && $rule['category'] === '404 Scanner Rate Limit') {
            $status_code = 404;
        } elseif (isset($rule['category']) && (stripos($rule['category'], 'method') !== false || stripos($rule['description'] ?? '', 'method') !== false)) {
            $status_code = 405;
        }
        $category = sanitize_key($rule['category'] ?? 'general_defense');

        // Delegate zero-SQL WAF incident logging to daily JSON filesystem partitioner
        $logged_id = WafFileLogger::log_incident($rule, $action, $incident_id);
        if ($logged_id === null) {
            return null;
        }
        $incident_id = $logged_id;

        // Dispatch DevSecOps Webhook on blocked attack
        if ($action === 'blocked' && class_exists('\\WebCareProScanner\\Notifications\\WebhookService')) {
            \WebCareProScanner\Notifications\WebhookService::send_waf_alert([
                'category'   => $rule['category'],
                'name'       => $rule['name'] ?? $rule['category'],
                'ip_address' => $ip,
                'incident_id'=> $incident_id,
            ]);
        }

        // Dispatch granular event notifications via NotificationDispatcher
        if ($action === 'blocked' && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            $is_virtual_patch = !empty($rule['is_virtual_patch']) || stripos($rule['category'] ?? '', 'Virtual Patch') !== false;
            if ($is_virtual_patch) {
                $can_translate = function_exists('did_action') && did_action('init');
                /* translators: 1: Attacker IP address, 2: Target rule name, 3: Incident ID */
                $patch_msg_fmt = $can_translate
                    ? __('Virtual Patch intercepted an exploit payload from %1$s targeting "%2$s" [Incident: %3$s].', 'webcare-pro-security')
                    : 'Virtual Patch intercepted an exploit payload from %1$s targeting "%2$s" [Incident: %3$s].';
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('waf_virtual_patch_hit', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: attacker IP address, 2: rule name or category, 3: incident ID */
                        $patch_msg_fmt,
                        $ip,
                        $rule['name'] ?? $rule['category'],
                        $incident_id
                    ),
                    'details'  => [
                        'attacker_ip' => $ip,
                        'incident_id' => $incident_id,
                        'rule_name'   => $rule['name'] ?? $rule['category'],
                        'category'    => $rule['category'],
                    ],
                ]);
            }
        }

        return $incident_id;
    }

    /**
     * Render branded 403 Forbidden Error Screen via standard wp_die()
     */
    public static function render_block_page(array $rule, string $client_ip, ?string $incident_id = null) {
        // Red Team Drill Intercept Handler
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WebCareProScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, 403);
            header('X-WebCare-Drill-Intercepted: 1');
            header('X-WebCare-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WebCare-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
            status_header(403);
            echo wp_json_encode([
                'success'     => false,
                'drill'       => true,
                'intercepted' => true,
                'rule_id'     => $rule['id'] ?? 'WAF-INTERCEPT',
                'category'    => $rule['category'] ?? 'WAF',
            ]);
            exit;
        }

        $settings   = class_exists(SettingsManager::class) ? SettingsManager::get_settings() : [];
        $is_warning = self::is_progressive_warning_rule($rule, $settings);
        $req_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');

        if (empty($incident_id)) {
            $incident_id = FirewallEngine::$last_incident_id ?: ('WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8)));
        }

        // Reuse ref_code already attached to log_incident() so WAF Logs and Support Code match 1:1
        $ref_code = !empty($rule['ref_code'])
            ? strtoupper(sanitize_text_field($rule['ref_code']))
            : (!empty(FirewallEngine::$last_ref_code) ? FirewallEngine::$last_ref_code : self::generate_ref_code());
        FirewallEngine::$last_ref_code = null;

        // Fast transient lookup for non-technical site owners to unblock paying customers in 1 click
        $transient_data = [
            'ref_code'      => $ref_code,
            'incident_id'   => $incident_id,
            'client_ip'     => $client_ip,
            'rule_id'       => $rule['id'] ?? 'WAF-BLOCK',
            'rule_name'     => $rule['name'] ?? ($rule['category'] ?? 'Security Shield'),
            'rule_category' => $rule['category'] ?? 'Security Shield',
            'description'   => $rule['description'] ?? 'Automated defense rule triggered.',
            'request_uri'   => substr(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/')), 0, 255),
            'timestamp'     => time(),
            'formatted_time'=> gmdate('Y-m-d H:i:s \U\T\C'),
        ];
        set_transient('webcareproscan_lockout_' . $ref_code, $transient_data, 2 * DAY_IN_SECONDS);
        if (!empty($incident_id) && $incident_id !== $ref_code) {
            set_transient('webcareproscan_lockout_' . $incident_id, $transient_data, 2 * DAY_IN_SECONDS);
        }
        // Also index by md5(IP) for instant customer unblocking via IP search
        set_transient('webcareproscan_lockout_ip_' . md5($client_ip), $transient_data, 2 * DAY_IN_SECONDS);

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        // Resolve Contact Support Destination (Configured URL or mailto fallback)
        $configured_contact = trim((string) ($settings['waf_contact_support_url'] ?? ''));
        if (!empty($configured_contact)) {
            $contact_url = str_starts_with($configured_contact, '/') ? site_url($configured_contact) : $configured_contact;
        } else {
            $admin_email = get_option('admin_email');
            if (!empty($admin_email)) {
                /* translators: 1: Site name, 2: Support reference code */
                $mail_subject = rawurlencode(sprintf('[%1$s] Security Checkpoint Ref: %2$s', get_bloginfo('name'), $ref_code));
                $mail_body    = rawurlencode(sprintf("Hello Support,\n\nI encountered an automated security checkpoint on your website.\nSupport Reference Code: %s\nIncident ID: %s\nClient IP: %s\nTime: %s UTC\n\nPlease verify and assist me with access.\n\nThank you.", $ref_code, $incident_id, $client_ip, gmdate('Y-m-d H:i:s')));
                $contact_url  = 'mailto:' . esc_attr($admin_email) . '?subject=' . $mail_subject . '&body=' . $mail_body;
            } else {
                $contact_url = home_url('/');
            }
        }

        // Safe translation wrapper that guards against premature _load_textdomain_just_in_time notices
        // when blocks execute during early plugins_loaded priority 0 before WordPress core fires 'init'.
        $can_translate = function_exists('did_action') && did_action('init');
        $t = static fn(string $text) => $can_translate ? esc_html__($text, 'webcare-pro-security') : $text;

        // 1. E-Commerce & Checkout AJAX handler (WooCommerce, SureCart, EDD)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Low-level firewall intercept inspects query parameters to determine structured JSON error formatting
        $is_wc_ajax = !empty($_GET['wc-ajax']) || !empty($_GET['wc-api']);
        if ($is_wc_ajax || (wp_doing_ajax() && FirewallEngine::is_commerce_or_membership_request($raw_uri))) {
            status_header(403);
            header('Content-Type: application/json; charset=utf-8');
            /* translators: 1: Security notice label, 2: Security explanation, 3: Support reference code label, 4: Support reference code */
            $ajax_msg = sprintf(
                '<div class="woocommerce-error" role="alert"><strong>%1$s</strong> %2$s<br/><span style="font-size:12px;opacity:0.9;">%3$s <strong>%4$s</strong></span>%5$s</div>',
                $is_warning ? $t('Security Warning:') : $t('Security Notice:'),
                $is_warning
                    ? $t('Unusual activity detected. If you continue sending repeated invalid requests, your session may be temporarily held.')
                    : $t('Your connection was temporarily held to protect this site.'),
                $t('Customer Support Reference Code:'),
                esc_html($ref_code),
                !empty($contact_url) ? sprintf('<br/><a href="%s" target="_blank" style="display:inline-block;margin-top:6px;font-weight:700;text-decoration:underline;">%s &rarr;</a>', esc_url($contact_url), $t('Contact Store Support')) : ''
            );
            echo wp_json_encode([
                'result'        => 'failure',
                'messages'      => $ajax_msg,
                'reload'        => false,
                'refresh'       => false,
                'incident_id'   => $incident_id,
                'ref_code'      => $ref_code,
                'is_warning'    => $is_warning,
                'contact_url'   => $contact_url,
                'error'         => $is_warning
                    ? $t('Security warning active. Continued unauthorized attempts will result in an IP ban.')
                    : $t('Security checkpoint active. Please quote reference code to support.'),
            ]);
            exit;
        }

        // 2. Generic REST API structured JSON error (detect via constant or request URI before rest_api_loaded)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Early firewall block page rendering before authentication/nonce setup.
        $has_rest_route_param = isset($_GET['rest_route']) && !empty($_GET['rest_route']);
        $is_rest_call = (defined('REST_REQUEST') && REST_REQUEST)
            || (strpos($raw_uri, '/wp-json/') !== false)
            || $has_rest_route_param
            || (strpos($raw_uri, 'rest_route=') !== false);

        if ($is_rest_call) {
            status_header(403);
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'code'          => $is_warning ? 'webcareproscan_warning_checkpoint' : 'webcareproscan_access_denied',
                'message'       => $is_warning
                    ? $t('Security Warning: Unusual activity detected. Continued unauthorized requests will result in an automated IP lockout.')
                    : $t('Your connection was temporarily held to protect this website against automated abusive traffic or invalid requests.'),
                'data'          => [
                    'status'      => 403,
                    'is_warning'  => $is_warning,
                    'incident_id' => $incident_id,
                    'ref_code'    => $ref_code,
                    'rule_id'     => $rule['id'] ?? 'WAF-BLOCK',
                    'category'    => $rule['category'] ?? 'Security Shield',
                    'contact_url' => $contact_url,
                ],
            ]);
            exit;
        }

        // Transparent WebCrypto PoW challenge before displaying amber warning screen on browser GET requests
        if ($is_warning) {
            $req_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
            if ($req_method === 'GET' && !wp_doing_ajax() && class_exists(BotReconDefense::class)) {
                $raw_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
                if (!BotReconDefense::has_valid_clearance_cookie($client_ip, $raw_ua)) {
                    // Challenge legitimate browser with invisible WebCrypto PoW (<150ms solve time)
                    BotReconDefense::render_webcrypto_challenge($client_ip, $raw_ua);
                    exit;
                }
            }
        }

        $strike_info = $rule['strike_info'] ?? ($is_warning ? \WebCareProScanner\Firewall\Core\TransientRateLimiter::get_warning_strike($client_ip, 4) : ['strike' => 0, 'max_strikes' => 4, 'is_terminal_ban' => false, 'remaining_strikes' => 4]);
        $strike_current = $strike_info['strike'];
        $strike_max     = $strike_info['max_strikes'];
        $strike_remain  = $strike_info['remaining_strikes'];

        $site_name   = get_bloginfo('name');
        $rule_cat    = esc_html($rule['category'] ?? 'Security Shield');

        // Color and visual theme attributes
        $badge_icon  = $is_warning ? '⚠️' : '🛡️';
        $badge_bg    = $is_warning ? '#fef3c7' : '#fee2e2';
        $badge_border= $is_warning ? '1px solid #fde68a' : '1px solid #fecaca';
        $title_color = $is_warning ? '#92400e' : '#0f172a';
        $card_accent = $is_warning ? 'border-top: 4px solid #f59e0b;' : 'border-top: 4px solid #dc2626;';
        $ref_border  = $is_warning ? '#f59e0b' : '#3b82f6';
        $ref_color   = $is_warning ? '#b45309' : '#1e40af';
        $btn_bg      = $is_warning ? '#d97706' : '#4f46e5';

        $headline = $is_warning
            ? $t('Security Notice: Action Warning')
            : $t('Protected by WebCare Pro Security');

        /* translators: %s: Site name */
        $subheadline = sprintf($can_translate ? esc_html__('Automated safety checkpoint on %s', 'webcare-pro-security') : 'Automated safety checkpoint on %s', esc_html($site_name));

        $primary_desc = $is_warning
            ? $t('Unusual activity was detected from your connection. If you continue sending repeated invalid requests, your IP address will be temporarily banned.')
            : $t('Your connection was temporarily held to protect this website against automated abusive traffic or repeated invalid requests.');

        $appeal_text = $is_warning
            ? $t('Are you a legitimate visitor or customer experiencing an issue? You can reach out directly with this code and we will resolve it immediately.')
            : $t('Are you a legitimate customer having trouble checking out or logging in? Share this code with the site owner or support team to restore access in 1 click.');

        // Strike counter indicator for progressive warnings
        $strike_html = '';
        if ($is_warning) {
            $pct = intval(($strike_current / max(1, $strike_max)) * 100);
            $strike_html = sprintf(
                '<div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 12px 16px; margin: 16px 0;">' .
                '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; font-size:12px; font-weight:700; color:#b45309;">' .
                '<span>%1$s %2$d / %3$d</span>' .
                '<span>%4$d %5$s</span>' .
                '</div>' .
                '<div style="width:100%; height:6px; background:#fef3c7; border-radius:3px; overflow:hidden;">' .
                '<div style="width:%6$d%%; height:100%%; background:#f59e0b; border-radius:3px;"></div>' .
                '</div>' .
                '</div>',
                $t('Security Warning Level:'),
                $strike_current,
                $strike_max,
                $strike_remain,
                $t('attempt(s) remaining before temporary 15-min pause'),
                $pct
            );
        }

        $message = sprintf(
            '<div style="font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Oxygen-Sans, Ubuntu, Cantarell, \"Helvetica Neue\", sans-serif; max-width: 620px; margin: 40px auto; line-height: 1.6; color: #1e293b; background: #ffffff; padding: 36px; border-radius: 14px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.06), 0 8px 10px -6px rgba(0,0,0,0.04); border: 1px solid #e2e8f0; %1$s">' .
            '<div style="display: flex; align-items: center; margin-bottom: 20px;">' .
            '<div style="width: 44px; height: 44px; border-radius: 10px; background: %2$s; border: %3$s; display: flex; align-items: center; justify-content: center; font-size: 22px; margin-right: 14px; text-align: center; line-height: 44px;">%4$s</div>' .
            '<div>' .
            '<h2 style="color: %5$s; margin: 0; font-size: 21px; font-weight: 700;">%6$s</h2>' .
            '<p style="margin: 3px 0 0; color: #64748b; font-size: 13px;">%7$s</p>' .
            '</div>' .
            '</div>' .
            '%8$s' .
            '<p style="font-size: 14px; color: #334155; margin-bottom: 20px;">%9$s</p>' .
            '<div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid %10$s; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">' .
            '<p style="margin: 0 0 6px; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; color: #64748b;">%11$s</p>' .
            '<div style="display: flex; align-items: baseline; gap: 10px;">' .
            '<span style="font-family: SFMono-Regular, Consolas, monospace; font-size: 24px; font-weight: 800; color: %12$s; letter-spacing: 1px;">%13$s</span>' .
            '<span style="font-size: 12px; color: #64748b;">(%14$s)</span>' .
            '</div>' .
            '<p style="margin: 8px 0 0; font-size: 12px; color: #475569;">%15$s</p>' .
            '</div>' .
            '<div style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 12px 16px; border-radius: 8px; margin: 18px 0; font-size: 12px; color: #475569;">' .
            '<p style="margin: 3px 0;"><strong>%16$s:</strong> <code>%17$s</code></p>' .
            '<p style="margin: 3px 0;"><strong>%18$s:</strong> <code>%19$s</code></p>' .
            '<p style="margin: 3px 0;"><strong>%20$s:</strong> <span>%21$s</span></p>' .
            '<p style="margin: 3px 0;"><strong>%22$s:</strong> <span>%23$s</span></p>' .
            '</div>' .
            '<div style="margin-top: 24px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;">' .
            '<a href="%24$s" style="display: inline-flex; align-items: center; justify-content: center; gap: 8px; background: %25$s; color: #ffffff; padding: 11px 22px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13.5px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">' .
            '<span>📩</span> %26$s' .
            '</a>' .
            '<a href="%27$s" style="display: inline-flex; align-items: center; justify-content: center; gap: 6px; background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; padding: 11px 18px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 13px;">' .
            '<span>🏠</span> %28$s' .
            '</a>' .
            '</div>' .
            '<p style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 24px;">%29$s</p>' .
            '</div>',
            $card_accent,
            $badge_bg,
            $badge_border,
            $badge_icon,
            $title_color,
            $headline,
            $subheadline,
            $strike_html,
            $primary_desc,
            $ref_border,
            $t('Customer Support Reference Code'),
            $ref_color,
            esc_html($ref_code),
            $t('Quote to Support'),
            $appeal_text,
            $t('Incident ID'),
            esc_html($incident_id),
            $t('Client IP'),
            esc_html($client_ip),
            $t('Defense Category'),
            $rule_cat,
            $t('Timestamp'),
            esc_html(gmdate('Y-m-d H:i:s \U\T\C')),
            esc_url($contact_url),
            $btn_bg,
            $t('Contact Site Support'),
            esc_url(home_url('/')),
            $t('Return to Home'),
            $t('WebCare Pro Security Suite • Zero-Trust Perimeter Defense')
        );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        wp_die($message, $t('403 Forbidden - Security Shield Block'), [
            'response'  => 403,
            'code'      => 'webcareproscan_access_denied',
            'back_link' => false,
        ]);

        return false;
    }

    /**
     * Determine whether a rule is eligible for the progressive warning and PoW clearance flow.
     * Critical exploit categories, confirmed-exploit catalog signatures, admin custom rules,
     * and explicit hard blocks must NEVER be eligible for progressive warning or PoW clearance,
     * even if caller-supplied metadata flags is_warning.
     *
     * @param array $rule
     * @param array $settings
     * @return bool
     */
    public static function is_progressive_warning_rule(array $rule, array $settings): bool {
        // Master toggle check: If progressive warnings are globally disabled in settings, no rule qualifies
        if (empty($settings['waf_enable_progressive_warnings'])) {
            return false;
        }

        // Absolute invariants: Hard blocks and custom admin blocks never qualify
        if (!empty($rule['is_hard_block'])) {
            return false;
        }

        $category      = (string) ($rule['category'] ?? '');
        $rule_id       = (string) ($rule['id'] ?? '');
        $rule_id_upper = strtoupper($rule_id);

        // Critical and exploit categories are strictly excluded under all circumstances
        $critical_categories = [
            'SQL Injection',
            'PHP Code Injection',
            'Path Traversal',
            'Cross-Site Scripting (XSS)',
            'Execution Armor',
            'XML Injection',
            'AI & Agent Defense',
            'Virtual Patch',
            'Next-Gen SQL RASP Defense',
            'Next-Gen Response DLP',
            'Modern API & GraphQL Shield',
            'AI Agent Kill-Chain Defense',
            'Forbidden Default Admin Usernames Shield',
            'Affiliate Defense',
            'File Reconnaissance',
            'Protocol Defense',
            'Server-Side Request Forgery (SSRF)',
            'Arbitrary File Upload',
            'Credential Defense',
            'Authentication Defense',
        ];

        if (in_array($category, $critical_categories, true)) {
            return false;
        }

        // Dedicated exploit, injection, or probe prefix exclusions
        if (str_starts_with($rule_id_upper, 'MOD-CUSTOM-')
            || str_starts_with($rule_id_upper, 'WAF-SQL-RASP-')
            || str_starts_with($rule_id_upper, 'WAF-DLP-')
            || str_starts_with($rule_id_upper, 'WAF-GRAPHQL-')
            || str_starts_with($rule_id_upper, 'WAF-AFFILIATE-')
            || str_starts_with($rule_id_upper, 'WAF-SENSITIVE-')
            || str_starts_with($rule_id_upper, 'WAF-XMLRPC-')
            || str_starts_with($rule_id_upper, 'WAF-SSRF-')
            || $rule_id_upper === 'WAF-AI-AGENT-KILLCHAIN'
        ) {
            return false;
        }

        // Confirmed exploit signatures and admin policies can never be downgraded to warnings
        if (FirewallEngine::get_confirmed_exploit_definition($rule_id_upper) !== null) {
            return false;
        }

        if (FirewallEngine::get_verified_admin_custom_rule($rule) !== null) {
            return false;
        }

        $tier = self::get_rule_enforcement_tier($rule);
        if ($tier === FirewallEngine::TIER_CONFIRMED_EXPLOIT || $tier === FirewallEngine::TIER_ADMIN_POLICY) {
            return false;
        }

        // STRICT FAIL-CLOSED ALLOW-LIST:
        // Only explicitly designated soft rate-limit, bot-recon, or warning rules may qualify.

        // Allow-list Condition A: Explicitly flagged warning rules that passed all security exclusions
        if (!empty($rule['is_warning'])) {
            return true;
        }

        // Allow-list Condition B: Dedicated soft rate-limit, bot-recon, or empty-UA rule IDs
        if (str_starts_with($rule_id_upper, 'RATE-LIMIT-')
            || str_starts_with($rule_id_upper, 'BOT-')
            || $rule_id_upper === 'WAF-EMPTY-USER-AGENT'
        ) {
            return true;
        }

        // Allow-list Condition C: Dedicated soft operational categories
        $soft_warning_categories = [
            '404 Scanner Rate Limit',
            'Rate Limiting',
            'Traffic Velocity',
        ];
        if (in_array($category, $soft_warning_categories, true)) {
            return true;
        }

        // Fail-closed default: general exploit, access-control, or unrecognized rules NEVER qualify
        return false;
    }

    /**
     * Determine whether an incoming request qualifies for progressive warning / PoW clearance,
     * and whether the visitor holds a valid clearance cookie or solution header to bypass the block.
     *
     * @param array $rule
     * @param array $settings
     * @param string $client_ip
     * @return bool True if the request is cleared to proceed.
     */
    public static function is_cleared_by_pow(array $rule, array $settings, string $client_ip): bool {
        if (empty($settings['waf_enable_progressive_warnings']) || wp_doing_ajax() || !class_exists(BotReconDefense::class)) {
            return false;
        }

        if (!self::is_progressive_warning_rule($rule, $settings)) {
            return false;
        }

        $raw_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        return BotReconDefense::has_valid_clearance_cookie($client_ip, $raw_ua)
            || BotReconDefense::verify_and_clear_pow_header($client_ip, $raw_ua);
    }

    public static function get_rule_enforcement_tier(array $rule): string {
        $rule_id_str = strtoupper((string) ($rule['id'] ?? ''));
        $rule_cat    = (string) ($rule['category'] ?? '');

        // 1. Immutable Heuristic Priority: Heuristic detections ALWAYS resolve to TIER_HEURISTIC.
        // No metadata, property, or supplied field can ever override this boundary.
        $is_heuristic = in_array($rule_cat, [
            'Cross-Site Scripting (XSS)',
            'AI & Agent Defense',
            'AI Agent Kill-Chain Defense',
            'Behavioral Defense',
            'Bot Recon Defense',
            '404 Scanner Rate Limit',
            'Form Spam Defense',
            'Login Rate Limit',
            'Protocol Defense',
            'Security Policy',
            'File Reconnaissance',
        ], true)
        || str_starts_with($rule_id_str, 'XSS-')
        || str_starts_with($rule_id_str, 'AI-')
        || str_starts_with($rule_id_str, 'BEHAVIOR-')
        || str_starts_with($rule_id_str, 'BOT-')
        || str_starts_with($rule_id_str, 'RATE-')
        || str_starts_with($rule_id_str, 'SCANNER-404');

        if ($is_heuristic) {
            return FirewallEngine::TIER_HEURISTIC;
        }

        // 2. Authoritative Administrator-Authored Custom Rule Provenance:
        // Must match a registered record in the trusted database repository.
        // Ban eligibility is authoritatively derived from the STORED record, NOT incoming array metadata.
        $stored_custom_rule = FirewallEngine::get_verified_admin_custom_rule($rule);
        if ($stored_custom_rule !== null) {
            $stored_ban_ttl = max(0, (int) ($stored_custom_rule['ban_ttl'] ?? 0));
            if ($stored_ban_ttl > 0) {
                return FirewallEngine::TIER_ADMIN_POLICY;
            }
        }

        // 3. Authoritative Confirmed Exploit Signature Registry:
        // Must match an authentic, registered exploit signature in the trusted internal registry.
        // Rejects unverified caller-supplied categories, fabricated IDs, or substring claims.
        if (FirewallEngine::is_registered_confirmed_exploit_rule($rule_id_str, $rule)) {
            return FirewallEngine::TIER_CONFIRMED_EXPLOIT;
        }

        // 4. Fail-Safe Default: All unclassified or ambiguous rules default to heuristic (no automated IP ban)
        return FirewallEngine::TIER_HEURISTIC;
    }

    /**
     * Handle firewall rule violation with mode sensitivity (learning vs blocking).
     *
     * @param array  $rule
     * @param array  $settings
     * @param string $client_ip
     * @param int    $status_code
     * @return void
     */
    public static function handle_rule_violation(array $rule, array $settings, string $client_ip, int $status_code = 403): void {
        $rule_id_str = strtoupper((string) ($rule['id'] ?? ''));

        // 1. Authoritative Rule Binding: Immediately resolve the canonical exploit definition or verified administrator rule
        // at the absolute entry of violation handling before evaluating any exemptions, warnings, or bypass paths.
        // Operates strictly on verified internal catalogs/DB, overriding any caller-supplied preliminary metadata.
        $stored_custom_rule = FirewallEngine::get_verified_admin_custom_rule($rule);
        if ($stored_custom_rule !== null) {
            $rule = array_merge($rule, $stored_custom_rule);
        } else {
            $canonical_exploit = FirewallEngine::get_confirmed_exploit_definition($rule_id_str);
            if ($canonical_exploit !== null) {
                $rule = array_merge($rule, $canonical_exploit);
            }
        }

        // Authoritative enforcement tier resolution (governed by get_rule_enforcement_tier)
        // Must be resolved before progressive warning / PoW clearance and IP whitelist evaluation to prevent
        // caller-supplied definitions or preliminary metadata from bypassing exploit classification.
        $tier = self::get_rule_enforcement_tier($rule);

        // Critical Exploit Categories & Explicit Custom Rules
        $critical_exploit_categories = [
            'SQL Injection',
            'PHP Code Injection',
            'Path Traversal',
            'Cross-Site Scripting (XSS)',
            'Execution Armor',
            'XML Injection',
            'AI & Agent Defense',
            'Virtual Patch',
            'Next-Gen SQL RASP Defense',
            'Next-Gen Response DLP',
            'Modern API & GraphQL Shield',
            'AI Agent Kill-Chain Defense',
        ];
        $rule_id_check = (string) ($rule['id'] ?? '');
        $rule_cat      = (string) ($rule['category'] ?? '');
        $is_critical_exploit = ($tier === FirewallEngine::TIER_CONFIRMED_EXPLOIT)
            || in_array($rule_cat, $critical_exploit_categories, true)
            || strpos($rule_id_check, 'MOD-CUSTOM-') === 0
            || strpos($rule_id_check, 'WAF-SQL-RASP-') === 0
            || strpos($rule_id_check, 'WAF-DLP-') === 0
            || strpos($rule_id_check, 'WAF-GRAPHQL-') === 0
            || $rule_id_check === 'WAF-AI-AGENT-KILLCHAIN';

        // Per-Detector Scoped Customer Trust Suppression (v3.23.2)
        // Check if an exact scoped customer exemption exists (route + method + role + canonical param_key).
        // Authoritative Security Invariant: Confirmed exploits (TIER_CONFIRMED_EXPLOIT or $is_critical_exploit)
        // can NEVER be suppressed by customer trust, under any circumstance.
        if (
            !$is_critical_exploit
            && $tier !== FirewallEngine::TIER_CONFIRMED_EXPLOIT
            && class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')
        ) {
            $req_uri_raw = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash((string) $_SERVER['REQUEST_URI'])) : '';
            $clean_uri   = str_replace(["\0", "\r", "\n"], '', $req_uri_raw);
            $clean_path  = (string) wp_parse_url($clean_uri, PHP_URL_PATH);
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $ajax_act    = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $rest_route  = isset($_GET['rest_route']) ? sanitize_text_field(wp_unslash($_GET['rest_route'])) : '';
            $req_method  = isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash((string) $_SERVER['REQUEST_METHOD'])) : 'GET';
            // Canonical parameter key resolution: strictly target the parameter key name, never raw payload values
            $param_key   = (string) ($rule['param_key'] ?? ($rule['target_param'] ?? ''));
            $user_role   = '';
            if (function_exists('wp_get_current_user')) {
                $u = wp_get_current_user();
                if ($u && !empty($u->roles)) {
                    $user_role = (string) reset($u->roles);
                }
            }

            if (\WebCareProScanner\Firewall\RescueAssistantManager::is_rule_or_request_trusted(
                $rule_id_str,
                $clean_path ?: $clean_uri,
                $ajax_act,
                $rest_route,
                $req_method,
                $user_role,
                $param_key
            )) {
                $bypass_rule = $rule;
                $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . ' [Suppressed via Scoped Customer Trust Exemption]';
                self::log_incident($bypass_rule, 'bypassed');
                return;
            }
        }

        // Honor ModularFirewallSynthesizer runtime exempt rule IDs (WCP-14)
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            $modular_exempt_ids = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_runtime_exempt_rule_ids();
            $cand_id = strtoupper((string) ($rule['id'] ?? ''));
            $is_exemptible_rule = (bool) preg_match('/^(?:MOD-(?:AJAX|REST|CVE|CUSTOM|UPLOAD|EGRESS)-[A-Z0-9_\-]+|BOT-[A-Z0-9_\-]+|RATE-[A-Z0-9_\-]+)$/', $cand_id);
            if ($is_exemptible_rule && !empty($modular_exempt_ids) && in_array($cand_id, $modular_exempt_ids, true)) {
                return;
            }
        }

        // Red Team Drill Intercept Handler
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WebCareProScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, $status_code);
            header('X-WebCare-Drill-Intercepted: 1');
            header('X-WebCare-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WebCare-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
            status_header($status_code);
            echo wp_json_encode([
                'success'     => false,
                'drill'       => true,
                'intercepted' => true,
                'rule_id'     => $rule['id'] ?? 'WAF-INTERCEPT',
                'category'    => $rule['category'] ?? 'WAF',
                'status_code' => $status_code,
            ]);
            exit;
        }

        // Defense-in-depth: Verified authenticated administrators operating strictly within WebCare Pro's own REST API
        // (where REST nonces are cryptographically validated) must proceed unimpeded for file inspection, diffing, and settings.
        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $clean_uri = str_replace(["\0", "\r", "\n"], '', $req_uri);
        $norm_rest_route = FirewallEngine::resolve_normalized_rest_route($clean_uri);
        $is_admin_session = FirewallEngine::is_authenticated_administrator();
        $is_admin_context = $is_admin_session && str_starts_with($norm_rest_route, '/webcare-pro-security/v1/');
        if ($is_admin_context) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry) {
                $bypass_rule = $rule;
                $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . ' [Bypassed via Authenticated Administrator Session]';
                self::log_incident($bypass_rule, 'bypassed');
            }
            return;
        }

        // Tiered Context-Aware & Rule-Scoped IP Whitelist Interceptor
        $whitelist_ctx = AllowlistManager::check_ip_whitelist_context($client_ip, $settings, $rule);
        if ($whitelist_ctx['is_whitelisted']) {
            $is_admin = $whitelist_ctx['is_admin'];
            $full_bypass = $whitelist_ctx['full_bypass'];
            $rule_bypass = !empty($whitelist_ctx['rule_bypass']);

            // Pre-authenticated / unauthenticated traffic must NEVER bypass confirmed exploits or critical categories.
            // Authenticated administrator sessions are the ONLY traffic that may bypass critical exploits via IP allowlist.
            $can_bypass = AllowlistManager::can_ip_whitelist_bypass_rule($is_admin, $full_bypass, $rule_bypass, $is_critical_exploit);

            if ($can_bypass) {
                // Log incident telemetry as 'bypassed' if telemetry logging is enabled
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    $bypass_rule = $rule;
                    if ($is_admin) {
                        $bypass_context = 'Authenticated Administrator Session';
                    } elseif ($rule_bypass) {
                        $bypass_context = 'Rule-Scoped Allowlist Exemption';
                    } else {
                        $bypass_context = 'Pre-Auth Whitelisted IP';
                    }
                    $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . " [Bypassed via {$bypass_context}]";
                    self::log_incident($bypass_rule, 'bypassed');
                }
                return; // Traffic allowed without dropping connection
            }
        }

        // Common clearance-aware decision point: If the authoritatively resolved rule qualifies
        // for progressive warning and visitor holds a valid PoW clearance cookie, allow the request to proceed immediately.
        // Bypasses ahead of learning mode observations, incident logging, threat score accumulation, and surge alerts.
        if (self::is_cleared_by_pow($rule, $settings, $client_ip)) {
            return;
        }

        $mode = $settings['waf_mode'] ?? 'enabled';

        // Check Synthesized Exemptions (CAF Phase 3): 1-Click safe-passes generated via Learning Mode
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\LearningModeEngine')) {
            $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
            $r_id = (string) ($rule['id'] ?? '');
            if (\WebCareProScanner\Firewall\CAF\LearningModeEngine::is_request_exempted($req_uri, $r_id)) {
                $bypass_rule = $rule;
                $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . ' [Bypassed via Synthesized Exemption]';
                self::log_incident($bypass_rule, 'bypassed');
                return; // Granted targeted safe-pass!
            }

            // If in learning mode or CAF adaptive learning mode active: record observation
            if ($mode === 'learning' || !empty($settings['caf_adaptive_learning_mode'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive observation recording of incoming request payload
                \WebCareProScanner\Firewall\CAF\LearningModeEngine::record_observation($rule, $client_ip, $req_uri, array_merge((array)($_GET ?? []), (array)($_POST ?? [])));
            }
        }

        if ($mode === 'learning') {
            if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine') && \WebCareProScanner\Firewall\LearningModeEngine::is_route_graduated()) {
                // Route has graduated: enforce blocking even during global learning mode!
            } else {
                if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                    \WebCareProScanner\Firewall\LearningModeEngine::record_threat_encountered(\WebCareProScanner\Firewall\LearningModeEngine::get_current_route_key());
                }
                self::log_incident($rule, 'detected');
                return;
            }
        } elseif ($mode === 'enabled') {
            // Check if specific route was explicitly forced into learning mode by admin
            if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                $route_key = \WebCareProScanner\Firewall\LearningModeEngine::get_current_route_key();
                $profiles = get_option(\WebCareProScanner\Firewall\LearningModeEngine::OPTION_PROFILES, []);
                if (isset($profiles[$route_key]['forced_status']) && $profiles[$route_key]['forced_status'] === 'learning') {
                    \WebCareProScanner\Firewall\LearningModeEngine::record_threat_encountered($route_key);
                    self::log_incident($rule, 'detected');
                    return;
                }
            }
        }

        // Evaluate progressive warning status and record single warning strike strictly when applicable
        $is_warning = self::is_progressive_warning_rule($rule, $settings);
        if ($is_warning && !isset($rule['strike_info'])) {
            $rule['strike_info'] = \WebCareProScanner\Firewall\Core\TransientRateLimiter::record_warning_strike($client_ip, 4, 900);
        }

        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
        self::log_incident($rule, $is_warning ? 'warned' : 'blocked', $incident_id);

        // Record blocked probe for 60-second rolling velocity counter (OS-01)
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker')) {
            \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker::record_blocked_probe();
        }

        $rule_id_str = (string) ($rule['id'] ?? '');
        $rule_cat    = (string) ($rule['category'] ?? '');

        $eligible_for_ip_ban = false;
        $effective_ban_ttl   = 0;

        if ($tier === FirewallEngine::TIER_ADMIN_POLICY && $stored_custom_rule !== null) {
            // 1. Explicit administrator-configured ban: strictly read TTL from the STORED database record
            $stored_ban_ttl     = max(0, (int) ($stored_custom_rule['ban_ttl'] ?? 0));
            if ($stored_ban_ttl > 0) {
                $eligible_for_ip_ban = true;
                $effective_ban_ttl   = $stored_ban_ttl;
            }
        } elseif ($tier === FirewallEngine::TIER_CONFIRMED_EXPLOIT) {
            // 2. Confirmed high-severity exploit: eligible for automated IP containment ban
            $eligible_for_ip_ban = true;
            $rule_ban_ttl        = max(0, (int) ($rule['ban_ttl'] ?? 0));
            $effective_ban_ttl   = $rule_ban_ttl > 0 ? $rule_ban_ttl : 86400;
        } else {
            // 3. Heuristic detection: log and block individual request; zero automated IP bans
            $eligible_for_ip_ban = false;
        }

        // Cloudflare sync preference: automatically sync if globally enabled in settings (cloudflare_auto_sync_bans) or explicitly requested by rule
        $cf_auto_sync_active = !empty($settings['cloudflare_enabled']) && !empty($settings['cloudflare_auto_sync_bans']);
        $rule_sync_cf        = $eligible_for_ip_ban && ($cf_auto_sync_active || !empty($rule['sync_cloudflare']));

        // Critical safety invariant: An authenticated administrator's own IP address must NEVER be banned or added to waf_blocked_ips.
        if ($is_admin_session || (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options'))) {
            $eligible_for_ip_ban = false;
        }

        // Active shopper session & commerce protection: Never impose multi-hour/24h IP bans on verified customers or shared carrier CGNAT IPs
        $has_shopper_session = class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard')
            && (\WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()
                || \WebCareProScanner\Firewall\Core\CommerceSessionGuard::is_exempt_from_operational_ban());

        if ($has_shopper_session) {
            if ($tier !== FirewallEngine::TIER_CONFIRMED_EXPLOIT) {
                // Heuristic or behavioral anomaly: block single request only, zero IP ban
                $eligible_for_ip_ban = false;
            } else {
                // Confirmed exploit on shopper session: cap cooldown to max 15 minutes instead of 24h
                $effective_ban_ttl = min($effective_ban_ttl, 900);
            }
        }

        if ($eligible_for_ip_ban) {
            $ban_reason        = sprintf('[%s] %s', $rule_id_str ?: $rule_cat, $rule['description'] ?? 'Critical WAF exploit intercepted');
            BlocklistRepository::add_blocked_ip(
                $client_ip,
                $ban_reason,
                $effective_ban_ttl,
                $rule_id_str ?: 'WAF-CRITICAL',
                $rule['name'] ?? $rule_cat,
                $rule_cat,
                $incident_id,
                null,
                $rule_sync_cf
            );
        } elseif (!$has_shopper_session && class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            // Skip ThreatScoreTracker accumulation when genuine crawlers follow on-page links (?add-to-cart= or /wp-login.php) with GET/HEAD
            $req_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
            if ($rule_id_str === 'BOT-CRAWLER-MUTATION-BLOCKED' && in_array($req_method, ['GET', 'HEAD', 'OPTIONS'], true)) {
                // Return 403 block on the specific link without accumulating toward a 24h IP ban for genuine crawlers
            } else {
                $event_type = 'probe_404';
                if ($rule_id_str === 'WAF-RESTRICTED-UPLOAD-EXTENSION') {
                    $event_type = 'behavioral_anomaly';
                } elseif (str_contains($rule_id_str, 'HONEY') || str_contains($rule_id_str, 'SENSITIVE') || str_contains($rule_id_str, 'ENV') || str_contains($rule_id_str, 'GIT')) {
                    $event_type = 'honeypot';
                } elseif (str_contains($rule_id_str, 'DORMANT') || str_contains($rule_id_str, 'CAF')) {
                    $event_type = 'dormant_surface';
                } elseif (str_contains($rule_id_str, 'AUTH') || str_contains($rule_id_str, 'LOGIN') || str_contains($rule_id_str, 'XMLRPC')) {
                    $event_type = 'auth_fail';
                }
                \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, $event_type);
            }
        }

        // Surge detection: Check if blocked count in the last 60 seconds exceeds surge threshold (e.g. 15 blocks/min)
        $surge_key = 'webcareproscan_waf_block_surge_window';
        $blocks = (int) get_transient($surge_key) + 1;
        set_transient($surge_key, $blocks, 60);

        if ($blocks === 15 || ($blocks > 15 && $blocks % 25 === 0)) {
            $surge_alert_sent = get_transient('webcareproscan_waf_block_surge_alerted');
            if (!$surge_alert_sent && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                set_transient('webcareproscan_waf_block_surge_alerted', 1, 300); // Throttle alerts to once per 5 minutes
                $can_translate = function_exists('did_action') && did_action('init');
                /* translators: %1$d: Number of blocked attack requests in under 60 seconds */
                $surge_msg_fmt = $can_translate
                    ? __('WAF Lite intercepted an abnormal surge of blocked attacks (%1$d blocks in under 60 seconds).', 'webcare-pro-security')
                    : 'WAF Lite intercepted an abnormal surge of blocked attacks (%1$d blocks in under 60 seconds).';
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('waf_block_surge', [
                    'severity' => 'high',
                    /* translators: 1: number of blocks */
                    'message'  => sprintf($surge_msg_fmt, $blocks),
                    'details'  => [
                        'Blocks in Window' => $blocks,
                        'Latest Attacker'  => $client_ip,
                        'Triggering Rule'  => $rule['title'] ?? ($rule['id'] ?? 'WAF Rule'),
                        'Incident ID'      => $incident_id,
                    ],
                ]);
            }
        }

        if ($status_code !== 403) {
            status_header($status_code);
        }

        self::render_block_page($rule, $client_ip, $incident_id);
        exit;
    }
}
