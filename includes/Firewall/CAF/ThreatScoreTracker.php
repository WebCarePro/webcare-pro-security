<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\BotReconDefense;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ThreatScoreTracker (CAF Phase 3)
 *
 * Implements Differential 403/404 & Behavioral Probe Velocity Tracking with Exponential Decay:
 *
 * Mathematical Model:
 *   T_{IP}(t) = T_{IP}(t_{last}) * e^{-\lambda * (t - t_{last})} + \Delta S_{event}
 *   where \lambda = ln(2) / 900 \approx 0.0007701635 s^{-1} (15-minute half-life)
 *
 * Score Weights (\Delta S):
 *   - Honeypot / Sensitive File Probe (.env, .git, wp-config.php~): +25
 *   - Dormant Surface Hit (Inactive Plugin, Uninstalled REST, Unapproved Guest AJAX): +15
 *   - Auth Endpoint 403 / Credential Stuffing / XML-RPC: +10
 *   - Consecutive 404 Probes on .php / sensitive extensions: +4
 *   - Client-Hint / HTTP/2 Anomaly: +15
 *
 * Escalation Policy:
 *   - T < \theta_{PoW} (default: 40): Normal visitor traffic (no friction)
 *   - \theta_{PoW} <= T < 85: Stateless WebCrypto SHA-256 Proof-of-Work Challenge (k = 16 zero bits)
 *   - T >= 85: Temporary HTTP 429 Throttle (self-healing via decay) + PoW challenge
 *   - Threat-score events never authorize automated IP bans. Confirmed exploit containment is handled
 *     by FirewallEngine's private detector dispatch path.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class ThreatScoreTracker {

    public const OPTION_HIGH_RISK_IPS = 'webcareproscan_caf_high_risk_ips';
    public const TRANSIENT_PREFIX     = 'webcareproscan_tscore_';

    // Exponential Decay Parameters
    public const HALF_LIFE_SECONDS    = 900;       // 15 minutes
    public const DECAY_LAMBDA         = 0.0007701635; // ln(2) / 900

    // Threat Escalation Thresholds
    public const THRESHOLD_POW        = 40.0;      // \theta_{PoW}: Trigger WebCrypto challenge
    public const THRESHOLD_THROTTLE   = 85.0;      // Severe behavioral score: temporary throttle
    public const THRESHOLD_HARD_BAN   = self::THRESHOLD_THROTTLE; // Deprecated compatibility alias

    // Event Score Weights (\Delta S)
    public const WEIGHT_CRITICAL_EXPLOIT = 85.0; // Deprecated compatibility value; caller claims are demoted
    public const WEIGHT_HONEYPOT         = 25.0;
    public const WEIGHT_DORMANT_SURF     = 15.0;
    public const WEIGHT_AUTH_VIOLATE     = 10.0;
    public const WEIGHT_PROBE_404        = 4.0;
    public const WEIGHT_HEADER_ANOMALY   = 15.0;

    /**
     * Record a security event for an IP and compute decayed threat score.
     *
     * @param string $ip Offending Client IP
     * @param string $event_type Event category; legacy 'critical_exploit' claims are treated as behavioral anomalies
     * @param float|null $custom_weight Optional explicit weight
     * @param array|null $exploit_context Deprecated compatibility parameter; caller metadata never authorizes a ban
     * @return array Array containing ['score' => float, 'action' => 'allow'|'challenge'|'throttle', 'escalated' => bool]
     */
    public static function record_event(string $ip, string $event_type, ?float $custom_weight = null, ?array $exploit_context = null): array {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return ['score' => 0.0, 'action' => 'allow', 'escalated' => false];
        }

        // Never accumulate threat scores for whitelisted IPs, administrators, or active shoppers
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($ip)) {
            return ['score' => 0.0, 'action' => 'allow', 'escalated' => false];
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard') && \WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()) {
            return ['score' => 0.0, 'action' => 'allow', 'escalated' => false];
        }

        // Do not treat caller-supplied rule metadata as proof that a detector ran.
        // Confirmed exploit bans are authorized only by FirewallEngine's private detector dispatch path.
        if ($event_type === 'critical_exploit') {
            $event_type = 'behavioral_anomaly';
            $custom_weight = min(25.0, $custom_weight ?? self::WEIGHT_HONEYPOT);
        }

        // Determine score increment
        $delta = $custom_weight !== null ? $custom_weight : self::get_event_weight($event_type);

        $now = time();
        $state = self::get_ip_state($ip);

        $last_score = (float) ($state['score'] ?? 0.0);
        $last_time  = (int) ($state['time'] ?? $now);

        // Apply exponential decay: T_{IP}(t_{last}) * e^{-\lambda * \Delta t}
        $time_diff = max(0, $now - $last_time);
        $decayed_score = $last_score * exp(-self::DECAY_LAMBDA * $time_diff);

        // Add event weight and clamp between 0.0 and 100.0
        $new_score = round(min(100.0, max(0.0, $decayed_score + $delta)), 2);

        // Update state in transient / memory
        self::save_ip_state($ip, [
            'score'        => $new_score,
            'time'         => $now,
            'last_event'   => $event_type,
            'event_count'  => (int) ($state['event_count'] ?? 0) + 1,
        ]);

        // Determine Action & Escalation:
        // Threat scores cannot authorize automated IP bans; they only apply temporary throttling or PoW challenges.
        $action = 'allow';
        $escalated = false;

        if ($new_score >= self::THRESHOLD_THROTTLE) {
            $action = 'throttle';
            $escalated = true;
            self::mark_for_pow_challenge($ip);
        } elseif ($new_score >= self::THRESHOLD_POW) {
            $action = 'challenge';
            $escalated = true;
            self::mark_for_pow_challenge($ip);
        }

        return [
            'score'     => $new_score,
            'action'    => $action,
            'escalated' => $escalated,
            'delta'     => $delta,
        ];
    }

    /**
     * Get current decayed threat score for an IP without adding a new event.
     *
     * @param string $ip
     * @return float
     */
    public static function get_current_score(string $ip): float {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return 0.0;
        }

        // Whitelisted IPs and active shoppers always return 0.0 effective score
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($ip)) {
            return 0.0;
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard') && \WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()) {
            return 0.0;
        }

        $state = self::get_ip_state($ip);
        if (empty($state['score'])) {
            return 0.0;
        }

        $now = time();
        $time_diff = max(0, $now - (int) ($state['time'] ?? $now));
        $decayed = (float) $state['score'] * exp(-self::DECAY_LAMBDA * $time_diff);
        return round(max(0.0, $decayed), 2);
    }

    /**
     * Pre-flight check: evaluate client on early request entry.
     * If score >= 85, drops connection immediately.
     * If score >= 40, invokes WebCrypto PoW challenge.
     *
     * @param string $ip
     * @return void
     */
    public static function inspect_client_threat(string $ip): void {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return;
        }

        // 1. Respect IP Whitelist before evaluating score or issuing any block/challenge
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($ip)) {
            return;
        }

        // 2. Exempt logged-in administrators and active WooCommerce shoppers
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard') && \WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()) {
            return;
        }

        $score = self::get_current_score($ip);
        if ($score <= 0.0) {
            return;
        }

        // Tier 1: Severe threat (score >= 85) -> Temporary HTTP 429 Throttle (self-healing via decay)
        if ($score >= self::THRESHOLD_THROTTLE) {
            status_header(429);
            header('Retry-After: 60');
            header('Content-Type: text/plain; charset=utf-8');
            header('X-WebCare-Threat-Score: ' . $score);
            echo 'Too Many Requests: Behavioral threat score threshold exceeded. Please wait 60 seconds and try again.';
            exit;
        }

        // Tier 2: Suspicious probe velocity (40 <= score < 85) -> WebCrypto PoW Challenge
        if ($score >= self::THRESHOLD_POW) {
            if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                BotReconDefense::verify_or_challenge_client();
            }
        }
    }

    /**
     * Mark IP in the PoW enforcement registry.
     */
    private static function mark_for_pow_challenge(string $ip): void {
        $pow_ips = get_option('webcare_pow_enforced_ips', []);
        if (!is_array($pow_ips)) {
            $pow_ips = [];
        }

        if (!isset($pow_ips[$ip])) {
            $pow_ips[$ip] = [
                'ip'         => $ip,
                'marked_at'  => time(),
                'expires_at' => time() + 3600, // 1 hour PoW requirement
            ];
            update_option('webcare_pow_enforced_ips', $pow_ips, false);
        }
    }

    /**
     * Get event score weight based on classification.
     */
    private static function get_event_weight(string $event_type): float {
        return match ($event_type) {
            'critical_exploit' => self::WEIGHT_CRITICAL_EXPLOIT,
            'honeypot'         => self::WEIGHT_HONEYPOT,
            'dormant_surface'  => self::WEIGHT_DORMANT_SURF,
            'auth_fail'        => self::WEIGHT_AUTH_VIOLATE,
            'probe_404'        => self::WEIGHT_PROBE_404,
            'header_anomaly'   => self::WEIGHT_HEADER_ANOMALY,
            default            => 5.0,
        };
    }

    /**
     * Clear cached threat score state for a specific IP.
     *
     * @param string $ip
     * @return void
     */
    public static function reset_ip(string $ip): void {
        $key = self::TRANSIENT_PREFIX . substr(md5($ip), 0, 16);
        if (function_exists('apcu_delete') && ini_get('apc.enabled')) {
            apcu_delete($key);
        }
        delete_transient($key);
    }

    /**
     * Read IP state from memory (APCu) or transient storage.
     */
    private static function get_ip_state(string $ip): array {
        $key = self::TRANSIENT_PREFIX . substr(md5($ip), 0, 16);

        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            $res = apcu_fetch($key);
            if (is_array($res)) {
                return $res;
            }
        }

        $stored = get_transient($key);
        return is_array($stored) ? $stored : [];
    }

    /**
     * Save IP state to memory (APCu) or transient storage.
     */
    private static function save_ip_state(string $ip, array $state): void {
        $key = self::TRANSIENT_PREFIX . substr(md5($ip), 0, 16);
        $ttl = 7200; // 2 hours

        if (function_exists('apcu_store') && ini_get('apc.enabled')) {
            apcu_store($key, $state, $ttl);
        }

        set_transient($key, $state, $ttl);
    }

    /**
     * Get behavioral telemetry overview for administrative reporting.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $high_risk = get_option(self::OPTION_HIGH_RISK_IPS, []);
        $pow_ips   = get_option('webcare_pow_enforced_ips', []);

        $active_high_risk = [];
        $now = time();

        if (is_array($high_risk)) {
            foreach ($high_risk as $ip => $data) {
                if (($data['expires_at'] ?? 0) > $now) {
                    $active_high_risk[] = $data;
                }
            }
        }

        return [
            'high_risk_ips_count' => count($active_high_risk),
            'high_risk_ips'       => array_slice($active_high_risk, 0, 25),
            'pow_active_count'    => is_array($pow_ips) ? count($pow_ips) : 0,
            'threshold_pow'       => self::THRESHOLD_POW,
            'threshold_throttle'  => self::THRESHOLD_THROTTLE,
            'threshold_ban'       => self::THRESHOLD_THROTTLE,
            'half_life_seconds'   => self::HALF_LIFE_SECONDS,
        ];
    }
}
