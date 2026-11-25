<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Core\CanonicalRouteParser;
use WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer;
use WebCareProScanner\Firewall\Core\BlocklistRepository;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Behavioral Campaign Engine
 *
 * Evidence-based correlation of autonomous adversary recon campaigns across targets and vectors.
 *
 * Invariants:
 * 1. Target Normalization: Canonicalize paths via CanonicalRouteParser::normalize_path() before hashing.
 * 2. Strict 20-Target Bucket Cap: When reached, freeze new insertions and increment bucket_overflow_count (never silently evict earlier evidence).
 * 3. High-Confidence Detectors ONLY:
 *    - 'sensitive_file', 'backup_archive', 'uploads_php', 'webshell_probe', 'xmlrpc_probe', 'canary_trap', 'auth_honeypot'
 * 4. Conservative Escalation Policy:
 *    - Confirmed exploit: Immediate deterministic blocking.
 *    - >= 5 distinct high-confidence recon targets in 60s: Escalate to WAF-CAMPAIGN-AUTOBAN (24h local ban + fenced async CF queue).
 *    - 2 independent high-confidence vectors: Elevate campaign risk; require corroborating evidence (>= 3 total high-confidence probes or confirmed exploit/honeypot) before 24h auto-ban.
 *    - Single canary hit (GhostRouteTrap): Block request (403) and increase campaign risk; NEVER auto-ban 24h solely from one isolated canary hit.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Core
 */
final class BehavioralCampaignEngine {

    public const MAX_BUCKET_TARGETS = 20;
    public const CAMPAIGN_WINDOW_SECONDS = 60;
    public const RULE_ID_CAMPAIGN_AUTOBAN = 'WAF-CAMPAIGN-AUTOBAN';

    public const VALID_DETECTORS = [
        'sensitive_file',
        'backup_archive',
        'uploads_php',
        'webshell_probe',
        'xmlrpc_probe',
        'canary_trap',
        'auth_honeypot',
    ];

    /**
     * Record a high-confidence probe into the IP campaign bucket and evaluate escalation.
     *
     * @param string $ip Client IP
     * @param string $detector High-confidence detector name
     * @param string $target Raw target URI or probe descriptor
     * @return array{escalate_ban: bool, distinct_targets_count: int, vectors_count: int, overflow_count: int, rule_id?: string}
     */
    public static function record_probe(string $ip, string $detector, string $target): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'escalate_ban'           => false,
                'distinct_targets_count' => 0,
                'vectors_count'          => 0,
                'overflow_count'         => 0,
            ];
        }

        // Only high-confidence detectors qualify for campaign escalation
        if (!in_array($detector, self::VALID_DETECTORS, true)) {
            return [
                'escalate_ban'           => false,
                'distinct_targets_count' => 0,
                'vectors_count'          => 0,
                'overflow_count'         => 0,
            ];
        }

        // 1. Canonicalize target before hashing to collapse trivial slash/query variances
        $normalized_target = CanonicalRouteParser::normalize_path($target);
        $target_hash = hash('xxh128', $normalized_target);

        $transient_key = 'wcps_camp_' . substr(hash('xxh128', $ip), 0, 16);
        $bucket = self::load_bucket($transient_key);

        $now = time();
        if (empty($bucket['created_at']) || ($now - (int) $bucket['created_at']) > self::CAMPAIGN_WINDOW_SECONDS) {
            // Initialize fresh 60s campaign window
            $bucket = [
                'created_at'            => $now,
                'targets'               => [],
                'vectors'               => [],
                'total_probes'          => 0,
                'bucket_overflow_count' => 0,
                'ban_committed'         => false,
                'cf_sync_state'         => null,
                'cf_operation_id'       => null,
            ];
        }

        $bucket['total_probes'] = ((int) ($bucket['total_probes'] ?? 0)) + 1;

        // Record vector
        if (!in_array($detector, $bucket['vectors'], true)) {
            $bucket['vectors'][] = $detector;
        }

        // Record target with strict 20-target bucket cap
        if (!in_array($target_hash, $bucket['targets'], true)) {
            if (count($bucket['targets']) < self::MAX_BUCKET_TARGETS) {
                $bucket['targets'][] = $target_hash;
            } else {
                // Saturated: freeze insertions, do NOT evict, increment overflow
                $bucket['bucket_overflow_count'] = ((int) ($bucket['bucket_overflow_count'] ?? 0)) + 1;
            }
        }

        $distinct_targets_count = count($bucket['targets']) + (int) ($bucket['bucket_overflow_count'] ?? 0);
        $vectors_count          = count($bucket['vectors']);
        $overflow_count         = (int) ($bucket['bucket_overflow_count'] ?? 0);
        $total_probes           = (int) $bucket['total_probes'];

        // Escalation Policy:
        // Policy A: >= 5 distinct targets within 60s -> 24h local ban + CF queue
        // Policy B: >= 2 independent vectors AND (total probes >= 3 OR honeypot present) -> 24h local ban + CF queue
        $escalate = false;
        if ($distinct_targets_count >= 5) {
            $escalate = true;
        } elseif ($vectors_count >= 2 && ($total_probes >= 3 || in_array('auth_honeypot', $bucket['vectors'], true))) {
            $escalate = true;
        }

        // Invariant: Single canary hit (GhostRouteTrap) alone does NOT trigger auto-ban
        if ($distinct_targets_count === 1 && $vectors_count === 1 && $bucket['vectors'][0] === 'canary_trap') {
            $escalate = false;
        }

        $cf_sync_state   = isset($bucket['cf_sync_state']) ? (string) $bucket['cf_sync_state'] : null;
        $cf_operation_id = isset($bucket['cf_operation_id']) ? (string) $bucket['cf_operation_id'] : null;

        // Persist updated probe counters first
        self::save_bucket($transient_key, $bucket);

        // Transactional per-campaign atomic escalation lock: prevents concurrent double-commit/double-enqueue
        // while preserving retries if initial Cloudflare enqueue returned 'enqueue_failed'.
        if ($escalate && (empty($bucket['ban_committed']) || $cf_sync_state === 'enqueue_failed')) {
            $lock_option = 'wcps_camp_lock_' . substr(hash('xxh128', $ip), 0, 16);
            if (self::acquire_campaign_lock($lock_option)) {
                try {
                    // Double-checked reload inside mutex
                    $locked_bucket = self::load_bucket($transient_key);
                    if (!empty($locked_bucket)) {
                        $bucket = $locked_bucket;
                    }
                    $cf_sync_state   = isset($bucket['cf_sync_state']) ? (string) $bucket['cf_sync_state'] : null;
                    $cf_operation_id = isset($bucket['cf_operation_id']) ? (string) $bucket['cf_operation_id'] : null;

                    if (empty($bucket['ban_committed']) || $cf_sync_state === 'enqueue_failed') {
                        $commit_res = self::commit_campaign_autoban(
                            $ip,
                            sprintf('Automated reconnaissance campaign (%d targets, %d vectors)', $distinct_targets_count, $vectors_count)
                        );
                        if (!empty($commit_res['local_banned'])) {
                            $bucket['ban_committed'] = true;
                        }
                        $cf_sync_state             = $commit_res['cf_sync_state'];
                        $cf_operation_id           = $commit_res['cf_operation_id'];
                        $bucket['cf_sync_state']   = $cf_sync_state;
                        $bucket['cf_operation_id'] = $cf_operation_id;
                        self::save_bucket($transient_key, $bucket);
                    }
                } finally {
                    self::release_campaign_lock($lock_option);
                }
            }
        }

        return [
            'escalate_ban'           => $escalate,
            'distinct_targets_count' => $distinct_targets_count,
            'vectors_count'          => $vectors_count,
            'overflow_count'         => $overflow_count,
            'rule_id'                => $escalate ? self::RULE_ID_CAMPAIGN_AUTOBAN : null,
            'cf_sync_state'          => $cf_sync_state,
            'cf_operation_id'        => $cf_operation_id,
        ];
    }

    /**
     * Acquire an atomic per-campaign mutex lock using add_option() with 15s stale-lock recovery.
     */
    private static function acquire_campaign_lock(string $lock_option, int $ttl = 15): bool {
        $now = time();
        if (add_option($lock_option, $now, '', 'no')) {
            return true;
        }
        $existing = (int) get_option($lock_option, 0);
        if ($existing > 0 && ($now - $existing) > $ttl) {
            delete_option($lock_option);
            return add_option($lock_option, $now, '', 'no');
        }
        return false;
    }

    /**
     * Release the per-campaign mutex lock.
     */
    private static function release_campaign_lock(string $lock_option): void {
        delete_option($lock_option);
    }

    /**
     * Commit a 24-hour local ban and queue Cloudflare sync.
     *
     * Invariant: Never ban authenticated admins, whitelisted IPs, or active shoppers.
     *
     * @param string $ip
     * @param string $reason
     * @return array{local_banned: bool, cf_sync_state: string, cf_operation_id: ?string}
     */
    public static function commit_campaign_autoban(string $ip, string $reason): array {
        // Exemption checks: Admins, Whitelisted IPs, and Active Shoppers
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator()) {
            return ['local_banned' => false, 'cf_sync_state' => 'not_queued', 'cf_operation_id' => null];
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\AllowlistManager')) {
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            if (\WebCareProScanner\Firewall\Core\AllowlistManager::is_ip_whitelisted($ip, (string) ($settings['waf_whitelisted_ips'] ?? ''))) {
                return ['local_banned' => false, 'cf_sync_state' => 'not_queued', 'cf_operation_id' => null];
            }
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard')) {
            if (\WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session() || \WebCareProScanner\Firewall\Core\CommerceSessionGuard::is_exempt_from_operational_ban($ip)) {
                return ['local_banned' => false, 'cf_sync_state' => 'not_queued', 'cf_operation_id' => null];
            }
        }

        // Commit the local ban first without duplicate auto-queueing (sync_cloudflare: false)
        $local_banned = BlocklistRepository::block_ip($ip, $reason, 86400, false);
        if (!$local_banned) {
            // Local safety guards (admin, allowlist, shopper, Cloudflare edge) rejected the ban; do not queue CF ban
            return ['local_banned' => false, 'cf_sync_state' => 'not_queued', 'cf_operation_id' => null];
        }

        // Local ban succeeded: queue generation-fenced Cloudflare ban once and preserve operation result
        $cf_res = ['cf_sync_state' => 'disabled', 'operation_id' => null];
        if (class_exists(CloudflareIpListSynchronizer::class)) {
            $cf_res = CloudflareIpListSynchronizer::queue_ip_ban($ip, $reason, 86400);
        }

        return [
            'local_banned'    => true,
            'cf_sync_state'   => (string) ($cf_res['cf_sync_state'] ?? 'disabled'),
            'cf_operation_id' => !empty($cf_res['operation_id']) ? (string) $cf_res['operation_id'] : null,
        ];
    }

    /**
     * Load campaign bucket from transient/APCu.
     *
     * @param string $key
     * @return array<string, mixed>
     */
    private static function load_bucket(string $key): array {
        if (function_exists('apcu_fetch')) {
            $success = false;
            $res = apcu_fetch($key, $success);
            if ($success && is_array($res)) {
                return $res;
            }
        }

        $stored = get_transient($key);
        if (is_array($stored)) {
            return $stored;
        }

        return [];
    }

    /**
     * Save campaign bucket to transient/APCu.
     *
     * @param string $key
     * @param array<string, mixed> $bucket
     */
    private static function save_bucket(string $key, array $bucket): void {
        if (function_exists('apcu_store')) {
            apcu_store($key, $bucket, self::CAMPAIGN_WINDOW_SECONDS);
        }
        set_transient($key, $bucket, self::CAMPAIGN_WINDOW_SECONDS);
    }

    /**
     * Clear campaign bucket for testing.
     *
     * @param string $ip
     */
    public static function reset_bucket_for_testing(string $ip): void {
        $transient_key = 'wcps_camp_' . substr(hash('xxh128', $ip), 0, 16);
        if (function_exists('apcu_delete')) {
            @apcu_delete($transient_key);
        }
        delete_transient($transient_key);
    }
}
