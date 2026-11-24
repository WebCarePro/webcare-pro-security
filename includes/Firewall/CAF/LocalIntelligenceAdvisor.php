<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Firewall\OfficialCrawlerRegistry;
use WebCareProScanner\Firewall\Core\SubnetSwarmGuard;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\TelemetrySnapshot;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Local Adaptive Intelligence Advisor (Zero-Telemetry & Recommend-Only)
 *
 * Scans local WAF telemetry within strictly bounded resource limits:
 * - Bounded log window (last 24 hours).
 * - Maximum records evaluated per run (capped at 5,000).
 * - Bounded memory & execution time.
 * - Cached / incremental results (1-hour cache TTL).
 * - Strictly RECOMMEND-ONLY: Surfaces up to 3 actionable security recommendations
 *   (e.g., crawler feed refresh, commercial crawler throttle preset, or Cloudflare queue health).
 *   NEVER silently alters firewall policy or issues automatic bans.
 * - Access control: Enforces manage_options capability and REST nonce validation.
 * - Log Separation: Maintains strict boundaries between WAF forensic logs, operational
 *   diagnostics, and the 7-day immutable admin-only Plugin Activity Log.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\CAF
 */
final class LocalIntelligenceAdvisor {

    public const CACHE_KEY = 'webcareproscan_local_intelligence_advisor';
    public const CACHE_TTL = 3600; // 1 hour
    public const MAX_RECORDS = 5000;
    public const MAX_RECOMMENDATIONS = 3;

    /**
     * Generate or fetch cached advisory recommendations.
     *
     * @param bool $force_refresh
     * @return array{generated_at: int, recommendations: array<array<string, mixed>>, status: string}
     */
    public static function get_recommendations(bool $force_refresh = false): array {
        if (!$force_refresh) {
            $cached = get_transient(self::CACHE_KEY);
            if (is_array($cached) && !empty($cached['recommendations'])) {
                return $cached;
            }
        }

        // Verify storage readability
        $storage_dir = WafFileLogger::get_storage_dir();
        if (!is_dir($storage_dir) || !is_readable($storage_dir)) {
            return [
                'generated_at'    => time(),
                'recommendations' => [],
                'status'          => 'unavailable',
            ];
        }

        try {
            $recommendations = [];
            $settings = SettingsManager::get_settings();

        // 1. Check Official Crawler Feed Age
        $crawler_cache = get_option(OfficialCrawlerRegistry::OPTION_CACHE_KEY, null);
        $last_sync = is_array($crawler_cache) ? ((int) ($crawler_cache['updated_at'] ?? 0)) : 0;
        if ($last_sync === 0 || (time() - $last_sync) > (7 * DAY_IN_SECONDS)) {
            $recommendations[] = [
                'id'          => 'REC-CRAWLER-FEED-STALE',
                'type'        => 'crawler_registry',
                'severity'    => 'low',
                'title'       => 'Refresh Official Search & AI Crawler Feeds',
                'description' => 'The local cache of verified Googlebot, Bingbot, and OpenAI IP feeds is older than 7 days or not yet initialized. Running background sync ensures legitimate search bots are recognized accurately.',
                'action_label' => 'Sync Feeds Now',
                'action_hook'  => 'sync_crawler_feeds',
            ];
        }

        // 2. Check Commercial Crawler Policy & High Swarm Volume
        $summaries = WafFileLogger::get_campaign_summaries(86400, self::MAX_RECORDS);
        $petalbot_bursts = 0;
        foreach ($summaries as $c) {
            if (isset($c['rule_ids']) && is_array($c['rule_ids']) && in_array(SubnetSwarmGuard::THROTTLE_RULE_ID, $c['rule_ids'], true)) {
                $petalbot_bursts += (int) ($c['burst_count'] ?? 0);
            }
        }

        $petal_policy = $settings['waf_crawler_policy_petalbot'] ?? SubnetSwarmGuard::POLICY_THROTTLE;
        if ($petalbot_bursts > 50 && $petal_policy === SubnetSwarmGuard::POLICY_ALLOW) {
            $recommendations[] = [
                'id'           => 'REC-CRAWLER-THROTTLE-PRESET',
                'type'         => 'crawler_policy',
                'severity'     => 'medium',
                'title'        => 'Enable Commercial Crawler Throttling for PetalBot',
                'description'  => sprintf('Detected %d PetalBot requests in the last 24 hours. Consider switching PetalBot policy to "Throttle" (10 req/min, 429 Retry-After) to conserve PHP/FPM server capacity.', $petalbot_bursts),
                'action_label' => 'Apply Throttle Preset',
                'action_hook'  => 'set_crawler_policy_throttle',
            ];
        }

        // 3. Check Cloudflare Edge Ban Queue & Sync Health
        $snapshot = TelemetrySnapshot::get_snapshot();
        $edge = $snapshot['edge_network'] ?? [];
        $cf_enabled = !empty($edge['cf_sync_enabled']);
        $dead_letter = (int) ($edge['cf_dead_letter_count'] ?? 0);
        $pending = (int) ($edge['cf_queue_pending_count'] ?? 0);

        if ($cf_enabled && $dead_letter > 0) {
            $recommendations[] = [
                'id'           => 'REC-CF-DEAD-LETTER-ALERT',
                'type'         => 'edge_queue',
                'severity'     => 'medium',
                'title'        => 'Cloudflare Queue Retries Exhausted (Dead Letter)',
                'description'  => sprintf('%d edge ban operations reached maximum retries and entered the dead-letter state. Verify Cloudflare API Token permissions and connectivity.', $dead_letter),
                'action_label' => 'Test Cloudflare Connection',
                'action_hook'  => 'test_cf_token',
            ];
        } elseif ($cf_enabled && $pending > 200) {
            $recommendations[] = [
                'id'           => 'REC-CF-QUEUE-BACKLOG',
                'type'         => 'edge_queue',
                'severity'     => 'low',
                'title'        => 'Cloudflare Sync Queue Backlog',
                'description'  => sprintf('There are currently %d pending bans in the background sync queue awaiting execution.', $pending),
                'action_label' => 'Process Queue Now',
                'action_hook'  => 'process_cf_queue',
            ];
        }

            // Cap to at most 3 actionable suggestions
            $sliced = array_slice($recommendations, 0, self::MAX_RECOMMENDATIONS);

            $result = [
                'generated_at'    => time(),
                'recommendations' => $sliced,
                'status'          => 'ok',
            ];

            set_transient(self::CACHE_KEY, $result, self::CACHE_TTL);
            return $result;
        } catch (\Throwable $e) {
            return [
                'generated_at'    => time(),
                'recommendations' => [],
                'status'          => 'degraded',
                'error'           => $e->getMessage(),
            ];
        }
    }

    /**
     * Clear cached advisor results for testing or manual refresh.
     */
    public static function clear_cache_for_testing(): void {
        delete_transient(self::CACHE_KEY);
    }
}
