<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WafVaultManager
 *
 * High-performance, zero-SQL JSON storage engine for high-churn WAF statistics,
 * ghost trap catches, and daily log indexes. Operates under WP_CONTENT_DIR . '/webcare-waf/vault/'.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class WafVaultManager {

    private const VAULT_DIR_NAME = 'webcare-waf/vault';

    /**
     * Get the canonical path to the emergency safe mode marker.
     *
     * @return string
     */
    public static function get_safe_mode_marker_path(): string {
        $base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        return wp_normalize_path(rtrim($base, '/\\') . '/webcare-waf/.rescue_pause_until');
    }

    /**
     * Get the canonical path to the preload rescue allowlist file.
     *
     * @return string
     */
    public static function get_preload_allow_path(): string {
        $base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        return wp_normalize_path(rtrim($base, '/\\') . '/webcare-waf/.rescue_allow.json');
    }

    /**
     * Get the WAF vault directory path without mutating permissions or creating directories.
     *
     * @return string
     */
    public static function get_vault_dir_readonly(): string {
        $base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        return wp_normalize_path(rtrim($base, '/\\') . '/' . self::VAULT_DIR_NAME);
    }

    /**
     * Get and ensure the hardened WAF vault directory path.
     *
     * @return string
     */
    public static function get_vault_dir(): string {
        $base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        $dir  = wp_normalize_path(rtrim($base, '/\\') . '/' . self::VAULT_DIR_NAME);

        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
            @chmod($dir, 0750);
        } else {
            @chmod($dir, 0750);
        }

        self::ensure_vault_secured($dir);

        return $dir;
    }

    /**
     * Ensure .htaccess and index.php security guards exist in the vault directory.
     *
     * @param string $dir
     */
    private static function ensure_vault_secured(string $dir): void {
        if (!is_dir($dir) || !wp_is_writable($dir)) {
            return;
        }

        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $content = "# WebCare Pro Security - Protect Vault Artifacts\n"
                . "<IfModule mod_authz_core.c>\n"
                . "    Require all denied\n"
                . "</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n"
                . "    Deny from all\n"
                . "</IfModule>\n";
            @file_put_contents($htaccess, $content);
            @chmod($htaccess, 0600);
        }

        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
            @chmod($index, 0600);
        }
    }

    /**
     * Increment atomic lifetime and today blocked counters in vault/stats-summary.json.
     * Completely bypasses MySQL wp_options to prevent DB lockups during attack waves.
     *
     * @param int $increment
     * @return array{lifetime_blocked: int, today_blocked: int, updated_at: int}
     */
    public static function increment_blocked_counter(int $increment = 1): array {
        $dir  = self::get_vault_dir();
        $file = $dir . '/stats-summary.json';

        $today = gmdate('Y-m-d');
        $data  = [
            'lifetime_blocked' => 0,
            'today'            => $today,
            'today_blocked'    => 0,
            'updated_at'       => time(),
        ];

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Atomic file lock for high-concurrency WAF counter
        $fp = @fopen($file, 'c+');
        if ($fp && flock($fp, LOCK_EX)) {
            $size = (int) filesize($file);
            if ($size > 0) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
                $raw = fread($fp, $size);
                if (is_string($raw) && $raw !== '') {
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded)) {
                        $data['lifetime_blocked'] = (int) ($decoded['lifetime_blocked'] ?? 0);
                        if (($decoded['today'] ?? '') === $today) {
                            $data['today_blocked'] = (int) ($decoded['today_blocked'] ?? 0);
                        } else {
                            $data['today_blocked'] = 0;
                        }
                    }
                }
            } else {
                // Initialize from legacy wp_options on first vault creation if available
                $legacy_c = (int) get_option('webcareproscan_lifetime_blocked_counter', 0);
                if ($legacy_c > 0) {
                    $data['lifetime_blocked'] = $legacy_c;
                }
            }

            $data['lifetime_blocked'] += $increment;
            $data['today']            = $today;
            $data['today_blocked']    += $increment;
            $data['updated_at']       = time();

            ftruncate($fp, 0);
            rewind($fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($fp, (string) wp_json_encode($data, JSON_PRETTY_PRINT));
            fflush($fp);
            flock($fp, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
        } else {
            if ($fp) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
            }
        }

        return $data;
    }

    /**
     * Update daily index summary in vault/logs/daily-index.json for fast O(1) totals and metrics.
     *
     * @param array<string, mixed> $record
     */
    public static function update_daily_index(array $record): void {
        $dir = self::get_vault_dir() . '/logs';
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }

        $file = $dir . '/daily-index.json';
        $day  = gmdate('Y-m-d');

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file, 'c+');
        if ($fp && flock($fp, LOCK_EX)) {
            $index = [];
            $size  = (int) filesize($file);
            if ($size > 0) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
                $raw = fread($fp, $size);
                if (is_string($raw) && $raw !== '') {
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded)) {
                        $index = $decoded;
                    }
                }
            }

            if (!isset($index[$day])) {
                $index[$day] = [
                    'total'       => 0,
                    'blocked'     => 0,
                    'challenged'  => 0,
                    'detected'    => 0,
                    'categories'  => [],
                    'last_update' => time(),
                ];
            }

            $index[$day]['total']++;
            $action = sanitize_key((string) ($record['action_taken'] ?? ''));
            if ($action === 'blocked') {
                $index[$day]['blocked']++;
            } elseif ($action === 'challenge_pow' || $action === 'challenged') {
                $index[$day]['challenged']++;
            } else {
                $index[$day]['detected']++;
            }

            $cat = sanitize_key((string) ($record['rule_category'] ?? 'other'));
            if ($cat !== '') {
                $index[$day]['categories'][$cat] = ($index[$day]['categories'][$cat] ?? 0) + 1;
            }

            $index[$day]['last_update'] = time();

            // Prune index entries older than 60 days
            $cutoff = gmdate('Y-m-d', time() - (60 * 86400));
            foreach ($index as $dateKey => $entry) {
                if ($dateKey < $cutoff) {
                    unset($index[$dateKey]);
                }
            }

            ftruncate($fp, 0);
            rewind($fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($fp, (string) wp_json_encode($index, JSON_PRETTY_PRINT));
            fflush($fp);
            flock($fp, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
        } elseif ($fp) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
        }
    }

    /**
     * Retrieve daily index summary for a date or date range.
     *
     * @return array<string, mixed>
     */
    public static function get_daily_index(): array {
        $file = self::get_vault_dir() . '/logs/daily-index.json';
        if (!file_exists($file)) {
            return [];
        }
        $raw = @file_get_contents($file);
        if (!$raw) {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Read current stats summary from vault/stats-summary.json.
     *
     * @return array{lifetime_blocked: int, today: string, today_blocked: int, updated_at: int}
     */
    public static function get_stats_summary(): array {
        $dir  = self::get_vault_dir();
        $file = $dir . '/stats-summary.json';

        $today = gmdate('Y-m-d');
        $default = [
            'lifetime_blocked' => (int) get_option('webcareproscan_lifetime_blocked_counter', 0),
            'today'            => $today,
            'today_blocked'    => 0,
            'updated_at'       => time(),
        ];

        if (!file_exists($file)) {
            return $default;
        }

        $raw = @file_get_contents($file);
        if (!$raw) {
            return $default;
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return $default;
        }

        if (($data['today'] ?? '') !== $today) {
            $data['today_blocked'] = 0;
            $data['today']         = $today;
        }

        return [
            'lifetime_blocked' => (int) ($data['lifetime_blocked'] ?? $default['lifetime_blocked']),
            'today'            => (string) ($data['today'] ?? $today),
            'today_blocked'    => (int) ($data['today_blocked'] ?? 0),
            'updated_at'       => (int) ($data['updated_at'] ?? time()),
        ];
    }

    /**
     * Record a ghost-route canary trap hit to vault/ghost-catches.jsonl (append-only stream).
     * Replaces hot wp_options rewrites with bounded rotation at 2 MB and 0600 file permissions.
     *
     * @param array<string, mixed> $event
     * @return bool
     */
    public static function record_ghost_catch(array $event): bool {
        $dir  = self::get_vault_dir();
        $file = $dir . '/ghost-catches.jsonl';

        // Rotate at 2 MB to prevent unbounded disk growth
        if (file_exists($file) && (filesize($file) ?: 0) > 2097152) {
            $rot = $file . '.1';
            @unlink($rot);
            @rename($file, $rot);
            @chmod($rot, 0600);
        }

        $line = wp_json_encode($event) . "\n";
        // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_put_contents_file_put_contents
        $written = (bool) @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
        if ($written) {
            @chmod($file, 0600);
        }
        return $written;
    }

    /**
     * Retrieve recent ghost-trap catches from vault/ghost-catches.jsonl (reverse order).
     * Uses bounded tail-seeking (32 KB buffer) instead of loading the entire file into RAM via file().
     *
     * @param int $limit
     * @return array<int, array<string, mixed>>
     */
    public static function get_ghost_catches(int $limit = 100): array {
        $dir  = self::get_vault_dir();
        $file = $dir . '/ghost-catches.jsonl';

        if (!file_exists($file)) {
            // Fallback to legacy option if vault file does not exist yet
            $legacy = get_option('webcareproscan_ghost_trap_catches', []);
            return is_array($legacy) ? array_slice($legacy, 0, $limit) : [];
        }

        $fsize = filesize($file) ?: 0;
        if ($fsize <= 0) {
            return [];
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file, 'rb');
        if (!$fp) {
            return [];
        }

        // Read at most the last 32 KB to strictly eliminate OOM risks on active sites
        $chunk_size = min($fsize, 32768);
        fseek($fp, -$chunk_size, SEEK_END);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
        $buffer = fread($fp, $chunk_size);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);

        if (!is_string($buffer) || $buffer === '') {
            return [];
        }

        $lines = explode("\n", $buffer);
        // If we read a partial chunk from the middle of the file, drop the incomplete first line
        if ($chunk_size < $fsize) {
            array_shift($lines);
        }

        $catches = [];
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $line = trim($lines[$i]);
            if ($line === '' || $line[0] !== '{') {
                continue;
            }
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
                $catches[] = $decoded;
                if (count($catches) >= $limit) {
                    break;
                }
            }
        }

        return $catches;
    }
}
