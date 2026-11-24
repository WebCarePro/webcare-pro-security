<?php
declare(strict_types=1);

namespace WebCareProScanner\Cli;

use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Security\EmergencyContainmentManager;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Modular WP-CLI controller for `wp webcare waf ...` administration commands.
 */
final class WafCliCommand {

    /**
     * Register WP-CLI `webcare waf` management subcommands.
     */
    public static function register(): void {
        if (!defined('WP_CLI') || !WP_CLI || !class_exists('\\WP_CLI')) {
            return;
        }

        \WP_CLI::add_command('webcare waf status', [self::class, 'cmd_status']);
        \WP_CLI::add_command('webcare waf rules', [self::class, 'cmd_rules']);
        \WP_CLI::add_command('webcare waf allowlist', [self::class, 'cmd_allowlist']);
        \WP_CLI::add_command('webcare waf unblock', [self::class, 'cmd_unblock']);
    }

    /**
     * Display current firewall, containment, preload, and telemetry summary.
     *
     * @param array<int, string> $args
     * @param array<string, mixed> $assoc_args
     */
    public static function cmd_status(array $args = [], array $assoc_args = []): void {
        $settings     = SettingsManager::get_settings();
        $pause_state  = RescueAssistantManager::get_pause_status();
        $today_stats  = WafFileLogger::get_log_stats('today');
        $manifest     = CompiledStackManifest::load();
        $preload_meta = get_option(MicroWafCompiler::OPTION_STATUS, []);
        $locked_ips   = BlocklistRepository::get_all_locked_ips();
        $custom_rules = ModularFirewallSynthesizer::get_active_rules();

        $summary = [
            'waf_enabled'         => !empty($settings['waf_enabled']),
            'strict_paused'       => !empty($pause_state['paused']),
            'containment_active'  => EmergencyContainmentManager::is_active(),
            'xmlrpc_disabled'     => !empty($settings['waf_disable_xmlrpc']),
            'virtual_patching'    => !empty($settings['waf_auto_enforce_virtual_patches']),
            'preload_active'      => is_array($preload_meta) && !empty($preload_meta['active']),
            'stack_compiled'      => !empty($manifest['routes']),
            'blocked_today'       => (int) ($today_stats['blocked_24h'] ?? 0),
            'locked_ip_count'     => count($locked_ips),
            'custom_rule_count'   => count($custom_rules),
        ];

        if (($assoc_args['format'] ?? '') === 'json') {
            \WP_CLI::line((string) wp_json_encode($summary, JSON_PRETTY_PRINT));
            return;
        }

        foreach ($summary as $key => $value) {
            \WP_CLI::line(sprintf('%-20s : %s', $key, is_bool($value) ? ($value ? 'enabled' : 'disabled') : (string) $value));
        }
    }

    /**
     * List active custom/modular firewall rules or toggle a specific rule ID.
     *
     * ## EXAMPLES
     *   wp webcare waf rules
     *   wp webcare waf rules enable rule_id
     *   wp webcare waf rules disable rule_id
     *
     * @param array<int, string> $args
     * @param array<string, mixed> $assoc_args
     */
    public static function cmd_rules(array $args = [], array $assoc_args = []): void {
        $action  = strtolower((string) ($args[0] ?? 'list'));
        $rule_id = sanitize_key((string) ($args[1] ?? ''));

        if (in_array($action, ['enable', 'disable', 'shadow'], true)) {
            if ($rule_id === '') {
                \WP_CLI::error('Usage: wp webcare waf rules <enable|disable|shadow> <rule_id>');
                return;
            }
            $res = ModularFirewallSynthesizer::toggle_rule($rule_id, $action);
            if (!empty($res['success'])) {
                \WP_CLI::success((string) ($res['message'] ?? sprintf('Rule %s updated to %s.', $rule_id, $action)));
            } else {
                \WP_CLI::error((string) ($res['message'] ?? sprintf('Unable to update rule %s.', $rule_id)));
            }
            return;
        }

        $rules = ModularFirewallSynthesizer::get_active_rules();
        if (($assoc_args['format'] ?? '') === 'json') {
            \WP_CLI::line((string) wp_json_encode($rules, JSON_PRETTY_PRINT));
            return;
        }

        if (empty($rules)) {
            \WP_CLI::line('No custom/modular WAF rules configured.');
            return;
        }

        foreach ($rules as $rule) {
            $id     = (string) ($rule['id'] ?? 'unknown');
            $mode   = (string) ($rule['mode'] ?? (!empty($rule['enabled']) ? 'active' : 'disabled'));
            $action_name = (string) ($rule['action'] ?? 'block');
            $title  = (string) ($rule['name'] ?? $rule['title'] ?? $id);
            \WP_CLI::line(sprintf('[%s] (%s/%s) %s', $id, $mode, $action_name, $title));
        }
    }

    /**
     * Manage the global trusted IP/CIDR allowlist (`list`, `add <ip>`, `remove <ip>`).
     *
     * @param array<int, string> $args
     * @param array<string, mixed> $assoc_args
     */
    public static function cmd_allowlist(array $args = [], array $assoc_args = []): void {
        $sub    = strtolower((string) ($args[0] ?? 'list'));
        $target = trim((string) ($args[1] ?? ''));

        $settings = SettingsManager::get_settings();
        $raw      = (string) ($settings['waf_whitelisted_ips'] ?? '');
        $entries  = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $raw) ?: [])));

        if ($sub === 'add') {
            if ($target === '' || !self::is_valid_ip_or_cidr($target)) {
                \WP_CLI::error('Provide a valid IPv4/IPv6 address or CIDR range to allowlist.');
                return;
            }
            if (!in_array($target, $entries, true)) {
                $entries[] = $target;
                SettingsManager::save_settings(['waf_whitelisted_ips' => implode("\n", $entries)]);
                \WP_CLI::success(sprintf('Added %s to WAF IP allowlist.', $target));
            } else {
                \WP_CLI::line(sprintf('%s is already allowlisted.', $target));
            }
            return;
        }

        if ($sub === 'remove') {
            if ($target === '') {
                \WP_CLI::error('Provide an IP or CIDR entry to remove from the allowlist.');
                return;
            }
            $filtered = array_values(array_filter($entries, static fn(string $item): bool => $item !== $target));
            if (count($filtered) === count($entries)) {
                \WP_CLI::warning(sprintf('%s was not present in the allowlist.', $target));
                return;
            }
            SettingsManager::save_settings(['waf_whitelisted_ips' => implode("\n", $filtered)]);
            \WP_CLI::success(sprintf('Removed %s from WAF IP allowlist.', $target));
            return;
        }

        if (($assoc_args['format'] ?? '') === 'json') {
            \WP_CLI::line((string) wp_json_encode($entries, JSON_PRETTY_PRINT));
            return;
        }

        if (empty($entries)) {
            \WP_CLI::line('WAF IP allowlist is empty.');
            return;
        }

        foreach ($entries as $entry) {
            \WP_CLI::line($entry);
        }
    }

    /**
     * Unblock a single IP/CIDR address or pass `--all` to clear temporary/permanent WAF IP locks.
     *
     * @param array<int, string> $args
     * @param array<string, mixed> $assoc_args
     */
    public static function cmd_unblock(array $args = [], array $assoc_args = []): void {
        if (!empty($assoc_args['all'])) {
            $res = BlocklistRepository::clear_all_blocked_ips();
            \WP_CLI::success(sprintf('Cleared %d blocked IP lock(s).', (int) ($res['cleared_count'] ?? 0)));
            return;
        }

        $ip = trim((string) ($args[0] ?? ''));
        if ($ip === '' || !self::is_valid_ip_or_cidr($ip)) {
            \WP_CLI::error('Usage: wp webcare waf unblock <ip|cidr> or wp webcare waf unblock --all');
            return;
        }

        $removed = BlocklistRepository::remove_blocked_ip($ip);
        if ($removed) {
            \WP_CLI::success(sprintf('Unblocked %s from active WAF locks.', $ip));
        } else {
            \WP_CLI::warning(sprintf('IP %s was not found in active local WAF blocklists.', $ip));
        }
    }

    /**
     * Validate an IPv4/IPv6 host or CIDR string strictly.
     */
    private static function is_valid_ip_or_cidr(string $candidate): bool {
        if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        if (str_contains($candidate, '/')) {
            $parts = explode('/', $candidate, 2);
            $ip    = $parts[0];
            $mask  = $parts[1];
            if (filter_var($ip, FILTER_VALIDATE_IP) === false || !ctype_digit($mask)) {
                return false;
            }
            $max_bits = str_contains($ip, ':') ? 128 : 32;
            $mask_int = (int) $mask;
            return $mask_int >= 0 && $mask_int <= $max_bits;
        }
        return false;
    }
}
