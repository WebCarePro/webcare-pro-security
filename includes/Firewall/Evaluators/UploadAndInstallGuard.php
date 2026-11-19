<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * UploadAndInstallGuard
 *
 * Inspects uploaded files and prevents prohibited or malicious plugin installations.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class UploadAndInstallGuard {

    /**
     * Parse php.ini size strings into integer bytes.
     */
    public static function parse_ini_size_bytes(string $val): int {
        return FirewallEngine::parse_ini_size_bytes($val);
    }

    /**
     * Determine maximum upload limit in bytes.
     */
    public static function get_max_upload_limit_bytes(): int {
        return FirewallEngine::get_max_upload_limit_bytes();
    }

    /**
     * Inspect an uploaded file before moving to permanent storage.
     *
     * @param array<string, mixed> $file
     * @return array<string, mixed>
     */
    public static function inspect_uploaded_file(array $file, bool $log_and_ban = true): array {
        return FirewallEngine::inspect_uploaded_file($file, $log_and_ban);
    }

    /**
     * Prevent installation of prohibited administrative plugins.
     *
     * @param mixed $response
     * @param array<string, mixed> $hook_extra
     * @return mixed
     */
    public static function prevent_prohibited_plugin_install(mixed $response, array $hook_extra): mixed {
        return FirewallEngine::prevent_prohibited_plugin_install($response, $hook_extra);
    }

    /**
     * Inspect unpacked plugin source directory for webshells/prohibited signatures.
     *
     * @param mixed $source
     * @param mixed $remote_source
     * @param mixed $upgrader
     * @param array<string, mixed> $hook_extra
     * @return mixed
     */
    public static function inspect_unpacked_plugin_source(mixed $source, mixed $remote_source, mixed $upgrader, array $hook_extra = []): mixed {
        return FirewallEngine::inspect_unpacked_plugin_source($source, $remote_source, $upgrader, $hook_extra);
    }

    /**
     * Filter plugin information API queries to block installation of prohibited packages.
     *
     * @param mixed $res
     * @param string $action
     * @param mixed $args
     * @return mixed
     */
    public static function filter_prohibited_plugin_api(mixed $res, string $action, mixed $args): mixed {
        return FirewallEngine::filter_prohibited_plugin_api($res, $action, $args);
    }
}
