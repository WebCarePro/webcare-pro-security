<?php
namespace WebCareProScanner\Auth;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SessionSentinel
 *
 * Protects administrator sessions against hijackings, cookie replay, and unauthorized concurrency.
 * Provides active session tracking, concurrent login alerts, IP lock, and instant one-click session revocation.
 */
class SessionSentinel {

    const VAULT_FOLDER = 'webcare-pro-security/auth-vault';
    const VAULT_FILE   = 'admin_session_history.vault.json';
    const RETENTION_PERIOD_SECONDS = 2592000; // 30 days (30 * 86400)

    private static $last_auth_token = '';
    public static string $pending_auth_type = '';
    public static string $pending_auth_label = '';
    public static array $pending_auth_details = [];

    /**
     * Get or create the hardened auth vault directory in uploads.
     */
    public static function get_vault_dir(): string {
        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['error']) || empty($upload_dir['basedir'])) {
            $err = !empty($upload_dir['error']) ? $upload_dir['error'] : 'Uploads directory unavailable.';
            throw new \RuntimeException(esc_html("Auth Vault requires a functional WordPress uploads directory: {$err}"));
        }
        $base = $upload_dir['basedir'];
        $vault_dir = wp_normalize_path(rtrim($base, '/\\') . '/' . self::VAULT_FOLDER);

        if (!is_dir($vault_dir)) {
            wp_mkdir_p($vault_dir);
        }

        $htaccess = rtrim($vault_dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "# WebCare Pro Security Auth Vault - Direct Access Prohibited\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n");
        }

        $index = rtrim($vault_dir, '/\\') . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }

        return $vault_dir;
    }

    /**
     * Read and decrypt all administrator session records from the vault JSON file.
     */
    public static function read_from_auth_vault(): array {
        try {
            $vault_dir = self::get_vault_dir();
            $vault_file = rtrim($vault_dir, '/\\') . '/' . self::VAULT_FILE;
            if (!file_exists($vault_file)) {
                return [];
            }

            $raw_content = @file_get_contents($vault_file);
            if (!$raw_content) {
                return [];
            }

            $container = json_decode($raw_content, true);
            if (!is_array($container) || empty($container['encrypted_payload'])) {
                return [];
            }

            // Verify HMAC signature if present
            if (!empty($container['hmac_sha256']) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                $key = \WebCareProScanner\Security\SecretVault::get_key();
                $expected_hmac = hash_hmac('sha256', (string) $container['encrypted_payload'], $key);
                if (!hash_equals($expected_hmac, (string) $container['hmac_sha256'])) {
                    // Tampered vault file detected - fail safe
                    return [];
                }
            }

            if (class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                $decrypted = \WebCareProScanner\Security\SecretVault::decrypt((string) $container['encrypted_payload']);
                if (is_string($decrypted) && !empty($decrypted)) {
                    $data = json_decode($decrypted, true);
                    return is_array($data) ? $data : [];
                }
            }
            return [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Synchronize administrator session metadata to the encrypted JSON vault file.
     */
    public static function sync_to_auth_vault(int $user_id, array $sessions_meta): void {
        try {
            if (!$user_id) {
                return;
            }

            $vault_dir = self::get_vault_dir();
            $vault_file = rtrim($vault_dir, '/\\') . '/' . self::VAULT_FILE;
            $lock_file  = $vault_file . '.lock';

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Atomic file lock for concurrent vault write protection.
            $lock_fp = @fopen($lock_file, 'c+');
            if (!$lock_fp) {
                return;
            }

            if (!@flock($lock_fp, LOCK_EX)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                @fclose($lock_fp);
                return;
            }

            try {
                $vault_data = self::read_from_auth_vault();
                if (empty($sessions_meta)) {
                    unset($vault_data[$user_id]);
                } else {
                    $vault_data[$user_id] = $sessions_meta;
                }

                $json = (string) wp_json_encode($vault_data);
                $key = class_exists('\\WebCareProScanner\\Security\\SecretVault') ? \WebCareProScanner\Security\SecretVault::get_key() : 'webcare_fallback_salt';
                $encrypted = class_exists('\\WebCareProScanner\\Security\\SecretVault') ? \WebCareProScanner\Security\SecretVault::encrypt($json) : base64_encode($json);
                $hmac = hash_hmac('sha256', $encrypted, $key);

                $container = [
                    'vault_format'      => 'V2_AUTH_SENTINEL_AEAD',
                    'scope'             => 'admin_session_sentinel_audit',
                    'updated_at'        => time(),
                    'updated_at_iso'    => gmdate('Y-m-d\TH:i:s\Z'),
                    'hmac_sha256'       => $hmac,
                    'encrypted_payload' => $encrypted,
                ];

                $encoded_container = (string) wp_json_encode($container, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

                $tmp_file = $vault_file . '.' . uniqid('wcp_vault_', true) . '.tmp';
                if (@file_put_contents($tmp_file, $encoded_container, LOCK_EX) !== false) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic vault replacement prevents partial file reads.
                    @rename($tmp_file, $vault_file);
                }
            } finally {
                @flock($lock_fp, LOCK_UN);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                @fclose($lock_fp);
            }
        } catch (\Throwable $e) {
            // Failsafe without breaking execution
        }
    }

    /**
     * Retrieve decrypted session metadata for a user from database (with vault fallback).
     */
    public static function get_stored_session_meta(int $user_id): array {
        if (!$user_id) {
            return [];
        }

        $raw = get_user_meta($user_id, 'webcareproscan_session_meta', true);

        // 1. If stored as an encrypted string (webcare_gcm:...)
        if (is_string($raw) && !empty($raw) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
            try {
                $decrypted = \WebCareProScanner\Security\SecretVault::decrypt($raw);
                if (is_string($decrypted) && !empty($decrypted)) {
                    $decoded = json_decode($decrypted, true);
                    if (is_array($decoded)) {
                        return $decoded;
                    }
                }
            } catch (\Throwable $e) {
                // Decryption error
            }
        }

        // 2. If stored as legacy/unencrypted array
        if (is_array($raw) && !empty($raw)) {
            return $raw;
        }

        // 3. Fallback: Recover from isolated encrypted JSON vault archive
        try {
            $vault_data = self::read_from_auth_vault();
            if (isset($vault_data[$user_id]) && is_array($vault_data[$user_id])) {
                // Re-persist recovered data into database in encrypted format
                self::save_stored_session_meta($user_id, $vault_data[$user_id]);
                return $vault_data[$user_id];
            }
        } catch (\Throwable $e) {
            // Ignore vault read errors
        }

        return [];
    }

    /**
     * Encrypt and store administrator login & session history in BOTH database and JSON vault file.
     */
    public static function save_stored_session_meta(int $user_id, array $sessions_meta): void {
        if (!$user_id) {
            return;
        }

        // 1. Encrypt and store in database
        try {
            $json = (string) wp_json_encode($sessions_meta);
            if (class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                $encrypted = \WebCareProScanner\Security\SecretVault::encrypt($json);
                update_user_meta($user_id, 'webcareproscan_session_meta', $encrypted);
            } else {
                update_user_meta($user_id, 'webcareproscan_session_meta', $sessions_meta);
            }
        } catch (\Throwable $e) {
            update_user_meta($user_id, 'webcareproscan_session_meta', $sessions_meta);
        }
        wp_cache_delete($user_id, 'user_meta');

        // 2. Synchronize to isolated encrypted JSON vault archive
        try {
            self::sync_to_auth_vault($user_id, $sessions_meta);
        } catch (\Throwable $e) {
            // Failsafe
        }
    }

    /**
     * Bootstrap Session Sentinel
     */
    public static function init() {
        // Capture generated session token during auth cookie issuance
        add_action('set_auth_cookie', [__CLASS__, 'on_set_auth_cookie'], 10, 6);

        // Track session upon login (priority 20) and cleanup pending auth attributes deferred (priority 99)
        add_action('wp_login', [__CLASS__, 'on_user_login'], 20, 2);
        add_action('wp_login', [__CLASS__, 'cleanup_pending_auth'], 99);

        // Verify session integrity on every authenticated request
        add_action('init', [__CLASS__, 'inspect_active_session'], 2);

        // Cleanup on logout
        add_action('wp_logout', [__CLASS__, 'on_user_logout']);
    }

    /**
     * Cache the freshly minted session token from WordPress core's set_auth_cookie hook
     */
    public static function on_set_auth_cookie($auth_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        if (!empty($token)) {
            self::$last_auth_token = $token;
        }
        $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
        if (!empty($cookie_name) && (!isset($_COOKIE[$cookie_name]) || empty($_COOKIE[$cookie_name]))) {
            $_COOKIE[$cookie_name] = $auth_cookie;
        }
    }

    /**
     * Track new authenticated session
     */
    public static function on_user_login(string $user_login, \WP_User $user) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['session_sentinel_enabled'])) {
            return;
        }

        // Only enforce for administrators or editors
        if (!$user->has_cap('edit_posts')) {
            return;
        }

        $session_token = !empty(self::$last_auth_token) ? self::$last_auth_token : wp_get_session_token();
        $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
        if (empty($session_token)) {
            if (is_array($wp_sessions) && !empty($wp_sessions)) {
                $keys = array_keys($wp_sessions);
                $session_token = end($keys);
            }
        }

        $ip = FirewallEngine::get_client_ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $screen_raw = isset($_POST['webcareproscan_screen_res']) ? sanitize_text_field(wp_unslash($_POST['webcareproscan_screen_res'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $tz_raw = isset($_POST['webcareproscan_client_tz']) ? sanitize_text_field(wp_unslash($_POST['webcareproscan_client_tz'])) : '';

        // Dual-Device Concurrency Control: Allow at most 2 devices (strictly 1 Desktop + 1 Mobile)
        if (!empty($settings['session_block_concurrent']) && $user->has_cap('administrator')) {
            $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
            if (is_array($wp_sessions) && count($wp_sessions) > 1 && $session_token) {
                $verifier = hash('sha256', $session_token);
                $sessions_meta = self::get_stored_session_meta($user->ID);

                // Determine current incoming device category ('mobile' vs 'desktop')
                $current_parsed = \WebCareProScanner\Auth\LoginHistoryManager::parse_device_details($ua, $screen_raw);
                $current_cat = in_array($current_parsed['device_type'], ['Mobile', 'Tablet'], true) ? 'mobile' : 'desktop';

                $current_session_key = isset($wp_sessions[$verifier]) ? $verifier : (isset($wp_sessions[$session_token]) ? $session_token : '');
                $current_session_data = $current_session_key ? $wp_sessions[$current_session_key] : null;

                $preserved = [];
                $other_device_session = null;
                $other_device_key = '';

                // Examine prior active sessions and enforce category boundaries
                foreach ($wp_sessions as $s_key => $s_data) {
                    // Skip current newly created session in this loop
                    if ($s_key === $verifier || $s_key === $session_token) {
                        continue;
                    }

                    // Extract user-agent for this existing session
                    $s_ua = $s_data['ua'] ?? '';
                    if (empty($s_ua) && !empty($sessions_meta[$s_key]['encrypted_meta'])) {
                        $decrypted = \WebCareProScanner\Security\SecretVault::decrypt((string) $sessions_meta[$s_key]['encrypted_meta']);
                        $decoded = is_string($decrypted) ? (json_decode($decrypted, true) ?: []) : [];
                        $s_ua = $decoded['user_agent'] ?? '';
                    }

                    $s_parsed = \WebCareProScanner\Auth\LoginHistoryManager::parse_device_details($s_ua, '');
                    $s_cat = in_array($s_parsed['device_type'], ['Mobile', 'Tablet'], true) ? 'mobile' : 'desktop';

                    if ($s_cat === $current_cat) {
                        // Same category as new device (e.g. new desktop replacing previous desktop) -> Terminate!
                        \WebCareProScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $s_key);
                        unset($sessions_meta[$s_key]);
                    } else {
                        // Different category (e.g. mobile session while logging in on desktop) -> Keep newest!
                        $s_login_time = $s_data['login'] ?? 0;
                        if (!$other_device_session || $s_login_time > ($other_device_session['login'] ?? 0)) {
                            if ($other_device_key) {
                                \WebCareProScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $other_device_key);
                                unset($sessions_meta[$other_device_key]);
                            }
                            $other_device_session = $s_data;
                            $other_device_key = $s_key;
                        } else {
                            \WebCareProScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $s_key);
                            unset($sessions_meta[$s_key]);
                        }
                    }
                }

                // Preserve the different device session (1 Desktop + 1 Mobile)
                if ($other_device_key && $other_device_session) {
                    $preserved[$other_device_key] = $other_device_session;
                }

                // Preserve current newly authenticated session
                if ($current_session_key && $current_session_data) {
                    $preserved[$current_session_key] = $current_session_data;
                } elseif ($session_token) {
                    $preserved[$verifier] = [
                        'expiration' => time() + (14 * DAY_IN_SECONDS),
                        'ip'         => $ip,
                        'ua'         => $ua,
                        'login'      => time(),
                    ];
                }

                update_user_meta($user->ID, 'session_tokens', $preserved);
                self::save_stored_session_meta($user->ID, $sessions_meta);
            }
        }

        // Determine login authentication factor / mechanism
        $auth_type = !empty(self::$pending_auth_type) ? self::$pending_auth_type : '';
        $auth_label = !empty(self::$pending_auth_label) ? self::$pending_auth_label : '';
        $auth_details = !empty(self::$pending_auth_details) ? self::$pending_auth_details : [];

        // If not explicitly set by the calling authenticator, deduce it accurately:
        if (empty($auth_type)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Inspection during session authentication creation to detect 2FA submission
            if (!empty($_POST['webcareproscan_2fa_code'])) {
                $auth_type = '2fa';
                $auth_label = __('2FA (TOTP Authenticator)', 'webcare-pro-security');
                $auth_details = ['type' => 'totp'];
            } elseif (class_exists('\\WebCareProScanner\\Auth\\TwoFactorAuth') && \WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user->ID) && \WebCareProScanner\Auth\TwoFactorAuth::is_trusted_device($user->ID)) {
                $auth_type = '2fa';
                $auth_label = __('2FA (Remembered Trusted Device)', 'webcare-pro-security');
                $auth_details = ['type' => 'trusted_device'];
            } else {
                $auth_type = 'password';
                $auth_label = __('Password Only (Single-Factor)', 'webcare-pro-security');
                $auth_details = ['type' => 'password'];
            }
        }

        // Store session metadata in user meta (AES-256-GCM encrypted in DB + Vault)
        $sessions_meta = self::get_stored_session_meta($user->ID);

        if ($session_token) {
            $now = time();
            $verifier = hash('sha256', $session_token);

            // 1. Resolve Device UUID and Hardware Fingerprint
            $device_uuid = class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')
                ? \WebCareProScanner\Auth\LoginHistoryManager::get_or_create_device_uuid()
                : (isset($_COOKIE['webcareproscan_device_uuid']) ? sanitize_text_field(wp_unslash($_COOKIE['webcareproscan_device_uuid'])) : wp_generate_password(32, false, false));

            $device_fp = class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')
                ? \WebCareProScanner\Auth\LoginHistoryManager::get_device_fingerprint($ua, $screen_raw, $tz_raw)
                : hash('sha256', $ua);

            // 2. Search for existing registered device record for this user to avoid duplicate device cards
            $matched_entry = null;
            $keys_to_clean = [];

            foreach ($sessions_meta as $s_key => $s_entry) {
                if (!is_array($s_entry)) {
                    continue;
                }

                $s_uuid = $s_entry['device_uuid'] ?? '';
                $s_fp   = $s_entry['device_fingerprint'] ?? '';
                $s_ua   = $s_entry['user_agent'] ?? '';
                $s_ip   = $s_entry['login_ip'] ?? '';

                if (!empty($s_entry['encrypted_meta']) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                    $dec = \WebCareProScanner\Security\SecretVault::decrypt((string) $s_entry['encrypted_meta']);
                    $dec_data = is_string($dec) ? (json_decode($dec, true) ?: []) : [];
                    $s_uuid = $s_uuid ?: ($dec_data['device_uuid'] ?? '');
                    $s_fp   = $s_fp ?: ($dec_data['device_fingerprint'] ?? '');
                    $s_ua   = $s_ua ?: ($dec_data['user_agent'] ?? '');
                    $s_ip   = $s_ip ?: ($dec_data['login_ip'] ?? '');
                }

                $is_match = false;
                // Match criteria 1: Persistent device UUID matches
                if (!empty($s_uuid) && !empty($device_uuid) && $s_uuid === $device_uuid) {
                    $is_match = true;
                }
                // Match criteria 2: Hardware fingerprint matches
                elseif (!empty($s_fp) && !empty($device_fp) && $s_fp === $device_fp) {
                    $is_match = true;
                }
                // Match criteria 3: Matching browser, platform, and IP (for legacy sessions created before UUID tracking)
                elseif (!empty($s_ua) && substr(sanitize_text_field($ua), 0, 255) === $s_ua && !empty($s_ip) && $s_ip === $ip) {
                    $is_match = true;
                }

                if ($is_match) {
                    $keys_to_clean[] = $s_key;
                    if (!$matched_entry) {
                        $matched_entry = $s_entry;
                    }
                }
            }

            // Remove previous session keys for this same device to prevent duplicate ghost rows
            foreach ($keys_to_clean as $old_key) {
                if ($old_key !== $session_token && $old_key !== $verifier) {
                    unset($sessions_meta[$old_key]);
                }
            }

            // 3. Build continuous IP history & audit telemetry
            $existing_history = [];
            $existing_events = [];
            $device_first_seen = $now;
            $total_logins = 1;

            if ($matched_entry) {
                $device_first_seen = (int) ($matched_entry['device_first_seen'] ?? ($matched_entry['login_time'] ?? $now));
                $total_logins      = (int) ($matched_entry['total_logins'] ?? 1) + 1;

                if (!empty($matched_entry['ip_history']) && is_array($matched_entry['ip_history'])) {
                    $existing_history = $matched_entry['ip_history'];
                }
                if (!empty($matched_entry['ip_events']) && is_array($matched_entry['ip_events'])) {
                    $existing_events = $matched_entry['ip_events'];
                }
            }

            // Append or update current IP in history
            $found_ip = false;
            foreach ($existing_history as &$hist_item) {
                if (($hist_item['ip'] ?? '') === $ip) {
                    $hist_item['last_seen'] = $now;
                    $hist_item['count'] = (int) ($hist_item['count'] ?? 1) + 1;
                    $hist_item['is_current'] = true;
                    $found_ip = true;
                } else {
                    $hist_item['is_current'] = false;
                }
            }
            unset($hist_item);

            if (!$found_ip) {
                $existing_history[] = [
                    'ip'         => $ip,
                    'first_seen' => $now,
                    'last_seen'  => $now,
                    'count'      => 1,
                    'is_login'   => true,
                    'is_current' => true,
                ];
            }

            // Append login event to events array (keep up to 50 most recent events)
            $existing_events[] = [
                'ip'   => $ip,
                'time' => $now,
                'type' => 'login',
                'ua'   => substr(sanitize_text_field($ua), 0, 255),
            ];
            if (count($existing_events) > 50) {
                $existing_events = array_slice($existing_events, -50);
            }

            // 4. Retrieve existing login records for this device or initialize array
            $existing_logins = [];
            if ($matched_entry && !empty($matched_entry['login_records']) && is_array($matched_entry['login_records'])) {
                $existing_logins = $matched_entry['login_records'];
            }

            $country_info = self::get_cloudflare_country($ip);
            $parsed_device = class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')
                ? \WebCareProScanner\Auth\LoginHistoryManager::parse_device_details($ua, $screen_raw)
                : ['browser' => 'Browser', 'browser_version' => '', 'platform' => 'Unknown OS', 'device_type' => 'Desktop', 'screen_resolution' => $screen_raw];

            $current_login_record = [
                'time'              => $now,
                'time_formatted'    => date_i18n('Y-m-d H:i:s', $now),
                'time_human'        => __('Active just now', 'webcare-pro-security'),
                'ip'                => $ip,
                'country'           => $country_info['country'],
                'country_code'      => $country_info['country_code'],
                'country_source'    => $country_info['country_source'],
                'auth_type'         => $auth_type,
                'auth_label'        => $auth_label,
                'browser'           => $parsed_device['browser'],
                'browser_version'   => $parsed_device['browser_version'],
                'platform'          => $parsed_device['platform'],
                'device_type'       => $parsed_device['device_type'],
                'screen_resolution' => !empty($screen_raw) ? $screen_raw : ($parsed_device['screen_resolution'] ?? ''),
                'timezone'          => !empty($tz_raw) ? $tz_raw : 'UTC',
                'user_agent'        => substr(sanitize_text_field($ua), 0, 500),
                'is_current'        => true,
            ];

            // Mark previous logins on this device as historical
            foreach ($existing_logins as &$pl) {
                $pl['is_current'] = false;
            }
            unset($pl);

            array_unshift($existing_logins, $current_login_record);
            if (count($existing_logins) > 50) {
                $existing_logins = array_slice($existing_logins, 0, 50);
            }

            $entry = [
                'device_uuid'        => $device_uuid,
                'device_fingerprint' => $device_fp,
                'device_first_seen'  => $device_first_seen,
                'total_logins'       => $total_logins,
                'login_time'         => $now,
                'last_seen'          => $now,
                'login_ip'           => $ip,
                'current_ip'         => $ip,
                'status'             => 'active',
                'is_revoked'         => false,
                'revoked_at'         => null,
                'revocation_reason'  => null,
                'ip_history'         => $existing_history,
                'ip_events'          => $existing_events,
                'login_records'      => $existing_logins,
                'auth_type'          => $auth_type,
                'auth_label'         => $auth_label,
                'auth_details'       => $auth_details,
                'screen_resolution'  => !empty($screen_raw) ? $screen_raw : ($parsed_device['screen_resolution'] ?? ''),
                'timezone'           => !empty($tz_raw) ? $tz_raw : 'UTC',
                'browser'            => $parsed_device['browser'],
                'browser_version'    => $parsed_device['browser_version'],
                'platform'           => $parsed_device['platform'],
                'device_type'        => $parsed_device['device_type'],
                'country'            => $country_info['country'],
                'country_code'       => $country_info['country_code'],
                'user_agent'         => substr(sanitize_text_field($ua), 0, 500),
                'encrypted_meta'     => class_exists('\\WebCareProScanner\\Security\\SecretVault') ? \WebCareProScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                    'device_uuid'        => $device_uuid,
                    'device_fingerprint' => $device_fp,
                    'device_first_seen'  => $device_first_seen,
                    'total_logins'       => $total_logins,
                    'login_ip'           => $ip,
                    'current_ip'         => $ip,
                    'ip_history'         => $existing_history,
                    'ip_events'          => $existing_events,
                    'login_records'      => $existing_logins,
                    'user_agent'         => substr(sanitize_text_field($ua), 0, 500),
                    'browser'            => $parsed_device['browser'],
                    'browser_version'    => $parsed_device['browser_version'],
                    'platform'           => $parsed_device['platform'],
                    'device_type'        => $parsed_device['device_type'],
                    'screen_resolution'  => !empty($screen_raw) ? $screen_raw : ($parsed_device['screen_resolution'] ?? ''),
                    'timezone'           => !empty($tz_raw) ? $tz_raw : 'UTC',
                    'country'            => $country_info['country'],
                    'country_code'       => $country_info['country_code'],
                    'auth_type'          => $auth_type,
                    'auth_label'         => $auth_label,
                    'auth_details'       => $auth_details,
                ])) : '',
            ];

            // Store metadata under both raw token and verifier so lookups by either succeed
            $sessions_meta[$session_token] = $entry;
            $sessions_meta[$verifier]      = $entry;

            self::save_stored_session_meta($user->ID, $sessions_meta);
        }
    }

    /**
     * Inspect session on each authenticated request to defend against hijacked cookies
     */
    public static function inspect_active_session() {
        if (!is_user_logged_in()) {
            return;
        }

        try {
            $settings = SettingsManager::get_settings();
            if (empty($settings['session_sentinel_enabled'])) {
                return;
            }

            $user_id = get_current_user_id();
            $user = wp_get_current_user();

            // Focus on administrative and editor sessions
            if (!$user || !$user->has_cap('edit_posts')) {
                return;
            }

            $current_token = wp_get_session_token();
            if (!$current_token) {
                return;
            }
            $current_verifier = hash('sha256', $current_token);

            $ip = FirewallEngine::get_client_ip();
            $sessions_meta = self::get_stored_session_meta($user_id);

            $session_info = $sessions_meta[$current_verifier] ?? ($sessions_meta[$current_token] ?? null);

            $current_login_ip = '';
            $decoded = [];
            if (!empty($session_info['encrypted_meta'])) {
                $decrypted_meta = \WebCareProScanner\Security\SecretVault::decrypt((string) $session_info['encrypted_meta']);
                $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                $current_login_ip = $decoded['login_ip'] ?? '';
            } else {
                $current_login_ip = $session_info['login_ip'] ?? '';
            }

            // Auto-initialize if session was active before sentinel activation or if IP was recorded as Cloudflare proxy
            $is_cf_ip = \WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($current_login_ip);

            if (!$session_info || empty($current_login_ip) || $is_cf_ip) {
                self::anchor_session($user_id, $current_token, $current_verifier, $ip, $session_info ?: []);
                return;
            }

            $now = time();
            $current_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            $current_asn = isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : '';
            $recorded_asn = $decoded['asn'] ?? '';

            // Retrieve and maintain unlimited IP access history for this session
            $raw_ip_history = isset($session_info['ip_history']) && is_array($session_info['ip_history'])
                ? $session_info['ip_history']
                : (isset($decoded['ip_history']) && is_array($decoded['ip_history']) ? $decoded['ip_history'] : []);

            if (empty($raw_ip_history) && !empty($current_login_ip)) {
                $raw_ip_history[] = [
                    'ip'         => $current_login_ip,
                    'first_seen' => (int) ($session_info['login_time'] ?? $now),
                    'last_seen'  => (int) ($session_info['last_seen'] ?? $now),
                    'count'      => 1,
                    'is_login'   => true,
                ];
            }

            $ip_found_idx = -1;
            foreach ($raw_ip_history as $idx => $item) {
                if (isset($item['ip']) && $item['ip'] === $ip) {
                    $ip_found_idx = $idx;
                    break;
                }
            }

            $raw_ip_events = isset($session_info['ip_events']) && is_array($session_info['ip_events'])
                ? $session_info['ip_events']
                : (isset($decoded['ip_events']) && is_array($decoded['ip_events']) ? $decoded['ip_events'] : []);

            $needs_meta_save = false;

            if ($ip_found_idx >= 0) {
                // Existing IP seen before on this session. Increment access counter throttled to every 30s
                $last_ip_hit = (int) ($raw_ip_history[$ip_found_idx]['last_seen'] ?? 0);
                if ($now - $last_ip_hit >= 30) {
                    $raw_ip_history[$ip_found_idx]['last_seen'] = $now;
                    $raw_ip_history[$ip_found_idx]['count'] = (int) ($raw_ip_history[$ip_found_idx]['count'] ?? 1) + 1;
                    $needs_meta_save = true;
                }
            } else {
                // Brand new IP observed for this session! Append to unlimited IP history
                $raw_ip_history[] = [
                    'ip'         => $ip,
                    'first_seen' => $now,
                    'last_seen'  => $now,
                    'count'      => 1,
                    'is_login'   => false,
                ];
                $raw_ip_events[] = [
                    'ip'   => $ip,
                    'time' => $now,
                    'type' => 'shift',
                    'ua'   => substr($current_ua, 0, 255),
                ];
                $needs_meta_save = true;
            }

            // Check overall session last_seen update (throttled every 60s)
            if ($now - ($session_info['last_seen'] ?? 0) > 60) {
                $needs_meta_save = true;
            }

            if (($session_info['current_ip'] ?? '') !== $ip) {
                $needs_meta_save = true;
            }

            if ($needs_meta_save) {
                $session_info['last_seen']  = $now;
                $session_info['current_ip'] = $ip;
                $session_info['ip_history'] = $raw_ip_history;
                $session_info['ip_events']  = $raw_ip_events;

                $sessions_meta[$current_token]    = $session_info;
                $sessions_meta[$current_verifier] = $session_info;
                self::save_stored_session_meta($user_id, $sessions_meta);
            }

            $is_ip_valid = self::is_ip_match_or_subnet($current_login_ip, $ip, $decoded, $current_ua);
            $asn_drift = (!empty($recorded_asn) && !empty($current_asn) && $recorded_asn !== $current_asn);
            $ua_mismatch = (!empty($decoded['user_agent']) && !empty($current_ua) && $decoded['user_agent'] !== substr($current_ua, 0, 255));

            // Record IP change / network shift in forensic directory if IP shifted
            if (!empty($ip) && $ip !== $current_login_ip && !\WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip) && $ip !== '127.0.0.1' && $ip !== '::1') {
                if (class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')) {
                    \WebCareProScanner\Auth\LoginHistoryManager::record_session_ip_shift($user_id, $ip, $current_token);
                }
            }

            if ((!empty($settings['session_lock_ip']) && !$is_ip_valid) || ($asn_drift && $ua_mismatch)) {
                // Invalidate hijacked session
                self::terminate_session($user_id, $current_token, 'Session Hijacking / ASN Drift Detected');
                \WebCareProScanner\System\AuditLogger::log(
                    'session_hijack_deflected',
                    sprintf('Deflected hijacked administrative session for %s. Baseline IP %s (ASN %s) vs Incoming IP %s (ASN %s). Session liquidated.', $user->user_login, $current_login_ip, $recorded_asn ?: 'N/A', $ip, $current_asn ?: 'N/A')
                );
                wp_safe_redirect(add_query_arg('webcare_session_invalidated', '1', wp_login_url()));
                exit;
            }
        } catch (\Throwable $e) {
            // Failsafe: never disrupt WordPress admin execution
        }
    }

    /**
     * Check if an incoming IP address matches the recorded session baseline IP or falls within
     * the legitimate carrier/ISP subnet (IPv4 /24 or IPv6 /64 prefix) or verified dual-stack profile.
     *
     * @param string $baseline_ip
     * @param string $incoming_ip
     * @param array  $decoded_meta
     * @param string $current_ua
     * @return bool
     */
    public static function is_ip_match_or_subnet(string $baseline_ip, string $incoming_ip, array $decoded_meta = [], string $current_ua = ''): bool {
        if (empty($baseline_ip) || empty($incoming_ip)) {
            return true; // Failsafe
        }

        // 1. Exact string match
        if ($baseline_ip === $incoming_ip) {
            return true;
        }

        // 2. Check if incoming IP matches verified alternate dual-stack IP (IPv4 vs IPv6)
        if (!empty($decoded_meta['alt_ip']) && $decoded_meta['alt_ip'] === $incoming_ip) {
            return true;
        }

        // 3. IPv4 Subnet Comparison (/24 or /16 for ISP CGNAT/dynamic allocation)
        $is_base_v4 = filter_var($baseline_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $is_inc_v4  = filter_var($incoming_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

        if ($is_base_v4 && $is_inc_v4) {
            $base_parts = explode('.', $baseline_ip);
            $inc_parts  = explode('.', $incoming_ip);
            if (count($base_parts) === 4 && count($inc_parts) === 4) {
                // Strict /24 match (first 3 octets match)
                if ($base_parts[0] === $inc_parts[0] && $base_parts[1] === $inc_parts[1] && $base_parts[2] === $inc_parts[2]) {
                    return true;
                }

                // If behind Cloudflare and User-Agent is an exact identical match, tolerate /16 subnet (ISP regional CGNAT pool)
                $recorded_ua = $decoded_meta['user_agent'] ?? '';
                $is_cf = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);
                if ($is_cf && !empty($recorded_ua) && !empty($current_ua) && $recorded_ua === $current_ua) {
                    if ($base_parts[0] === $inc_parts[0] && $base_parts[1] === $inc_parts[1]) {
                        return true;
                    }
                }
            }
        }

        // 4. IPv6 Subnet Comparison (/64 - First 64 bits / 8 bytes match)
        // Defends against RFC 4941 client privacy interface identifier rotation
        $is_base_v6 = filter_var($baseline_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $is_inc_v6  = filter_var($incoming_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        if ($is_base_v6 && $is_inc_v6) {
            $base_bin = @inet_pton($baseline_ip);
            $inc_bin  = @inet_pton($incoming_ip);
            if ($base_bin !== false && $inc_bin !== false && strlen($base_bin) === 16 && strlen($inc_bin) === 16) {
                if (substr($base_bin, 0, 8) === substr($inc_bin, 0, 8)) {
                    return true;
                }
            }
        }

        // 5. Dual-Stack Cloudflare Flapping (One is IPv4 and one is IPv6)
        // Under Cloudflare and modern browsers (RFC 8305 Happy Eyeballs),
        // browser races IPv4 and IPv6 sockets. If User-Agent is an exact match and request arrives via Cloudflare:
        if (($is_base_v4 && $is_inc_v6) || ($is_base_v6 && $is_inc_v4)) {
            $recorded_ua = $decoded_meta['user_agent'] ?? '';
            $is_cf = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);

            if ($is_cf && !empty($recorded_ua) && !empty($current_ua) && $recorded_ua === $current_ua) {
                return true;
            }
        }

        // 6. Loopback / Internal Proxy Failsafe
        // If incoming request resolved to localhost/private IP due to internal proxy/cron/loopback, do not kill admin session
        if ($incoming_ip === '127.0.0.1' || $incoming_ip === '::1' || \WebCareProScanner\Firewall\FirewallEngine::is_private_ip($incoming_ip)) {
            return true;
        }

        return false;
    }

    /**
     * Anchor or heal an active session with cryptographic metadata binding.
     *
     * @param int    $user_id
     * @param string $token
     * @param string $verifier
     * @param string $ip
     * @param array  $existing_info
     * @return void
     */
    public static function anchor_session(int $user_id, string $token, string $verifier, string $ip, array $existing_info = []): void {
        $sessions_meta = self::get_stored_session_meta($user_id);

        $existing_decoded = [];
        if (!empty($existing_info['encrypted_meta'])) {
            $dec = \WebCareProScanner\Security\SecretVault::decrypt((string) $existing_info['encrypted_meta']);
            $existing_decoded = is_string($dec) ? (json_decode($dec, true) ?: []) : [];
        }

        $now = time();
        $login_ip = $existing_info['login_ip'] ?? ($existing_decoded['login_ip'] ?? $ip);

        // Preserve and update unlimited IP history
        $existing_history = isset($existing_info['ip_history']) && is_array($existing_info['ip_history'])
            ? $existing_info['ip_history']
            : (isset($existing_decoded['ip_history']) && is_array($existing_decoded['ip_history']) ? $existing_decoded['ip_history'] : []);

        if (empty($existing_history) && !empty($login_ip)) {
            $existing_history[] = [
                'ip'         => $login_ip,
                'first_seen' => (int) ($existing_info['login_time'] ?? $now),
                'last_seen'  => $now,
                'count'      => 1,
                'is_login'   => true,
            ];
        }

        $found_hist = false;
        foreach ($existing_history as &$h_entry) {
            if (isset($h_entry['ip']) && $h_entry['ip'] === $ip) {
                $h_entry['last_seen'] = $now;
                $h_entry['count'] = (int) ($h_entry['count'] ?? 1) + 1;
                $found_hist = true;
                break;
            }
        }
        unset($h_entry);

        if (!$found_hist && !empty($ip)) {
            $existing_history[] = [
                'ip'         => $ip,
                'first_seen' => $now,
                'last_seen'  => $now,
                'count'      => 1,
                'is_login'   => empty($existing_history),
            ];
        }

        $existing_events = isset($existing_info['ip_events']) && is_array($existing_info['ip_events'])
            ? $existing_info['ip_events']
            : (isset($existing_decoded['ip_events']) && is_array($existing_decoded['ip_events']) ? $existing_decoded['ip_events'] : []);

        $entry = [
            'login_time'     => $existing_info['login_time'] ?? $now,
            'last_seen'      => $now,
            'login_ip'       => $login_ip,
            'current_ip'     => $ip,
            'ip_history'     => $existing_history,
            'ip_events'      => $existing_events,
            'auth_type'      => $existing_info['auth_type'] ?? ($existing_decoded['auth_type'] ?? 'password'),
            'auth_label'     => $existing_info['auth_label'] ?? ($existing_decoded['auth_label'] ?? 'Password'),
            'encrypted_meta' => \WebCareProScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                'login_ip'   => $login_ip,
                'current_ip' => $ip,
                'ip_history' => $existing_history,
                'ip_events'  => $existing_events,
                'alt_ip'     => $existing_decoded['alt_ip'] ?? '',
                'user_agent' => substr(!empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : ($existing_decoded['user_agent'] ?? 'Unknown'), 0, 255),
                'asn'        => isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : ($existing_decoded['asn'] ?? ''),
                'tls_fp'     => !empty($_SERVER['SSL_CIPHER']) ? hash('sha256', (string) sanitize_text_field(wp_unslash($_SERVER['SSL_CIPHER']))) : ($existing_decoded['tls_fp'] ?? ''),
                'auth_type'  => $existing_info['auth_type'] ?? ($existing_decoded['auth_type'] ?? 'password'),
                'auth_label' => $existing_info['auth_label'] ?? ($existing_decoded['auth_label'] ?? 'Password'),
            ])),
        ];

        $sessions_meta[$token]    = $entry;
        $sessions_meta[$verifier] = $entry;
        self::save_stored_session_meta($user_id, $sessions_meta);
    }

    /**
     * Re-anchor the current user's active session to their current verified IP address.
     * Keeps session metadata in sync with the administrator's active connection.
     */
    public static function reanchor_current_user_session(): void {
        if (!is_user_logged_in()) {
            return;
        }
        $user_id = get_current_user_id();
        $token = wp_get_session_token();
        if (empty($user_id) || empty($token)) {
            return;
        }
        $verifier = hash('sha256', $token);
        $ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        $sessions_meta = self::get_stored_session_meta($user_id);
        $session_info = $sessions_meta[$verifier] ?? ($sessions_meta[$token] ?? []);

        self::anchor_session($user_id, $token, $verifier, $ip, $session_info);
    }

    /**
     * Terminate an individual session
     */
    public static function terminate_session(int $user_id, string $session_token, string $reason = '') {
        if (empty($user_id) || empty($session_token)) {
            return false;
        }

        try {
            // 1. Direct destruction from WordPress core 'session_tokens' user meta.
            // In WP core, sessions are stored in user meta 'session_tokens' keyed by the SHA-256 verifier hash.
            $sessions = get_user_meta($user_id, 'session_tokens', true);
            if (is_array($sessions)) {
                $hashed = hash('sha256', $session_token);
                $modified = false;

                // Check if $session_token is already the verifier hash (as returned by session_tokens user meta)
                if (isset($sessions[$session_token])) {
                    unset($sessions[$session_token]);
                    $modified = true;
                }
                // Check if $session_token was the raw plain text token
                if (isset($sessions[$hashed])) {
                    unset($sessions[$hashed]);
                    $modified = true;
                }

                if ($modified) {
                    if (!empty($sessions)) {
                        update_user_meta($user_id, 'session_tokens', $sessions);
                    } else {
                        delete_user_meta($user_id, 'session_tokens');
                    }
                }
            }

            // 2. Also invoke WP_Session_Tokens core manager destroy()
            try {
                $manager = \WP_Session_Tokens::get_instance($user_id);
                if ($manager) {
                    $manager->destroy($session_token);
                }
            } catch (\Throwable $e) {}

            // Flush WordPress user meta cache
            wp_cache_delete($user_id, 'user_meta');

            // 3. Mark session as logged_out in webcareproscan_session_meta so the device record is preserved
            $sessions_meta = self::get_stored_session_meta($user_id);
            if (is_array($sessions_meta)) {
                $now = time();
                $update_entry = function(&$entry) use ($now, $reason) {
                    if (is_array($entry)) {
                        $entry['status'] = 'logged_out';
                        $entry['is_revoked'] = true;
                        $entry['revoked_at'] = $now;
                        $entry['revocation_reason'] = $reason ?: 'Logged out by administrator via Session Sentinel';
                    }
                };

                if (isset($sessions_meta[$session_token])) {
                    $update_entry($sessions_meta[$session_token]);
                }
                if (isset($sessions_meta[$hashed])) {
                    $update_entry($sessions_meta[$hashed]);
                }

                // If no entry existed, create one so the device displays as logged out
                if (!isset($sessions_meta[$session_token]) && !isset($sessions_meta[$hashed])) {
                    $sessions_meta[$hashed] = [
                        'login_time'        => $now,
                        'last_seen'         => $now,
                        'status'            => 'logged_out',
                        'is_revoked'        => true,
                        'revoked_at'        => $now,
                        'revocation_reason' => $reason ?: 'Logged out by administrator via Session Sentinel',
                    ];
                }

                self::save_stored_session_meta($user_id, $sessions_meta);
            }

            // 4. Mark session terminated in LoginHistoryManager if available
            if (class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')) {
                \WebCareProScanner\Auth\LoginHistoryManager::record_session_terminated($user_id, $session_token);
            }

            // 5. If the terminated session belongs to the current logged-in user, clear auth cookies
            if ($user_id === get_current_user_id()) {
                $current_raw = wp_get_session_token();
                $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
                $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
                if (empty($current_raw) && !empty($raw_logged_in_cookie)) {
                    $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
                    if (!empty($cookie_elements['token'])) {
                        $current_raw = $cookie_elements['token'];
                    }
                }
                if ($current_raw === $session_token || hash('sha256', (string) $current_raw) === $session_token) {
                    if (function_exists('wp_clear_auth_cookie')) {
                        wp_clear_auth_cookie();
                    }
                }
            }

            return true;
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WebCare Pro Security] Error terminating session: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Terminate all other sessions except the current administrator's active device.
     * Only logs out the sessions; strictly preserves all device records and IP histories as logged_out.
     */
    public static function terminate_all_other_sessions(int $target_user_id = 0, bool $revoke_all_admins = false): bool {
        try {
            $current_user_id = get_current_user_id();
            $current_token = wp_get_session_token();

            $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
            $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
            if (empty($current_token) && !empty($raw_logged_in_cookie)) {
                $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
                if (!empty($cookie_elements['token'])) {
                    $current_token = $cookie_elements['token'];
                }
            }

            $current_verifier = !empty($current_token) ? hash('sha256', $current_token) : '';

            // If a specific target_user_id was specified and not revoke_all_admins:
            if (!empty($target_user_id) && !$revoke_all_admins) {
                if ($target_user_id === $current_user_id) {
                    self::terminate_user_other_sessions($target_user_id, $current_token, $current_verifier);
                } else {
                    // Log out all sessions for this target user without wiping device records
                    try {
                        $manager = \WP_Session_Tokens::get_instance($target_user_id);
                        $manager->destroy_all();
                    } catch (\Throwable $e) {}
                    delete_user_meta($target_user_id, 'session_tokens');

                    $sessions_meta = self::get_stored_session_meta($target_user_id);
                    if (is_array($sessions_meta) && !empty($sessions_meta)) {
                        $now = time();
                        foreach ($sessions_meta as $key => &$entry) {
                            if (is_array($entry)) {
                                $entry['status'] = 'logged_out';
                                $entry['is_revoked'] = true;
                                $entry['revoked_at'] = $now;
                                $entry['revocation_reason'] = 'Terminated by administrator via Session Sentinel';
                            }
                        }
                        unset($entry);
                        self::save_stored_session_meta($target_user_id, $sessions_meta);
                    }
                    wp_cache_delete($target_user_id, 'user_meta');
                }
                return true;
            }

            // Otherwise, terminate other sessions across all administrators
            $admins = get_users(['role' => 'administrator', 'number' => 100]);
            foreach ($admins as $admin) {
                if ($admin->ID === $current_user_id) {
                    self::terminate_user_other_sessions($admin->ID, $current_token, $current_verifier);
                } else {
                    try {
                        $manager = \WP_Session_Tokens::get_instance($admin->ID);
                        $manager->destroy_all();
                    } catch (\Throwable $e) {}
                    delete_user_meta($admin->ID, 'session_tokens');

                    $sessions_meta = self::get_stored_session_meta($admin->ID);
                    if (is_array($sessions_meta) && !empty($sessions_meta)) {
                        $now = time();
                        foreach ($sessions_meta as $key => &$entry) {
                            if (is_array($entry)) {
                                $entry['status'] = 'logged_out';
                                $entry['is_revoked'] = true;
                                $entry['revoked_at'] = $now;
                                $entry['revocation_reason'] = 'Terminated by administrator via Session Sentinel';
                            }
                        }
                        unset($entry);
                        self::save_stored_session_meta($admin->ID, $sessions_meta);
                    }
                    wp_cache_delete($admin->ID, 'user_meta');
                }
            }

            return true;
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WebCare Pro Security] Error terminating other sessions: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Helper to terminate a user's other sessions while strictly preserving their active session
     */
    private static function terminate_user_other_sessions(int $user_id, string $current_token, string $current_verifier): void {
        try {
            $sessions = get_user_meta($user_id, 'session_tokens', true);
            if (is_array($sessions) && !empty($current_verifier)) {
                $preserved = isset($sessions[$current_verifier]) ? [$current_verifier => $sessions[$current_verifier]] : [];
                if (!empty($preserved)) {
                    update_user_meta($user_id, 'session_tokens', $preserved);
                } else {
                    $manager = \WP_Session_Tokens::get_instance($user_id);
                    $manager->destroy_others($current_token);
                }
            } else {
                $manager = \WP_Session_Tokens::get_instance($user_id);
                $manager->destroy_others($current_token);
            }

            // DO NOT wipe the metadata for other sessions!
            // Mark non-current sessions as logged_out so their device records stay intact!
            $sessions_meta = self::get_stored_session_meta($user_id);
            if (is_array($sessions_meta) && !empty($sessions_meta)) {
                $now = time();
                foreach ($sessions_meta as $key => &$entry) {
                    if (!is_array($entry)) {
                        continue;
                    }
                    $is_curr = ($key === $current_token || $key === $current_verifier);
                    if (!$is_curr) {
                        $entry['status'] = 'logged_out';
                        $entry['is_revoked'] = true;
                        $entry['revoked_at'] = $now;
                        $entry['revocation_reason'] = 'Terminated by administrator via Session Sentinel';
                    }
                }
                unset($entry);
                self::save_stored_session_meta($user_id, $sessions_meta);
            }

            wp_cache_delete($user_id, 'user_meta');
        } catch (\Throwable $e) {}
    }

    /**
     * Permanently remove a session / device record from metadata history.
     *
     * Strict Forensic Retention Policy:
     * Only logged-out devices that are at least 30 days old can be removed.
     * Active devices and devices logged out less than 30 days ago CANNOT be removed.
     */
    public static function delete_session_record(int $user_id, string $session_token): bool {
        if (empty($user_id) || empty($session_token)) {
            return false;
        }

        $sessions_meta = self::get_stored_session_meta($user_id);
        $hashed = hash('sha256', $session_token);

        $entry = $sessions_meta[$session_token] ?? ($sessions_meta[$hashed] ?? null);
        if (!$entry || !is_array($entry)) {
            return false;
        }

        // 1. Verify session is NOT active in WordPress core
        $wp_sessions = get_user_meta($user_id, 'session_tokens', true) ?: [];
        if (isset($wp_sessions[$hashed]) || isset($wp_sessions[$session_token])) {
            throw new \RuntimeException(
                esc_html__('Active Device: This device is currently active. You must log out the device before it can be considered for removal.', 'webcare-pro-security')
            );
        }

        // 2. Verify marked as logged_out
        $is_logged_out = (!empty($entry['is_revoked']) || ($entry['status'] ?? '') === 'logged_out');
        if (!$is_logged_out) {
            throw new \RuntimeException(
                esc_html__('Active Device: This device record is not logged out. You must log out the device first.', 'webcare-pro-security')
            );
        }

        // 3. Enforce 30-day retention invariant
        $now = time();
        $thirty_days_seconds = self::RETENTION_PERIOD_SECONDS;
        $inactive_since = (int) ($entry['revoked_at'] ?? ($entry['last_seen'] ?? ($entry['created_at'] ?? 0)));
        $elapsed = $now - $inactive_since;

        if ($elapsed < $thirty_days_seconds) {
            $days_remaining = (int) max(1, ceil(($thirty_days_seconds - $elapsed) / DAY_IN_SECONDS));
            throw new \RuntimeException(
                esc_html(sprintf(
                    /* translators: %d: number of days remaining */
                    __('Forensic Retention Lock: Device records are preserved for 30 days after logout for audit compliance. This record will become eligible for removal in %d days.', 'webcare-pro-security'),
                    $days_remaining
                ))
            );
        }

        // 4. Eligible for removal! Unset from session metadata and save encrypted to DB & Vault
        unset($sessions_meta[$session_token]);
        unset($sessions_meta[$hashed]);

        self::save_stored_session_meta($user_id, $sessions_meta);
        return true;
    }

    /**
     * Cleanup on logout: mark session as logged_out instead of deleting record
     */
    public static function on_user_logout() {
        $user_id = get_current_user_id();
        $current_token = wp_get_session_token();

        if ($user_id && $current_token) {
            $sessions_meta = self::get_stored_session_meta($user_id);
            $verifier = hash('sha256', $current_token);
            $now = time();
            if (isset($sessions_meta[$current_token]) && is_array($sessions_meta[$current_token])) {
                $sessions_meta[$current_token]['status'] = 'logged_out';
                $sessions_meta[$current_token]['is_revoked'] = true;
                $sessions_meta[$current_token]['revoked_at'] = $now;
            }
            if (isset($sessions_meta[$verifier]) && is_array($sessions_meta[$verifier])) {
                $sessions_meta[$verifier]['status'] = 'logged_out';
                $sessions_meta[$verifier]['is_revoked'] = true;
                $sessions_meta[$verifier]['revoked_at'] = $now;
            }
            self::save_stored_session_meta($user_id, $sessions_meta);
        }
    }

    /**
     * Merge multiple IP history arrays into a unified, deduplicated list
     */
    public static function merge_ip_histories(array $hist1, array $hist2): array {
        $by_ip = [];
        foreach (array_merge($hist1, $hist2) as $item) {
            $ip = sanitize_text_field($item['ip'] ?? '');
            if (empty($ip)) {
                continue;
            }
            if (!isset($by_ip[$ip])) {
                $by_ip[$ip] = $item;
            } else {
                $by_ip[$ip]['first_seen'] = min((int)($by_ip[$ip]['first_seen'] ?? time()), (int)($item['first_seen'] ?? time()));
                $by_ip[$ip]['last_seen']  = max((int)($by_ip[$ip]['last_seen'] ?? time()), (int)($item['last_seen'] ?? time()));
                $by_ip[$ip]['count']      = ((int)($by_ip[$ip]['count'] ?? 1)) + ((int)($item['count'] ?? 1));
                if (!empty($item['is_login'])) {
                    $by_ip[$ip]['is_login'] = true;
                }
                if (!empty($item['is_current'])) {
                    $by_ip[$ip]['is_current'] = true;
                }
            }
        }
        return array_values($by_ip);
    }

    /**
     * Retrieve all active sessions across administrator accounts
     */
    public static function get_active_sessions(): array {
        $current_user_id = get_current_user_id();
        $current_token   = wp_get_session_token();

        // When called via REST API or admin-ajax, wp_get_session_token() can be empty.
        // Fall back to extracting the token directly from the authenticated logged_in cookie.
        $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
        $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
        if (empty($current_token) && !empty($raw_logged_in_cookie)) {
            $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
            if (!empty($cookie_elements['token'])) {
                $current_token = $cookie_elements['token'];
            }
        }

        $current_verifier = !empty($current_token) ? hash('sha256', $current_token) : '';
        $client_ip = FirewallEngine::get_client_ip();

        // Get admin users
        $admins = get_users(['role' => 'administrator', 'number' => 50]);
        $results = [];
        $now = time();

        foreach ($admins as $admin) {
            $wp_sessions = get_user_meta($admin->ID, 'session_tokens', true) ?: [];
            if (!is_array($wp_sessions)) {
                $wp_sessions = [];
            }
            $sessions_meta = self::get_stored_session_meta($admin->ID);

            if (empty($wp_sessions) && empty($sessions_meta)) {
                continue;
            }

            // Build unified canonical session entries keyed by $verifier hash
            $unified_sessions = [];

            // 1. First register active sessions known to WordPress core
            foreach ($wp_sessions as $verifier => $data) {
                if (!is_array($data)) {
                    continue;
                }
                $meta_entry = $sessions_meta[$verifier] ?? ($sessions_meta[$current_token] ?? []);
                $unified_sessions[$verifier] = [
                    'wp_data' => $data,
                    'meta'    => $meta_entry,
                ];
            }

            // 2. Next merge all sessions stored in webcareproscan_session_meta (including logged-out / revoked devices)
            foreach ($sessions_meta as $key => $meta_entry) {
                if (!is_array($meta_entry)) {
                    continue;
                }
                $canonical_v = (strlen($key) === 64 && ctype_xdigit($key)) ? $key : hash('sha256', $key);
                if (!isset($unified_sessions[$canonical_v])) {
                    $unified_sessions[$canonical_v] = [
                        'wp_data' => null,
                        'meta'    => $meta_entry,
                    ];
                } elseif (empty($unified_sessions[$canonical_v]['meta'])) {
                    $unified_sessions[$canonical_v]['meta'] = $meta_entry;
                }
            }

            // 3. Consolidate sessions by persistent Device Identity (eliminate duplicate ghost device rows)
            $consolidated_devices = [];
            $meta_healed = false;

            // Pre-index known device UUIDs by hardware/browser signature to associate legacy sessions
            $fp_to_uuid = [];
            foreach ($unified_sessions as $verifier => $u_sess) {
                $meta = $u_sess['meta'] ?: [];
                $wp_d = $u_sess['wp_data'];
                $dec = [];
                if (!empty($meta['encrypted_meta']) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                    $dec_raw = \WebCareProScanner\Security\SecretVault::decrypt((string) $meta['encrypted_meta']);
                    $dec = is_string($dec_raw) ? (json_decode($dec_raw, true) ?: []) : [];
                }
                $u = $meta['device_uuid'] ?? ($dec['device_uuid'] ?? '');
                if (!empty($u)) {
                    $ua = $dec['user_agent'] ?? ($meta['user_agent'] ?? ($wp_d['ua'] ?? ''));
                    $ip = $dec['login_ip'] ?? ($meta['login_ip'] ?? ($wp_d['ip'] ?? ''));
                    $b_info = self::parse_user_agent($ua);
                    $fp = hash('sha256', ($b_info['browser'] ?? '') . '|' . ($b_info['platform'] ?? '') . '|' . ($b_info['device_type'] ?? '') . '|' . $ip);
                    $fp_to_uuid[$fp] = $u;
                }
            }

            foreach ($unified_sessions as $verifier => $u_sess) {
                $data = $u_sess['wp_data'];
                $meta = $u_sess['meta'] ?: [];

                // Decrypt metadata if available
                $decoded = [];
                if (!empty($meta['encrypted_meta']) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                    $decrypted_meta = \WebCareProScanner\Security\SecretVault::decrypt((string) $meta['encrypted_meta']);
                    $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                }

                $d_uuid = $meta['device_uuid'] ?? ($decoded['device_uuid'] ?? '');
                $d_ua   = $decoded['user_agent'] ?? ($meta['user_agent'] ?? ($data['ua'] ?? 'Unknown'));
                $d_ip   = $decoded['login_ip'] ?? ($meta['login_ip'] ?? ($data['ip'] ?? 'Unknown'));

                $b_info = self::parse_user_agent($d_ua);
                $fp = hash('sha256', ($b_info['browser'] ?? '') . '|' . ($b_info['platform'] ?? '') . '|' . ($b_info['device_type'] ?? '') . '|' . $d_ip);

                if (empty($d_uuid) && isset($fp_to_uuid[$fp])) {
                    $d_uuid = $fp_to_uuid[$fp];
                }

                // Determine device grouping key
                if (!empty($d_uuid)) {
                    $device_group_key = 'uuid_' . $d_uuid;
                } else {
                    $device_group_key = 'fp_' . $fp;
                }

                // Check if this specific verifier is current active session
                $is_current_verifier = false;
                if ($admin->ID === $current_user_id) {
                    if (!empty($current_verifier) && $verifier === $current_verifier) {
                        $is_current_verifier = true;
                    } elseif (!empty($current_token) && ($verifier === $current_token || hash('sha256', $current_token) === $verifier)) {
                        $is_current_verifier = true;
                    }
                }

                if (!isset($consolidated_devices[$device_group_key])) {
                    $consolidated_devices[$device_group_key] = [
                        'canonical_verifier' => $verifier,
                        'wp_data'            => $data,
                        'meta'               => $meta,
                        'decoded'            => $decoded,
                        'd_uuid'             => $d_uuid,
                        'is_current'         => $is_current_verifier,
                        'all_verifiers'      => [$verifier],
                    ];
                } else {
                    // Duplicate session for this same physical device found!
                    $meta_healed = true;
                    $existing = &$consolidated_devices[$device_group_key];
                    $existing['all_verifiers'][] = $verifier;

                    if (!empty($d_uuid) && empty($existing['d_uuid'])) {
                        $existing['d_uuid'] = $d_uuid;
                    }

                    // If this verifier is current or active in WP core, promote it as canonical
                    if ($is_current_verifier || (!empty($data) && empty($existing['wp_data']))) {
                        $existing['canonical_verifier'] = $verifier;
                        $existing['wp_data']            = $data;
                        if ($is_current_verifier) {
                            $existing['is_current'] = true;
                        }
                    }

                    // Merge IP histories
                    $e_hist = $existing['meta']['ip_history'] ?? ($existing['decoded']['ip_history'] ?? []);
                    $n_hist = $meta['ip_history'] ?? ($decoded['ip_history'] ?? []);
                    $merged_hist = self::merge_ip_histories($e_hist, $n_hist);
                    $existing['meta']['ip_history'] = $merged_hist;

                    // Merge IP events
                    $e_events = $existing['meta']['ip_events'] ?? ($existing['decoded']['ip_events'] ?? []);
                    $n_events = $meta['ip_events'] ?? ($decoded['ip_events'] ?? []);
                    if (is_array($n_events) && !empty($n_events)) {
                        $existing['meta']['ip_events'] = array_slice(array_merge($e_events, $n_events), -50);
                    }

                    // Merge Login Records
                    $e_logins = $existing['meta']['login_records'] ?? ($existing['decoded']['login_records'] ?? []);
                    $n_logins = $meta['login_records'] ?? ($decoded['login_records'] ?? []);
                    $existing['meta']['login_records'] = self::merge_login_records($e_logins, $n_logins);

                    // Carry forward telemetry
                    if (empty($existing['meta']['screen_resolution']) && !empty($meta['screen_resolution'])) {
                        $existing['meta']['screen_resolution'] = $meta['screen_resolution'];
                    }
                    if (empty($existing['meta']['timezone']) && !empty($meta['timezone'])) {
                        $existing['meta']['timezone'] = $meta['timezone'];
                    }
                    if (empty($existing['meta']['country']) && !empty($meta['country'])) {
                        $existing['meta']['country'] = $meta['country'];
                        $existing['meta']['country_code'] = $meta['country_code'] ?? '';
                    }

                    // Carry forward timestamps
                    $existing['meta']['login_time'] = max((int)($existing['meta']['login_time'] ?? 0), (int)($meta['login_time'] ?? 0));
                    $existing['meta']['last_seen']  = max((int)($existing['meta']['last_seen'] ?? 0), (int)($meta['last_seen'] ?? 0));

                    // If one session is active, the consolidated device is active
                    if ($existing['is_current'] || !empty($existing['wp_data'])) {
                        $existing['meta']['status'] = 'active';
                        $existing['meta']['is_revoked'] = false;
                    }

                    unset($existing);
                }
            }

            // Heal $sessions_meta in user meta and vault by unsetting stale duplicate verifiers
            if ($meta_healed && !empty($sessions_meta)) {
                $canonical_keys = [];
                foreach ($consolidated_devices as $c_dev) {
                    $canonical_keys[$c_dev['canonical_verifier']] = true;
                }
                $modified_meta = false;
                foreach ($consolidated_devices as $c_dev) {
                    foreach ($c_dev['all_verifiers'] as $v) {
                        if (!isset($canonical_keys[$v]) && isset($sessions_meta[$v])) {
                            unset($sessions_meta[$v]);
                            $modified_meta = true;
                        }
                    }
                }
                if ($modified_meta) {
                    self::save_stored_session_meta($admin->ID, $sessions_meta);
                }
            }

            foreach ($consolidated_devices as $device_group_key => $c_dev) {
                $verifier   = $c_dev['canonical_verifier'];
                $data       = $c_dev['wp_data'];
                $meta       = $c_dev['meta'];
                $decoded    = $c_dev['decoded'];
                $d_uuid     = $c_dev['d_uuid'];
                $is_current = $c_dev['is_current'];

                $is_logged_out = (!empty($meta['is_revoked']) || ($meta['status'] ?? '') === 'logged_out' || empty($data) || (isset($data['expiration']) && (int) $data['expiration'] <= $now));
                if ($is_current) {
                    $is_logged_out = false;
                }

                $is_active = !$is_logged_out;
                $status = $is_active ? 'active' : 'logged_out';

                $ip = 'Unknown';
                $ua = 'Unknown';
                $auth_type = $meta['auth_type'] ?? '';
                $auth_label = $meta['auth_label'] ?? '';
                $auth_details = $meta['auth_details'] ?? [];
                $support_link_meta = null;

                if (!empty($meta['encrypted_meta'])) {
                    if (empty($decoded) && class_exists('\\WebCareProScanner\\Security\\SecretVault')) {
                        $decrypted_meta = \WebCareProScanner\Security\SecretVault::decrypt((string) $meta['encrypted_meta']);
                        $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                    }
                    $ip = $decoded['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $decoded['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                    if (empty($auth_type) && !empty($decoded['auth_type'])) {
                        $auth_type = $decoded['auth_type'];
                        $auth_label = $decoded['auth_label'] ?? '';
                        $auth_details = $decoded['auth_details'] ?? [];
                    }
                } else {
                    $ip = $meta['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $meta['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                }

                $login_ts = isset($meta['login_time']) ? (int) $meta['login_time'] : (isset($data['login']) ? (int) $data['login'] : time());

                // Smart Deductive Inference for existing sessions without stored auth_type
                if (empty($auth_type)) {
                    // Check if a passkey was used around the login time
                    $user_passkeys = class_exists('\\WebCareProScanner\\Auth\\WebAuthnManager') ? \WebCareProScanner\Auth\WebAuthnManager::get_user_credentials($admin->ID) : [];
                    $matched_pk = null;
                    foreach ($user_passkeys as $pk) {
                        if (!empty($pk['last_used']) && abs((int) $pk['last_used'] - $login_ts) <= 180) {
                            $matched_pk = $pk;
                            break;
                        }
                    }
                    if ($matched_pk) {
                        $auth_type = 'passkey';
                        $auth_label = sprintf(
                            /* translators: %s: device name */
                            __('Passkey (%s)', 'webcare-pro-security'),
                            $matched_pk['name'] ?? 'Windows Hello / FIDO2'
                        );
                        $auth_details = [
                            'type'        => 'passkey',
                            'device_name' => $matched_pk['name'] ?? 'Hardware Key',
                        ];
                    } elseif (class_exists('\\WebCareProScanner\\Auth\\TwoFactorAuth') && \WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($admin->ID)) {
                        $auth_type = '2fa';
                        $auth_label = __('2FA (TOTP Authenticator)', 'webcare-pro-security');
                        $auth_details = ['type' => 'totp'];
                    } else {
                        $auth_type = 'password';
                        $auth_label = __('Password Only (Single-Factor)', 'webcare-pro-security');
                        $auth_details = ['type' => 'password'];
                    }
                }

                // If $ip belongs to Cloudflare's Anycast proxy network, it's an edge node, not the visitor's device.
                // Heal current active session directly to the verified client IP.
                if (\WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip)) {
                    if ($is_current) {
                        $ip = $client_ip;
                        $entry = [
                            'login_time'     => $login_ts,
                            'last_seen'      => time(),
                            'auth_type'      => $auth_type,
                            'auth_label'     => $auth_label,
                            'auth_details'   => $auth_details,
                            'encrypted_meta' => \WebCareProScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                                'login_ip'     => $client_ip,
                                'user_agent'   => $ua,
                                'auth_type'    => $auth_type,
                                'auth_label'   => $auth_label,
                                'auth_details' => $auth_details,
                            ])),
                        ];
                        $sessions_meta[$verifier] = $entry;
                        if (!empty($current_token)) {
                            $sessions_meta[$current_token] = $entry;
                        }
                        self::save_stored_session_meta($admin->ID, $sessions_meta);
                    }
                }

                // Determine browser / OS / device type info
                $browser_info = self::parse_user_agent($ua);

                $duration_sec = max(1, time() - $login_ts);
                $duration_formatted = class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager') 
                    ? \WebCareProScanner\Auth\LoginHistoryManager::format_duration($duration_sec)
                    : sprintf('%d mins', round($duration_sec / 60));

                // Security posture level and risk factor calculation
                $security_level = 'hardened';
                if ($auth_type === 'password') {
                    $security_level = 'at_risk';
                }

                $last_seen_ts = isset($meta['last_seen']) ? (int) $meta['last_seen'] : $login_ts;

                // Retrieve unlimited IP access history and determine if IP changed
                $raw_history = isset($meta['ip_history']) && is_array($meta['ip_history'])
                    ? $meta['ip_history']
                    : (isset($decoded['ip_history']) && is_array($decoded['ip_history']) ? $decoded['ip_history'] : []);

                if (empty($raw_history) && !empty($ip) && $ip !== 'Unknown') {
                    $raw_history[] = [
                        'ip'         => $ip,
                        'first_seen' => $login_ts,
                        'last_seen'  => $last_seen_ts,
                        'count'      => 1,
                        'is_login'   => true,
                    ];
                }

                $session_active_ip = $meta['current_ip'] ?? ($decoded['current_ip'] ?? ($is_current ? $client_ip : $ip));
                $distinct_ips = [];
                $formatted_ip_history = [];

                foreach ($raw_history as $hist) {
                    $hist_ip = sanitize_text_field($hist['ip'] ?? '');
                    if (empty($hist_ip)) {
                        continue;
                    }
                    if (!in_array($hist_ip, $distinct_ips, true)) {
                        $distinct_ips[] = $hist_ip;
                    }
                    $first_ts = (int) ($hist['first_seen'] ?? $login_ts);
                    $last_ts  = (int) ($hist['last_seen'] ?? $last_seen_ts);
                    $is_login_ip = !empty($hist['is_login']) || ($hist_ip === $ip);
                    $is_active_ip = ($hist_ip === $session_active_ip);

                    $formatted_ip_history[] = [
                        'ip'               => $hist_ip,
                        'first_seen'       => date_i18n('Y-m-d H:i:s', $first_ts),
                        'first_seen_raw'   => $first_ts,
                        'first_seen_human' => human_time_diff($first_ts, time()) . ' ago',
                        'last_seen'        => date_i18n('Y-m-d H:i:s', $last_ts),
                        'last_seen_raw'    => $last_ts,
                        'last_seen_human'  => (time() - $last_ts < 90) ? __('Active just now', 'webcare-pro-security') : human_time_diff($last_ts, time()) . ' ago',
                        'count'            => max(1, (int) ($hist['count'] ?? 1)),
                        'is_login'         => $is_login_ip,
                        'is_current'       => $is_active_ip,
                        'is_local_ip'      => ($hist_ip === '127.0.0.1' || $hist_ip === '::1' || \WebCareProScanner\Firewall\FirewallEngine::is_private_ip($hist_ip)),
                    ];
                }

                usort($formatted_ip_history, function ($a, $b) {
                    if (!empty($a['is_current']) && empty($b['is_current'])) return -1;
                    if (empty($a['is_current']) && !empty($b['is_current'])) return 1;
                    return ($b['last_seen_raw'] ?? 0) <=> ($a['last_seen_raw'] ?? 0);
                });

                $has_ip_changed = count($distinct_ips) > 1 || (!empty($session_active_ip) && !empty($ip) && $session_active_ip !== $ip);

                if ($has_ip_changed && !in_array($session_active_ip, $distinct_ips, true) && !empty($session_active_ip) && $session_active_ip !== 'Unknown') {
                    $distinct_ips[] = $session_active_ip;
                }

                $risk_factors = [];
                if ($auth_type === 'password') {
                    $risk_factors[] = __('Single-factor password login: Account lacks MFA (2FA or Passkey).', 'webcare-pro-security');
                }
                if ($has_ip_changed) {
                    $risk_factors[] = sprintf(
                        /* translators: 1: login IP, 2: current IP, 3: count */
                        __('IP changed since login (%1$s &rarr; %2$s). %3$d unique IPs observed.', 'webcare-pro-security'),
                        esc_html($ip),
                        esc_html($session_active_ip),
                        count($distinct_ips)
                    );
                }

                // Expiration calculations
                $expiration_ts = isset($data['expiration']) ? (int) $data['expiration'] : null;
                $expiration_formatted = $expiration_ts ? date_i18n('Y-m-d H:i:s', $expiration_ts) : 'Default (14 days)';
                $expiration_human = '';
                if ($is_active) {
                    if ($expiration_ts) {
                        if ($expiration_ts < time()) {
                            $expiration_human = __('Expired', 'webcare-pro-security');
                        } else {
                            $expiration_human = sprintf(
                                /* translators: %s: remaining time difference */
                                __('Expires in %s', 'webcare-pro-security'),
                                human_time_diff(time(), $expiration_ts)
                            );
                        }
                    } else {
                        $expiration_human = __('Expires in 14 days', 'webcare-pro-security');
                    }
                } else {
                    $revoked_at_ts = isset($meta['revoked_at']) ? (int) $meta['revoked_at'] : (isset($meta['last_seen']) ? (int) $meta['last_seen'] : time());
                    $expiration_human = sprintf(
                        /* translators: %s: time difference */
                        __('Logged out %s ago', 'webcare-pro-security'),
                        human_time_diff($revoked_at_ts, time())
                    );
                }

                // Idle time calculation
                $idle_diff = max(0, time() - $last_seen_ts);
                $idle_human = $idle_diff < 90 ? __('Active just now', 'webcare-pro-security') : sprintf(
                    /* translators: %s: time difference */
                    __('Idle for %s', 'webcare-pro-security'),
                    human_time_diff($last_seen_ts, time())
                );

                // 30-Day Retention Invariant: Only logged out devices older than 30 days are eligible for removal
                $thirty_days_seconds = self::RETENTION_PERIOD_SECONDS;
                $inactive_since = (int) ($meta['revoked_at'] ?? ($meta['last_seen'] ?? ($meta['created_at'] ?? $login_ts)));
                $elapsed_inactive = $now - $inactive_since;
                $is_eligible_for_removal = ($is_logged_out && $elapsed_inactive >= $thirty_days_seconds);
                $retention_days_remaining = ($is_logged_out && $elapsed_inactive < $thirty_days_seconds)
                    ? (int) max(1, ceil(($thirty_days_seconds - $elapsed_inactive) / DAY_IN_SECONDS))
                    : 0;

                $parsed_device = class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')
                    ? \WebCareProScanner\Auth\LoginHistoryManager::parse_device_details($ua, '')
                    : ['browser' => $browser_info['browser'], 'browser_version' => '', 'platform' => $browser_info['platform'], 'device_type' => $browser_info['device_type'], 'screen_resolution' => ''];

                $screen_res  = $decoded['screen_resolution'] ?? ($meta['screen_resolution'] ?? ($parsed_device['screen_resolution'] ?? ''));
                $timezone    = $decoded['timezone'] ?? ($meta['timezone'] ?? '');
                $browser_ver = $decoded['browser_version'] ?? ($meta['browser_version'] ?? ($parsed_device['browser_version'] ?? ''));
                $country     = $decoded['country'] ?? ($meta['country'] ?? '');
                $country_code= $decoded['country_code'] ?? ($meta['country_code'] ?? '');

                if (empty($country) || $country === 'Unknown') {
                    $cf_geo = self::get_cloudflare_country($ip);
                    $country = $cf_geo['country'];
                    $country_code = $cf_geo['country_code'];
                }

                $login_records = $decoded['login_records'] ?? ($meta['login_records'] ?? []);
                if (empty($login_records) || !is_array($login_records)) {
                    $login_records = [
                        [
                            'time'              => $login_ts,
                            'time_formatted'    => date_i18n('Y-m-d H:i:s', $login_ts),
                            'time_human'        => human_time_diff($login_ts, time()) . ' ago',
                            'ip'                => $ip,
                            'country'           => $country,
                            'country_code'      => $country_code,
                            'auth_type'         => $auth_type,
                            'auth_label'        => $auth_label,
                            'browser'           => $browser_info['browser'],
                            'browser_version'   => $browser_ver,
                            'platform'          => $browser_info['platform'],
                            'device_type'       => $browser_info['device_type'],
                            'screen_resolution' => $screen_res,
                            'timezone'          => $timezone ?: 'UTC',
                            'user_agent'        => $ua,
                            'is_current'        => $is_current,
                        ]
                    ];
                }

                $device_first_seen_ts = (int) ($meta['device_first_seen'] ?? ($decoded['device_first_seen'] ?? $login_ts));

                $results[] = [
                    'session_id'               => substr((string) $verifier, 0, 16),
                    'token'                    => (string) $verifier,
                    'user_id'                  => $admin->ID,
                    'user_login'               => $admin->user_login,
                    'display_name'             => $admin->display_name ?: $admin->user_login,
                    'user_email'               => $admin->user_email,
                    'avatar_url'               => get_avatar_url($admin->ID, ['size' => 48]),
                    'is_current'               => $is_current,
                    'is_active'                => $is_active,
                    'status'                   => $status,
                    'is_revoked'               => $is_logged_out,
                    'revoked_at'               => isset($meta['revoked_at']) ? (int) $meta['revoked_at'] : null,
                    'revoked_at_human'         => isset($meta['revoked_at']) ? sprintf(
                        /* translators: %s: time difference */
                        __('%s ago', 'webcare-pro-security'),
                        human_time_diff((int) $meta['revoked_at'], time())
                    ) : null,
                    'revocation_reason'        => $meta['revocation_reason'] ?? '',
                    'can_delete'               => $is_eligible_for_removal,
                    'retention_days_remaining' => $retention_days_remaining,
                    'retention_lock_reason'    => ($is_logged_out && !$is_eligible_for_removal)
                        ? sprintf(
                            /* translators: %d: days remaining */
                            __('Forensic Retention Lock: Device records are preserved for 30 days after logout (%d days remaining).', 'webcare-pro-security'),
                            $retention_days_remaining
                        )
                        : null,
                    'login_ip'                 => $ip,
                    'current_ip'               => $session_active_ip,
                    'is_same_ip'               => ($ip === $session_active_ip),
                    'is_local_ip'              => ($ip === '127.0.0.1' || $ip === '::1' || \WebCareProScanner\Firewall\FirewallEngine::is_private_ip($ip)),
                    'has_ip_changed'           => $has_ip_changed,
                    'distinct_ips'             => $distinct_ips,
                    'distinct_ip_count'        => count($distinct_ips),
                    'ip_changes_count'         => max(0, count($distinct_ips) - 1),
                    'ip_history'               => $formatted_ip_history,
                    'ip_events'                => $meta['ip_events'] ?? ($decoded['ip_events'] ?? []),
                    'login_time'               => date_i18n('Y-m-d H:i:s', $login_ts),
                    'login_time_raw'           => $login_ts,
                    'login_time_human'         => human_time_diff($login_ts, time()) . ' ago',
                    'login_duration_seconds'   => $duration_sec,
                    'login_duration_formatted' => $duration_formatted,
                    'last_seen'                => isset($meta['last_seen']) ? date_i18n('Y-m-d H:i:s', $meta['last_seen']) : 'Recently',
                    'last_seen_raw'            => $last_seen_ts,
                    'idle_human'               => $idle_human,
                    'expiration'               => $expiration_formatted,
                    'expiration_raw'           => $expiration_ts,
                    'expiration_human'         => $expiration_human,
                    'browser'                  => $browser_info['browser'],
                    'browser_version'          => $browser_ver,
                    'platform'                 => $browser_info['platform'],
                    'device_type'              => $browser_info['device_type'],
                    'screen_resolution'        => $screen_res,
                    'timezone'                 => $timezone ?: 'UTC',
                    'country'                  => $country,
                    'country_code'             => $country_code,
                    'device_uuid'              => $d_uuid,
                    'total_logins'             => max((int) ($meta['total_logins'] ?? ($decoded['total_logins'] ?? 1)), count($login_records)),
                    'login_records'            => $login_records,
                    'device_first_seen'        => $device_first_seen_ts,
                    'device_first_seen_human'  => human_time_diff($device_first_seen_ts, time()) . ' ago',
                    'device_first_seen_formatted' => date_i18n('Y-m-d H:i:s', $device_first_seen_ts),
                    'user_agent'               => $ua,
                    'auth_type'                => $auth_type,
                    'auth_label'               => $auth_label,
                    'auth_details'             => $auth_details,
                    'security_level'           => $security_level,
                    'risk_factors'             => $risk_factors,
                    'support_link_meta'        => $support_link_meta,
                ];
            }
        }

        // If no session was matched directly by token (e.g. REST API environment cookie variations),
        // fallback to flagging the active user's newest session on the matching client IP as current.
        $has_current = false;
        foreach ($results as $res) {
            if (!empty($res['is_current'])) {
                $has_current = true;
                break;
            }
        }

        if (!$has_current && !empty($results)) {
            $best_match_idx = null;
            $best_time = 0;
            foreach ($results as $idx => $res) {
                if ($res['user_id'] === $current_user_id && !empty($res['is_active'])) {
                    $score = 0;
                    if ($res['is_same_ip']) {
                        $score += 1000;
                    }
                    if ($best_match_idx === null || $score > $best_time) {
                        $best_time = $score;
                        $best_match_idx = $idx;
                    }
                }
            }
            if ($best_match_idx !== null) {
                $results[$best_match_idx]['is_current'] = true;
                $results[$best_match_idx]['is_active'] = true;
                $results[$best_match_idx]['status'] = 'active';
                $results[$best_match_idx]['can_delete'] = false;
                $results[$best_match_idx]['retention_days_remaining'] = 0;
                $results[$best_match_idx]['retention_lock_reason'] = null;
            }
        }

        return $results;
    }

    /**
     * Simple parser for Browser & OS
     */
    private static function parse_user_agent(string $ua): array {
        $platform = 'Unknown OS';
        $device_type = 'Desktop';

        if (stripos($ua, 'iPad') !== false || stripos($ua, 'Tablet') !== false) {
            $device_type = 'Tablet';
        } elseif (stripos($ua, 'Mobile') !== false || stripos($ua, 'Android') !== false || stripos($ua, 'iPhone') !== false) {
            $device_type = 'Mobile';
        }

        if (stripos($ua, 'Windows') !== false) {
            $platform = 'Windows';
        } elseif (stripos($ua, 'Macintosh') !== false || stripos($ua, 'Mac OS') !== false) {
            $platform = 'macOS';
        } elseif (stripos($ua, 'Linux') !== false) {
            $platform = 'Linux';
        } elseif (stripos($ua, 'Android') !== false) {
            $platform = 'Android';
        } elseif (stripos($ua, 'iPhone') !== false || stripos($ua, 'iPad') !== false) {
            $platform = 'iOS';
        }

        $browser = 'Browser';
        if (stripos($ua, 'Edg') !== false) {
            $browser = 'Microsoft Edge';
        } elseif (stripos($ua, 'Chrome') !== false) {
            $browser = 'Google Chrome';
        } elseif (stripos($ua, 'Firefox') !== false) {
            $browser = 'Mozilla Firefox';
        } elseif (stripos($ua, 'Safari') !== false) {
            $browser = 'Apple Safari';
        } elseif (stripos($ua, 'Opera') !== false || stripos($ua, 'OPR') !== false) {
            $browser = 'Opera';
        }

        return [
            'browser'     => $browser,
            'platform'    => $platform,
            'device_type' => $device_type,
        ];
    }

    /**
     * Map common ISO country codes to readable names with (CC) suffix.
     */
    public static function country_code_to_name(string $code): string {
        $map = [
            'US' => 'United States',
            'GB' => 'United Kingdom',
            'CA' => 'Canada',
            'DE' => 'Germany',
            'FR' => 'France',
            'NL' => 'Netherlands',
            'AU' => 'Australia',
            'JP' => 'Japan',
            'SG' => 'Singapore',
            'IN' => 'India',
            'BR' => 'Brazil',
            'BD' => 'Bangladesh',
            'CN' => 'China',
            'RU' => 'Russia',
            'UA' => 'Ukraine',
            'SE' => 'Sweden',
            'CH' => 'Switzerland',
            'ES' => 'Spain',
            'IT' => 'Italy',
            'PL' => 'Poland',
            'PK' => 'Pakistan',
            'ID' => 'Indonesia',
            'MY' => 'Malaysia',
            'TR' => 'Turkey',
            'AE' => 'United Arab Emirates',
            'SA' => 'Saudi Arabia',
            'EG' => 'Egypt',
            'ZA' => 'South Africa',
            'NZ' => 'New Zealand',
            'IE' => 'Ireland',
            'HK' => 'Hong Kong',
            'KR' => 'South Korea',
            'VN' => 'Vietnam',
            'TH' => 'Thailand',
            'PH' => 'Philippines',
            'RO' => 'Romania',
            'AT' => 'Austria',
            'BE' => 'Belgium',
            'NO' => 'Norway',
            'DK' => 'Denmark',
            'FI' => 'Finland',
            'PT' => 'Portugal',
            'GR' => 'Greece',
            'CZ' => 'Czech Republic',
            'HU' => 'Hungary',
            'IL' => 'Israel',
            'AR' => 'Argentina',
            'CL' => 'Chile',
            'CO' => 'Colombia',
            'MX' => 'Mexico',
        ];
        $upper = strtoupper(trim($code));
        return isset($map[$upper]) ? "{$map[$upper]} ({$upper})" : $upper;
    }

    /**
     * Resolve visitor Country strictly from Cloudflare Edge Headers without third-party APIs.
     *
     * @param string $ip
     * @return array
     */
    public static function get_cloudflare_country(string $ip = ''): array {
        $code = '';
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $code = strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY'])));
        } elseif (!empty($_SERVER['HTTP_CF_CONNECTING_IP_COUNTRY'])) {
            $code = strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP_COUNTRY'])));
        }

        if (!empty($code) && $code !== 'XX' && $code !== 'T1') {
            return [
                'country_code'   => $code,
                'country'        => self::country_code_to_name($code),
                'country_source' => 'Cloudflare Edge (CF-IPCountry)',
                'is_cf'          => true,
            ];
        }

        if ($ip === '127.0.0.1' || $ip === '::1' || (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && \WebCareProScanner\Firewall\FirewallEngine::is_private_ip($ip))) {
            return [
                'country_code'   => 'LAN',
                'country'        => 'Localhost / Internal Network',
                'country_source' => 'Internal IP Scope',
                'is_cf'          => false,
            ];
        }

        return [
            'country_code'   => 'Unknown',
            'country'        => 'Unknown',
            'country_source' => 'Direct Origin (No CF Header)',
            'is_cf'          => false,
        ];
    }

    /**
     * Deduplicate and merge device login records ordered chronologically descending.
     */
    public static function merge_login_records(array $list_a, array $list_b): array {
        $combined = array_merge($list_a, $list_b);
        $seen = [];
        $unique = [];
        foreach ($combined as $rec) {
            if (!is_array($rec)) {
                continue;
            }
            $time_val = (int) ($rec['time'] ?? ($rec['time_raw'] ?? 0));
            $ip_val   = (string) ($rec['ip'] ?? '');
            $sig = "{$time_val}|{$ip_val}";
            if (!isset($seen[$sig])) {
                $seen[$sig] = true;
                $unique[] = $rec;
            }
        }
        usort($unique, function ($x, $y) {
            $tx = (int) ($x['time'] ?? ($x['time_raw'] ?? 0));
            $ty = (int) ($y['time'] ?? ($y['time_raw'] ?? 0));
            return $ty <=> $tx;
        });
        return array_slice($unique, 0, 50);
    }

    /**
     * Deferred cleanup of static pending auth factor attributes on wp_login:99.
     */
    public static function cleanup_pending_auth(): void {
        self::$pending_auth_type    = '';
        self::$pending_auth_label   = '';
        self::$pending_auth_details = [];
    }
}
