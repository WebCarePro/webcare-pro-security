<?php
declare(strict_types=1);

if (!defined('WEBCAREPROSCAN_TESTING')) {
    define('WEBCAREPROSCAN_TESTING', true);
}

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . '/wp-mock/');
}

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

if (!defined('WEEK_IN_SECONDS')) {
    define('WEEK_IN_SECONDS', 604800);
}

if (!defined('MONTH_IN_SECONDS')) {
    define('MONTH_IN_SECONDS', 2592000);
}

if (!defined('YEAR_IN_SECONDS')) {
    define('YEAR_IN_SECONDS', 31536000);
}

if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

if (!defined('OBJECT')) {
    define('OBJECT', 'OBJECT');
}

if (!is_dir(ABSPATH . 'wp-admin/includes')) {
    mkdir(ABSPATH . 'wp-admin/includes', 0755, true);
}
if (!file_exists(ABSPATH . 'wp-admin/includes/plugin.php')) {
    file_put_contents(ABSPATH . 'wp-admin/includes/plugin.php', "<?php\n// mock plugin.php\nif (!function_exists('get_plugins')) { function get_plugins() { return []; } }\n");
}
if (!file_exists(ABSPATH . 'wp-admin/includes/file.php')) {
    file_put_contents(ABSPATH . 'wp-admin/includes/file.php', "<?php\n// mock file.php\nif (!function_exists('WP_Filesystem')) { function WP_Filesystem() { return true; } }\n");
}
if (!file_exists(ABSPATH . 'wp-admin/includes/update.php')) {
    file_put_contents(ABSPATH . 'wp-admin/includes/update.php', "<?php\n// mock update.php\nif (!function_exists('get_core_updates')) { function get_core_updates() { return []; } }\nif (!function_exists('wp_get_translation_updates')) { function wp_get_translation_updates() { return []; } }\n");
}

if (!is_dir(ABSPATH)) {
    mkdir(ABSPATH, 0755, true);
}

// Global mock storage for WordPress functions, transients, and $wpdb
$GLOBALS['wp_mock_options'] = [];
$_SERVER['HTTP_HOST'] = $_SERVER['HTTP_HOST'] ?? 'example.com';
$GLOBALS['wp_mock_transients'] = [];
$GLOBALS['wp_mock_transient_ttls'] = [];
$GLOBALS['wp_mock_transient_expires'] = [];
$GLOBALS['wp_mock_object_cache'] = [];
$GLOBALS['wp_mock_ext_object_cache'] = false;
$GLOBALS['wp_mock_upload_dir'] = sys_get_temp_dir() . '/wp-uploads-mock';
if (!is_dir($GLOBALS['wp_mock_upload_dir'])) {
    mkdir($GLOBALS['wp_mock_upload_dir'], 0755, true);
}

if (!defined('WEBCARE_TESTING')) {
    define('WEBCARE_TESTING', true);
}

if (!function_exists('webcare_purge_test_storage')) {
    function webcare_purge_test_storage(): void {
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wp_mock_transient_ttls'] = [];
        $GLOBALS['wp_mock_transient_expires'] = [];
        $GLOBALS['wp_mock_users'] = [];
        $GLOBALS['wp_mock_user_meta'] = [];
        $GLOBALS['wp_mock_is_multisite'] = false;
        $GLOBALS['wp_mock_current_blog_id'] = 1;
        $GLOBALS['wp_mock_blog_memberships'] = [];
        $GLOBALS['wp_mock_super_admins'] = [];
        $GLOBALS['wp_mock_mails'] = [];
        $GLOBALS['wp_mock_sessions_destroyed'] = [];
        $GLOBALS['wp_mock_http_requests'] = [];
        $GLOBALS['wp_mock_http_callback'] = null;
        $GLOBALS['wp_mock_current_user_can_callback'] = null;
        unset($GLOBALS['wp_mock_current_user_can'], $GLOBALS['wp_mock_current_user']);
        if (class_exists('WebCareProScanner\\System\\SettingsManager') && method_exists('WebCareProScanner\\System\\SettingsManager', 'reset_settings_cache')) {
            \WebCareProScanner\System\SettingsManager::reset_settings_cache();
        }
        $rl_dir = ($GLOBALS['wp_mock_upload_dir'] ?? sys_get_temp_dir() . '/wp-uploads-mock') . '/webcare-pro-security/rate-limits';
        if (is_dir($rl_dir)) {
            $files = glob($rl_dir . '/rl_*.php');
            if (is_array($files)) {
                foreach ($files as $f) {
                    @unlink($f);
                }
            }
        }
    }
}

if (!function_exists('get_option')) {
    function get_option(string $option, $default = false) {
        $filter_hook = 'pre_option_' . $option;
        if (!empty($GLOBALS['wp_mock_filters'][$filter_hook])) {
            $filtered = apply_filters($filter_hook, false, $option, $default);
            if ($filtered !== false) {
                return $filtered;
            }
        }
        return $GLOBALS['wp_mock_options'][$option] ?? $default;
    }
}

if (!function_exists('add_option')) {
    function add_option(string $option, $value = '', string $deprecated = '', $autoload = 'yes'): bool {
        if (isset($GLOBALS['wp_mock_options'][$option])) {
            return false;
        }
        $GLOBALS['wp_mock_options'][$option] = $value;
        return true;
    }
}

if (!function_exists('update_option')) {
    function update_option(string $option, $value, $autoload = null): bool {
        if (isset($GLOBALS['wp_mock_update_option_failures'][$option])) {
            $fail_val = $GLOBALS['wp_mock_update_option_failures'][$option];
            if (is_callable($fail_val)) {
                if ($fail_val($option, $value) === true) {
                    return false;
                }
            } elseif (is_int($fail_val)) {
                if ($fail_val > 0) {
                    $GLOBALS['wp_mock_update_option_failures'][$option]--;
                    return false;
                }
            } elseif (!empty($fail_val)) {
                return false;
            }
        }
        $GLOBALS['wp_mock_options'][$option] = $value;
        return true;
    }
}

if (!function_exists('delete_option')) {
    function delete_option(string $option): bool {
        unset($GLOBALS['wp_mock_options'][$option]);
        return true;
    }
}

if (!function_exists('get_transient')) {
    function get_transient(string $transient) {
        if (isset($GLOBALS['wp_mock_transient_expires'][$transient])) {
            $exp = (int) $GLOBALS['wp_mock_transient_expires'][$transient];
            if ($exp > 0 && $exp <= time()) {
                unset(
                    $GLOBALS['wp_mock_transients'][$transient],
                    $GLOBALS['wp_mock_transient_ttls'][$transient],
                    $GLOBALS['wp_mock_transient_expires'][$transient]
                );
                return false;
            }
        }
        return $GLOBALS['wp_mock_transients'][$transient] ?? false;
    }
}

if (!function_exists('set_transient')) {
    function set_transient(string $transient, $value, int $expiration = 0): bool {
        $GLOBALS['wp_mock_transients'][$transient] = $value;
        $GLOBALS['wp_mock_transient_ttls'][$transient] = $expiration;
        $GLOBALS['wp_mock_transient_expires'][$transient] = $expiration > 0 ? (time() + $expiration) : 0;
        return true;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient(string $transient): bool {
        unset(
            $GLOBALS['wp_mock_transients'][$transient],
            $GLOBALS['wp_mock_transient_ttls'][$transient],
            $GLOBALS['wp_mock_transient_expires'][$transient]
        );
        return true;
    }
}

if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir(): array {
        return [
            'basedir' => $GLOBALS['wp_mock_upload_dir'],
            'baseurl' => 'https://example.test/wp-content/uploads',
        ];
    }
}

if (!function_exists('trailingslashit')) {
    function trailingslashit(string $string): string {
        return rtrim($string, '/\\') . '/';
    }
}

if (!function_exists('untrailingslashit')) {
    function untrailingslashit(string $string): string {
        return rtrim($string, '/\\');
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error {
        protected array $errors = [];
        protected array $error_data = [];

        public function __construct(string|int $code = '', string $message = '', mixed $data = '') {
            if (!empty($code)) {
                $this->errors[$code][] = $message;
                if (!empty($data)) {
                    $this->error_data[$code] = $data;
                }
            }
        }

        public function get_error_code(): string|int|null {
            $codes = array_keys($this->errors);
            return empty($codes) ? null : $codes[0];
        }

        public function get_error_message(string|int $code = ''): string {
            if (empty($code)) {
                $code = $this->get_error_code();
            }
            return !empty($this->errors[$code][0]) ? $this->errors[$code][0] : '';
        }

        public function get_error_data(string|int $code = ''): mixed {
            if (empty($code)) {
                $code = $this->get_error_code();
            }
            return $this->error_data[$code] ?? null;
        }
    }
}

if (!function_exists('wp_date')) {
    function wp_date(string $format, ?int $timestamp = null, ?\DateTimeZone $timezone = null): string {
        $timestamp = $timestamp ?? time();
        return date($format, $timestamp);
    }
}

if (!function_exists('is_ssl')) {
    function is_ssl(): bool {
        return !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';
    }
}

if (!function_exists('home_url')) {
    function home_url(string $path = '', ?string $scheme = null): string {
        return 'http://example.com' . ($path ? '/' . ltrim($path, '/') : '');
    }
}

if (!function_exists('site_url')) {
    function site_url(string $path = '', ?string $scheme = null): string {
        return 'http://example.com' . ($path ? '/' . ltrim($path, '/') : '');
    }
}

if (!function_exists('get_site_url')) {
    function get_site_url(?int $blog_id = null, string $path = '', ?string $scheme = null): string {
        return site_url($path, $scheme);
    }
}

if (!function_exists('wp_max_upload_size')) {
    function wp_max_upload_size(): int {
        return 134217728;
    }
}

if (!function_exists('is_multisite')) {
    function is_multisite(): bool {
        return !empty($GLOBALS['wp_mock_is_multisite']);
    }
}

if (!function_exists('get_current_blog_id')) {
    function get_current_blog_id(): int {
        return (int) ($GLOBALS['wp_mock_current_blog_id'] ?? 1);
    }
}

if (!function_exists('is_super_admin')) {
    function is_super_admin(?int $user_id = null): bool {
        $uid = $user_id ?? get_current_user_id();
        return !empty($GLOBALS['wp_mock_super_admins'][$uid]);
    }
}

if (!function_exists('is_user_member_of_blog')) {
    function is_user_member_of_blog(int $user_id = 0, int $blog_id = 0): bool {
        $bid = $blog_id ?: get_current_blog_id();
        $members = $GLOBALS['wp_mock_blog_memberships'][$bid] ?? [];
        return !empty($members[$user_id]);
    }
}

if (!function_exists('get_current_user_id')) {
    function get_current_user_id(): int {
        return !empty($GLOBALS['wp_mock_current_user']) ? (int) $GLOBALS['wp_mock_current_user']->ID : 0;
    }
}

if (!function_exists('wp_get_session_token')) {
    function wp_get_session_token(): string {
        return '';
    }
}

if (!class_exists('WP_User')) {
    class WP_User {
        public int $ID = 0;
        public string $user_login = '';
        public string $user_email = '';
        public string $display_name = '';
        public array $roles = [];
        public array $allcaps = [];
        public function __construct(int $id = 0, string $name = '') {
            $this->ID = $id;
            $this->user_login = $name ?: 'user_' . $id;
            $this->user_email = $this->user_login . '@example.com';
            $this->display_name = $this->user_login;
        }
        public function exists(): bool {
            return $this->ID > 0;
        }
        public function has_cap(string $cap): bool {
            return !empty($this->allcaps[$cap]) || in_array($cap, $this->roles, true);
        }
    }
}

if (!function_exists('wp_set_current_user')) {
    function wp_set_current_user(int $id, string $name = '') {
        $user = new WP_User($id, $name);
        $GLOBALS['wp_mock_current_user'] = $user;
        return $user;
    }
}

if (!function_exists('is_user_logged_in')) {
    function is_user_logged_in(): bool {
        return !empty($GLOBALS['wp_mock_current_user']) && $GLOBALS['wp_mock_current_user']->ID > 0;
    }
}

if (!function_exists('get_userdata')) {
    function get_userdata(int $user_id) {
        if (isset($GLOBALS['wp_mock_users'][$user_id])) {
            return $GLOBALS['wp_mock_users'][$user_id];
        }
        if (!empty($GLOBALS['wp_mock_current_user']) && $GLOBALS['wp_mock_current_user']->ID === $user_id) {
            return $GLOBALS['wp_mock_current_user'];
        }
        return false;
    }
}

if (!function_exists('get_user_by')) {
    function get_user_by(string $field, int|string $value) {
        if ($field === 'id' || $field === 'ID') {
            return get_userdata((int) $value);
        }
        foreach (($GLOBALS['wp_mock_users'] ?? []) as $u) {
            if ($field === 'login' && ($u->user_login ?? '') === $value) {
                return $u;
            }
            if ($field === 'email' && ($u->user_email ?? '') === $value) {
                return $u;
            }
        }
        return false;
    }
}

if (!function_exists('get_user_meta')) {
    function get_user_meta(int $user_id, string $key = '', bool $single = false) {
        $all = $GLOBALS['wp_mock_user_meta'][$user_id] ?? [];
        if ($key === '') {
            return $all;
        }
        if (!array_key_exists($key, $all)) {
            return $single ? '' : [];
        }
        return $single ? $all[$key] : [$all[$key]];
    }
}

if (!function_exists('update_user_meta')) {
    function update_user_meta(int $user_id, string $meta_key, mixed $meta_value, mixed $prev_value = ''): int|bool {
        $GLOBALS['wp_mock_user_meta'][$user_id][$meta_key] = $meta_value;
        return true;
    }
}

if (!function_exists('delete_user_meta')) {
    function delete_user_meta(int $user_id, string $meta_key, mixed $meta_value = ''): bool {
        unset($GLOBALS['wp_mock_user_meta'][$user_id][$meta_key]);
        return true;
    }
}

if (!function_exists('user_can')) {
    function user_can(int|\WP_User $user, string $capability, mixed ...$args): bool {
        $user_obj = $user instanceof WP_User ? $user : get_userdata((int) $user);
        if (!$user_obj instanceof WP_User) {
            return false;
        }
        return $user_obj->has_cap($capability);
    }
}

if (!function_exists('wp_get_current_user')) {
    function wp_get_current_user() {
        if (isset($GLOBALS['wp_mock_current_user'])) {
            return $GLOBALS['wp_mock_current_user'];
        }
        return new class {
            public int $ID = 0;
            public string $user_login = 'mock_user';
            public array $roles = [];
            public array $allcaps = [];
            public function exists(): bool {
                return false;
            }
        };
    }
}

if (!function_exists('get_users')) {
    function get_users(array $args = []): array {
        return [];
    }
}

if (!function_exists('wp_version_check')) {
    function wp_version_check(): void {}
}
if (!function_exists('wp_update_plugins')) {
    function wp_update_plugins(): void {}
}
if (!function_exists('wp_update_themes')) {
    function wp_update_themes(): void {}
}

if (!function_exists('wp_get_themes')) {
    function wp_get_themes(array $args = []): array {
        if (!empty($GLOBALS['wp_mock_themes'])) {
            return $GLOBALS['wp_mock_themes'];
        }
        return [
            'mock-theme' => wp_get_theme(),
        ];
    }
}

if (!function_exists('get_mu_plugins')) {
    function get_mu_plugins(): array {
        return $GLOBALS['wp_mock_mu_plugins'] ?? [];
    }
}

if (!function_exists('get_dropins')) {
    function get_dropins(): array {
        return $GLOBALS['wp_mock_dropins'] ?? [
            'advanced-cache.php' => ['Name' => 'Advanced Cache Drop-in'],
        ];
    }
}

if (!function_exists('wp_get_theme')) {
    function wp_get_theme() {
        return new class {
            public function get(string $header) {
                return $header === 'Name' ? 'Mock Theme' : ($header === 'Version' ? '1.0.0' : '');
            }
            public function get_template(): string {
                return 'mock-theme';
            }
            public function get_stylesheet(): string {
                return 'mock-theme';
            }
            public function exists(): bool {
                return true;
            }
            public function parent() {
                return false;
            }
        };
    }
}

if (!function_exists('get_template')) {
    function get_template(): string {
        return 'mock-theme';
    }
}

if (!function_exists('get_stylesheet')) {
    function get_stylesheet(): string {
        return 'mock-theme';
    }
}

if (!function_exists('wp_normalize_path')) {
    function wp_normalize_path(string $path): string {
        $path = str_replace('\\', '/', $path);
        return (string) preg_replace('|(?<=.)/+|', '/', $path);
    }
}

if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p(string $target): bool {
        if (is_dir($target)) {
            return true;
        }
        return @mkdir($target, 0755, true);
    }
}

if (!function_exists('wp_rand')) {
    function wp_rand(int $min = 0, int $max = 0): int {
        return random_int($min !== 0 ? $min : 0, $max ?: 999999);
    }
}

if (!function_exists('wp_generate_password')) {
    function wp_generate_password(int $length = 12, bool $special_chars = true, bool $extra_special_chars = false): string {
        return bin2hex(random_bytes((int) ceil($length / 2)));
    }
}

if (!function_exists('get_site_transient')) {
    function get_site_transient(string $transient) {
        return get_transient($transient);
    }
}

if (!function_exists('set_site_transient')) {
    function set_site_transient(string $transient, $value, int $expiration = 0): bool {
        return set_transient($transient, $value, $expiration);
    }
}

if (!function_exists('delete_site_transient')) {
    function delete_site_transient(string $transient): bool {
        return delete_transient($transient);
    }
}

if (!function_exists('admin_url')) {
    function admin_url(string $path = ''): string {
        return 'http://example.com/wp-admin/' . ltrim($path, '/');
    }
}

if (!function_exists('add_query_arg')) {
    function add_query_arg(...$args): string {
        if (count($args) === 2 && is_array($args[0]) && is_string($args[1])) {
            $query = http_build_query($args[0]);
            $sep = str_contains($args[1], '?') ? '&' : '?';
            return $query !== '' ? $args[1] . $sep . $query : $args[1];
        }
        return 'http://example.com/wp-admin/admin.php';
    }
}

if (!function_exists('wp_remote_head')) {
    function wp_remote_head(string $url, array $args = []): array {
        return ['response' => ['code' => 404]];
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error(mixed $thing): bool {
        return $thing instanceof WP_Error;
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code(mixed $response): int {
        return (int) ($response['response']['code'] ?? 200);
    }
}

if (!function_exists('wp_remote_get')) {
    function wp_remote_get(string $url, array $args = []): array {
        return ['response' => ['code' => 404], 'body' => ''];
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body(mixed $response): string {
        return (string) ($response['body'] ?? '');
    }
}

if (!function_exists('wp_strip_all_tags')) {
    function wp_strip_all_tags(string $text, bool $remove_breaks = false): string {
        $text = preg_replace('@<(script|style)[^>]*?>.*?</\\1>@si', '', $text);
        $text = strip_tags($text);
        if ($remove_breaks) {
            $text = preg_replace('/[\r\n\t ]+/', ' ', $text);
        }
        return trim($text);
    }
}

if (!function_exists('wp_salt')) {
    function wp_salt(string $scheme = 'auth'): string {
        return 'test-salt-' . $scheme . '-key-material-2026';
    }
}

if (!function_exists('wp_delete_file')) {
    function wp_delete_file(string $file): void {
        $filtered = function_exists('apply_filters') ? (string) apply_filters('wp_delete_file', $file) : $file;
        if ($filtered !== '' && file_exists($filtered)) {
            @unlink($filtered);
        }
    }
}

if (!function_exists('wp_specialchars_decode')) {
    function wp_specialchars_decode(string $string, int|string $quote_style = ENT_NOQUOTES): string {
        $flags = is_int($quote_style) ? $quote_style : ENT_QUOTES;
        return html_entity_decode($string, $flags, 'UTF-8');
    }
}

if (!function_exists('status_header')) {
    function status_header(int $code, string $description = ''): void {
        $GLOBALS['wp_mock_last_status_header'] = $code;
    }
}

if (!function_exists('wp_parse_url')) {
    function wp_parse_url(string $url, int $component = -1) {
        return parse_url($url, $component);
    }
}

if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data, int $options = 0, int $depth = 512) {
        return json_encode($data, $options, $depth);
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string {
        return trim(strip_tags($str));
    }
}

if (!function_exists('sanitize_title')) {
    function sanitize_title(string $title, string $fallback_title = '', string $context = 'save'): string {
        $clean = preg_replace('/[^a-zA-Z0-9_\-\.]/', '-', $title);
        $clean = strtolower(trim((string) $clean, '-'));
        return $clean ?: $fallback_title;
    }
}

if (!function_exists('sanitize_key')) {
    function sanitize_key(string $key): string {
        return preg_replace('/[^a-z0-9_\\-]/', '', strtolower($key));
    }
}

if (!function_exists('sanitize_user')) {
    function sanitize_user(string $username, bool $strict = false): string {
        $username = trim(strip_tags($username));
        if ($strict) {
            $username = preg_replace('|[^a-z0-9 _.\-@]|i', '', $username);
        }
        return preg_replace('|\s+|', ' ', (string) $username);
    }
}

if (!function_exists('esc_attr')) {
    function esc_attr(string $text): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_html')) {
    function esc_html(string $text): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_html_e')) {
    function esc_html_e(string $text, string $domain = 'default'): void {
        echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_attr__')) {
    function esc_attr__(string $text, string $domain = 'default'): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_attr_e')) {
    function esc_attr_e(string $text, string $domain = 'default'): void {
        echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('number_format_i18n')) {
    function number_format_i18n(float $number, int $decimals = 0): string {
        return number_format($number, $decimals);
    }
}

if (!function_exists('esc_url_raw')) {
    function esc_url_raw(string $url): string {
        return filter_var($url, FILTER_SANITIZE_URL) ?: '';
    }
}

if (!function_exists('wp_unslash')) {
    function wp_unslash($value) {
        return is_string($value) ? stripslashes($value) : $value;
    }
}

if (!function_exists('current_time')) {
    function current_time(string $type, bool $gmt = false) {
        return $type === 'mysql' ? gmdate('Y-m-d H:i:s') : time();
    }
}

if (!function_exists('size_format')) {
    function size_format(int|float $bytes, int $decimals = 0): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = $bytes > 0 ? floor(log($bytes, 1024)) : 0;
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, $decimals) . ' ' . $units[$pow];
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can(string $capability, ...$args): bool {
        if (!empty($GLOBALS['wp_mock_current_user_can_callback']) && is_callable($GLOBALS['wp_mock_current_user_can_callback'])) {
            return (bool) call_user_func($GLOBALS['wp_mock_current_user_can_callback'], $capability, ...$args);
        }
        if (isset($GLOBALS['wp_mock_current_user_can'])) {
            return (bool) $GLOBALS['wp_mock_current_user_can'];
        }
        if (!empty($GLOBALS['wp_mock_current_user']) && method_exists($GLOBALS['wp_mock_current_user'], 'has_cap')) {
            return $GLOBALS['wp_mock_current_user']->has_cap($capability);
        }
        return false;
    }
}

if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string {
        return $text;
    }
}

if (!function_exists('maybe_serialize')) {
    function maybe_serialize($data) {
        if (is_array($data) || is_object($data)) {
            return serialize($data);
        }
        return $data;
    }
}

if (!function_exists('maybe_unserialize')) {
    function maybe_unserialize($data) {
        if (is_string($data)) {
            $unserialized = @unserialize($data);
            if ($unserialized !== false || $data === 'b:0;') {
                return $unserialized;
            }
        }
        return $data;
    }
}

// Mock minimal WP_REST_Request class if not loaded
if (!class_exists('WP_REST_Request')) {
    class WP_REST_Request {
        private array $headers = [];
        private array $params = [];
        private string $body = '';
        private ?array $json_params = null;
        public string $method = 'GET';
        public string $route = '';

        public function __construct(string|array $methodOrHeaders = 'GET', string $route = '', array $attributes = []) {
            if (is_array($methodOrHeaders)) {
                foreach ($methodOrHeaders as $k => $v) {
                    $this->headers[strtolower($k)] = $v;
                }
            } else {
                $this->method = strtoupper($methodOrHeaders);
                $this->route = $route;
            }
        }

        public function get_header(string $key): ?string {
            return $this->headers[strtolower($key)] ?? null;
        }

        public function set_header(string $key, string $value): void {
            $this->headers[strtolower($key)] = $value;
        }

        public function set_body(string $body): void {
            $this->body = $body;
            $decoded = json_decode($body, true);
            if (is_array($decoded)) {
                $this->json_params = $decoded;
                $this->params = array_merge($this->params, $decoded);
            }
        }

        public function get_body(): string {
            return $this->body;
        }

        public function get_json_params(): array {
            return $this->json_params ?? [];
        }

        public function set_param(string $key, mixed $value): void {
            $this->params[$key] = $value;
        }

        public function get_param(string $key): mixed {
            return $this->params[$key] ?? null;
        }

        public function get_params(): array {
            return $this->params;
        }

        public function get_route(): string {
            return $this->route;
        }

        public function set_route(string $route): void {
            $this->route = $route;
        }
    }
}

if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response {
        private mixed $data = null;
        private int $status = 200;
        private array $headers = [];

        public function __construct(mixed $data = null, int $status = 200, array $headers = []) {
            $this->data = $data;
            $this->status = $status;
            $this->headers = $headers;
        }

        public function get_data(): mixed {
            return $this->data;
        }

        public function set_data(mixed $data): void {
            $this->data = $data;
        }

        public function get_status(): int {
            return $this->status;
        }

        public function set_status(int $status): void {
            $this->status = $status;
        }

        public function get_headers(): array {
            return $this->headers;
        }
    }
}

// Mock minimal wpdb class if not loaded
if (!class_exists('wpdb')) {
    #[\AllowDynamicProperties]
    class wpdb {
        public string $prefix = 'wp_';
        public int $insert_id = 0;
        public array $queries = [];
        public array $mock_tables = [];
        public $mock_get_var_callback = null;
        public array $tx_undo_stack = [];
        public ?string $mock_options_engine = 'InnoDB';
        public array $mock_table_engines = [];

        private function record_tx_option_undo(string $optKey): void {
            if (empty($this->tx_undo_stack)) {
                return;
            }
            $topIdx = count($this->tx_undo_stack) - 1;
            if (!array_key_exists($optKey, $this->tx_undo_stack[$topIdx])) {
                $existed = array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []);
                $this->tx_undo_stack[$topIdx][$optKey] = [
                    'existed' => $existed,
                    'value'   => $existed ? $GLOBALS['wp_mock_options'][$optKey] : null,
                ];
            }
        }

        private function check_mock_option_failure(string $optKey, mixed $value): bool {
            if (!isset($GLOBALS['wp_mock_update_option_failures'][$optKey])) {
                return false;
            }
            $failVal = $GLOBALS['wp_mock_update_option_failures'][$optKey];
            if (is_callable($failVal)) {
                return ($failVal($optKey, $value) === true);
            }
            if (is_int($failVal)) {
                if ($failVal > 0) {
                    $GLOBALS['wp_mock_update_option_failures'][$optKey]--;
                    return true;
                }
                return false;
            }
            return !empty($failVal);
        }

        public function esc_like(string $text): string {
            return addcslashes($text, '_%\\');
        }

        public function get_col(string $query): array {
            $this->queries[] = $query;
            return [];
        }

        public function prepare(string $query, ...$args): string {
            $escapedArgs = array_map(
                static fn($a) => is_string($a) ? str_replace("'", "\\'", $a) : $a,
                $args
            );
            return vsprintf(str_replace(['%s', '%d', '%i'], ["'%s'", '%d', '`%s`'], $query), $escapedArgs);
        }

        public function get_var(string $query) {
            $this->queries[] = $query;
            if (is_callable($this->mock_get_var_callback)) {
                return ($this->mock_get_var_callback)($query);
            }
            if (!empty($this->options)) {
                if (preg_match("/SELECT\s+ENGINE\s+FROM\s+information_schema\.TABLES\s+WHERE.*TABLE_NAME\s*=\s*'((?:\\\\'|[^'])+)'/is", $query, $emTbl)) {
                    $queriedTbl = str_replace("\\'", "'", $emTbl[1]);
                    if (array_key_exists($queriedTbl, $this->mock_table_engines)) {
                        return $this->mock_table_engines[$queriedTbl];
                    }
                    return $this->mock_options_engine;
                }

                // SELECT option_value FROM wp_options WHERE option_name = '...' AND option_value LIKE '...%' AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= N [LIMIT 1] [FOR UPDATE]
                if (preg_match("/SELECT\s+option_value\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s+LIKE\s+'((?:\\\\'|[^'])*)%'\s+AND\s+CAST\(SUBSTRING_INDEX\(option_value,\s*'\|',\s*-1\)\s+AS\s+UNSIGNED\)\s*>=\s*(\d+)/is", $query, $lm)) {
                    $optKey = str_replace("\\'", "'", $lm[1]);
                    $prefix = stripslashes(str_replace("\\'", "'", $lm[2]));
                    $minExp = (int) $lm[3];
                    if (!array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? [])) {
                        return null;
                    }
                    $rawVal = (string) maybe_serialize($GLOBALS['wp_mock_options'][$optKey]);
                    if (!str_starts_with($rawVal, $prefix) || !str_contains($rawVal, '|')) {
                        return null;
                    }
                    $exp = (int) substr((string) strrchr($rawVal, '|'), 1);
                    return ($exp >= $minExp) ? $rawVal : null;
                }

                // SELECT option_value FROM wp_options WHERE option_name = '...' AND option_value = '...' AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) >= N [LIMIT 1] [FOR UPDATE]
                if (preg_match("/SELECT\s+option_value\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s+AND\s+CAST\(SUBSTRING_INDEX\(option_value,\s*'\|',\s*-1\)\s+AS\s+UNSIGNED\)\s*>=\s*(\d+)/is", $query, $em)) {
                    $optKey = str_replace("\\'", "'", $em[1]);
                    $expVal = str_replace("\\'", "'", $em[2]);
                    $minExp = (int) $em[3];
                    if (!array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? [])) {
                        return null;
                    }
                    $rawVal = (string) maybe_serialize($GLOBALS['wp_mock_options'][$optKey]);
                    if ($rawVal !== $expVal || !str_contains($rawVal, '|')) {
                        return null;
                    }
                    $exp = (int) substr((string) strrchr($rawVal, '|'), 1);
                    return ($exp >= $minExp) ? $rawVal : null;
                }

                if (preg_match("/SELECT\s+option_value\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'/is", $query, $sm)) {
                    $optKey = str_replace("\\'", "'", $sm[1]);
                    return array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? [])
                        ? (string) maybe_serialize($GLOBALS['wp_mock_options'][$optKey])
                        : null;
                }
            }
            return null;
        }

        public function get_row(string $query, string $output = 'OBJECT') {
            $this->queries[] = $query;
            return null;
        }

        public function get_results(string $query, string $output = 'OBJECT') {
            $this->queries[] = $query;
            return [];
        }

        public function insert(string $table, array $data, ?array $format = null) {
            $this->queries[] = "INSERT INTO {$table}";
            if (!isset($this->mock_tables[$table])) {
                $this->mock_tables[$table] = [];
            }
            $id = count($this->mock_tables[$table]) + 1;
            $data['id'] = $data['id'] ?? $id;
            $this->mock_tables[$table][$data['id']] = $data;
            return 1;
        }

        public function update(string $table, array $data, array $where, ?array $format = null, ?array $where_format = null) {
            $this->queries[] = "UPDATE {$table}";
            if (isset($this->mock_tables[$table])) {
                foreach ($where as $wKey => $wVal) {
                    if (isset($this->mock_tables[$table][$wVal])) {
                        $this->mock_tables[$table][$wVal] = array_merge($this->mock_tables[$table][$wVal], $data);
                    }
                }
            }
            return 1;
        }

        public function delete(string $table, array $where, ?array $where_format = null) {
            $this->queries[] = "DELETE FROM {$table}";
            if (isset($this->mock_tables[$table])) {
                foreach ($where as $wKey => $wVal) {
                    unset($this->mock_tables[$table][$wVal]);
                }
            }
            return 1;
        }

        public function query(string $query) {
            $this->queries[] = $query;

            $trimmedUpper = strtoupper(trim($query));
            if ($trimmedUpper === 'START TRANSACTION') {
                $this->tx_undo_stack[] = [];
                return 1;
            }
            if ($trimmedUpper === 'COMMIT') {
                if (!empty($this->tx_undo_stack)) {
                    array_pop($this->tx_undo_stack);
                }
                return 1;
            }
            if ($trimmedUpper === 'ROLLBACK') {
                if (!empty($this->tx_undo_stack)) {
                    $undoFrame = array_pop($this->tx_undo_stack);
                    foreach ($undoFrame as $optKey => $prior) {
                        if ($prior['existed']) {
                            $GLOBALS['wp_mock_options'][$optKey] = $prior['value'];
                        } else {
                            unset($GLOBALS['wp_mock_options'][$optKey]);
                        }
                    }
                }
                return 1;
            }

            if (!empty($this->options)) {
                // Simulate INSERT IGNORE INTO wp_options (option_name, option_value, autoload) VALUES ('...', '...', 'no')
                if (preg_match("/INSERT\s+IGNORE\s+INTO\s+\S+\s*\(\s*option_name\s*,\s*option_value\s*,\s*autoload\s*\)\s*VALUES\s*\('((?:\\\\'|[^'])+)',\s*'((?:\\\\'|[^'])*)',\s*'[^']*'\)/is", $query, $im)) {
                    $optKey = str_replace("\\'", "'", $im[1]);
                    $rawVal = str_replace("\\'", "'", $im[2]);
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? [])) {
                        return 0;
                    }
                    $this->record_tx_option_undo($optKey);
                    $GLOBALS['wp_mock_options'][$optKey] = maybe_unserialize($rawVal);
                    return 1;
                }

                // Simulate AtomicNonceStore INSERT ... ON DUPLICATE KEY UPDATE option_value = IF(CAST(...) < N, ...)
                if (preg_match("/INSERT\s+INTO\s+\S+\s*\(\s*option_name\s*,\s*option_value\s*,\s*autoload\s*\)\s*VALUES\s*\('([^']+)',\s*'([^']+)',\s*'no'\)\s*ON\s+DUPLICATE\s+KEY\s+UPDATE\s*option_value\s*=\s*IF\(CAST\(option_value\s+AS\s+UNSIGNED\)\s*<\s*(\d+)/is", $query, $m)) {
                    $optKey = $m[1];
                    $newVal = $m[2];
                    $nowTs  = (int) $m[3];
                    if (!isset($GLOBALS['wp_mock_options'][$optKey])) {
                        $this->record_tx_option_undo($optKey);
                        $GLOBALS['wp_mock_options'][$optKey] = $newVal;
                        return 1;
                    }
                    $curExp = (int) $GLOBALS['wp_mock_options'][$optKey];
                    if ($curExp < $nowTs) {
                        $this->record_tx_option_undo($optKey);
                        $GLOBALS['wp_mock_options'][$optKey] = $newVal;
                        return 2;
                    }
                    return 0;
                }

                // Simulate transactional_upsert_option INSERT INTO wp_options ... ON DUPLICATE KEY UPDATE option_value = '...', autoload = '...'
                if (preg_match("/INSERT\s+INTO\s+\S+\s*\(\s*option_name\s*,\s*option_value\s*,\s*autoload\s*\)\s*VALUES\s*\('((?:\\\\'|[^'])+)',\s*'((?:\\\\'|[^'])*)',\s*'[^']*'\)\s*ON\s+DUPLICATE\s+KEY\s+UPDATE\s+option_value\s*=\s*'((?:\\\\'|[^'])*)',\s*autoload\s*=\s*'[^']*'/is", $query, $upm)) {
                    $optKey = str_replace("\\'", "'", $upm[1]);
                    $rawVal = str_replace("\\'", "'", $upm[2]);
                    $parsedVal = maybe_unserialize($rawVal);
                    if ($this->check_mock_option_failure($optKey, $parsedVal)) {
                        return false;
                    }
                    $existed = array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []);
                    $this->record_tx_option_undo($optKey);
                    $GLOBALS['wp_mock_options'][$optKey] = $parsedVal;
                    return $existed ? 2 : 1;
                }

                // Simulate AtomicNonceStore bounded DELETE ... LIMIT against $GLOBALS['wp_mock_options']
                if (preg_match("/DELETE\s+FROM\s+\S+\s+WHERE\s+option_name\s+LIKE\s+'[^']+'\s+AND\s+option_name\s+NOT\s+IN\s*\('([^']+)',\s*'([^']+)'\).*CAST\(option_value\s+AS\s+UNSIGNED\)\s*<\s*(\d+)\s+LIMIT\s+(\d+)/is", $query, $dm)) {
                    $excl1  = $dm[1];
                    $excl2  = $dm[2];
                    $nowTs  = (int) $dm[3];
                    $limitN = (int) $dm[4];
                    $deleted = 0;
                    foreach (array_keys($GLOBALS['wp_mock_options'] ?? []) as $optName) {
                        if ($deleted >= $limitN) {
                            break;
                        }
                        $k = (string) $optName;
                        if (!str_starts_with($k, 'wcp_nonce_') || $k === $excl1 || $k === $excl2) {
                            continue;
                        }
                        $v = $GLOBALS['wp_mock_options'][$k] ?? null;
                        if ((is_int($v) || (is_string($v) && ctype_digit($v))) && (int) $v > 0 && (int) $v < $nowTs) {
                            $this->record_tx_option_undo($k);
                            unset($GLOBALS['wp_mock_options'][$k]);
                            $deleted++;
                        }
                    }
                    return $deleted;
                }

                // Simulate SQL-expiry-enforced stale-lock compare-and-delete
                if (preg_match("/DELETE\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s+AND\s+CAST\(SUBSTRING_INDEX\(option_value,\s*'\|',\s*-1\)\s+AS\s+UNSIGNED\)\s*>\s*0\s+AND\s+CAST\(SUBSTRING_INDEX\(option_value,\s*'\|',\s*-1\)\s+AS\s+UNSIGNED\)\s*<\s*(\d+)/is", $query, $scdm)) {
                    $optKey = str_replace("\\'", "'", $scdm[1]);
                    $expVal = str_replace("\\'", "'", $scdm[2]);
                    $maxExp = (int) $scdm[3];
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []) && (string) $GLOBALS['wp_mock_options'][$optKey] === $expVal && str_contains($expVal, '|')) {
                        $expTs = (int) substr((string) strrchr($expVal, '|'), 1);
                        if ($expTs > 0 && $expTs < $maxExp) {
                            $this->record_tx_option_undo($optKey);
                            unset($GLOBALS['wp_mock_options'][$optKey]);
                            return 1;
                        }
                    }
                    return 0;
                }

                // Simulate atomic compare-and-delete: DELETE FROM wp_options WHERE option_name = '...' AND option_value = '...'
                if (preg_match("/DELETE\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s*$/is", $query, $cdm)) {
                    $optKey = str_replace("\\'", "'", $cdm[1]);
                    $expVal = str_replace("\\'", "'", $cdm[2]);
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []) && (string) $GLOBALS['wp_mock_options'][$optKey] === $expVal) {
                        $this->record_tx_option_undo($optKey);
                        unset($GLOBALS['wp_mock_options'][$optKey]);
                        return 1;
                    }
                    return 0;
                }

                // Simulate atomic prefix compare-and-delete: DELETE FROM wp_options WHERE option_name = '...' AND option_value LIKE '...%'
                if (preg_match("/DELETE\s+FROM\s+\S+\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s+LIKE\s+'((?:\\\\'|[^'])*)%'/is", $query, $ldm)) {
                    $optKey = str_replace("\\'", "'", $ldm[1]);
                    $prefix = stripslashes(str_replace("\\'", "'", $ldm[2]));
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []) && str_starts_with((string) $GLOBALS['wp_mock_options'][$optKey], $prefix)) {
                        $this->record_tx_option_undo($optKey);
                        unset($GLOBALS['wp_mock_options'][$optKey]);
                        return 1;
                    }
                    return 0;
                }

                // Simulate SQL-expiry-enforced compare-and-swap renewal: UPDATE wp_options SET option_value = '...' WHERE option_name = '...' AND option_value = '...' AND CAST(SUBSTRING_INDEX(...)) >= N
                if (preg_match("/UPDATE\s+\S+\s+SET\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s+AND\s+CAST\(SUBSTRING_INDEX\(option_value,\s*'\|',\s*-1\)\s+AS\s+UNSIGNED\)\s*>=\s*(\d+)/is", $query, $sum)) {
                    $newVal = str_replace("\\'", "'", $sum[1]);
                    $optKey = str_replace("\\'", "'", $sum[2]);
                    $expVal = str_replace("\\'", "'", $sum[3]);
                    $minExp = (int) $sum[4];
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []) && (string) $GLOBALS['wp_mock_options'][$optKey] === $expVal && str_contains($expVal, '|')) {
                        $curExp = (int) substr((string) strrchr($expVal, '|'), 1);
                        if ($curExp >= $minExp && $newVal !== $expVal) {
                            $this->record_tx_option_undo($optKey);
                            $GLOBALS['wp_mock_options'][$optKey] = $newVal;
                            return 1;
                        }
                    }
                    return 0;
                }

                // Simulate atomic compare-and-swap: UPDATE wp_options SET option_value = '...' WHERE option_name = '...' AND option_value = '...'
                if (preg_match("/UPDATE\s+\S+\s+SET\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s+WHERE\s+option_name\s*=\s*'((?:\\\\'|[^'])+)'\s+AND\s+option_value\s*=\s*'((?:\\\\'|[^'])*)'\s*$/is", $query, $um)) {
                    $newVal = str_replace("\\'", "'", $um[1]);
                    $optKey = str_replace("\\'", "'", $um[2]);
                    $expVal = str_replace("\\'", "'", $um[3]);
                    if (array_key_exists($optKey, $GLOBALS['wp_mock_options'] ?? []) && (string) $GLOBALS['wp_mock_options'][$optKey] === $expVal) {
                        if ($newVal === $expVal) {
                            return 0;
                        }
                        $this->record_tx_option_undo($optKey);
                        $GLOBALS['wp_mock_options'][$optKey] = $newVal;
                        return 1;
                    }
                    return 0;
                }
            }

            return 1;
        }

        public function db_version(): string {
            return '8.0.36';
        }
    }
}

$GLOBALS['wp_mock_filters'] = [];

if (!function_exists('add_filter')) {
    function add_filter(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): bool {
        $GLOBALS['wp_mock_filters'][$hook_name][] = $callback;
        return true;
    }
}

if (!function_exists('apply_filters')) {
    function apply_filters(string $hook_name, $value, ...$args) {
        if (!empty($GLOBALS['wp_mock_filters'][$hook_name])) {
            foreach ($GLOBALS['wp_mock_filters'][$hook_name] as $cb) {
                $value = $cb($value, ...$args);
            }
        }
        return $value;
    }
}

if (!function_exists('rest_ensure_response')) {
    function rest_ensure_response(mixed $response): mixed {
        return $response;
    }
}

if (!function_exists('remove_filter')) {
    function remove_filter(string $hook_name, callable $callback, int $priority = 10): bool {
        if (!empty($GLOBALS['wp_mock_filters'][$hook_name])) {
            foreach ($GLOBALS['wp_mock_filters'][$hook_name] as $idx => $cb) {
                if ($cb === $callback) {
                    unset($GLOBALS['wp_mock_filters'][$hook_name][$idx]);
                }
            }
            $GLOBALS['wp_mock_filters'][$hook_name] = array_values($GLOBALS['wp_mock_filters'][$hook_name]);
        }
        return true;
    }
}

if (!function_exists('remove_all_filters')) {
    function remove_all_filters(string $hook_name, $priority = false): bool {
        unset($GLOBALS['wp_mock_filters'][$hook_name]);
        return true;
    }
}

if (!function_exists('did_action')) {
    function did_action(string $hook_name): int {
        return 0;
    }
}

$GLOBALS['wp_mock_actions'] = [];

if (!function_exists('add_action')) {
    function add_action(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): bool {
        $GLOBALS['wp_mock_actions'][$hook_name][] = $callback;
        return true;
    }
}

if (!function_exists('remove_all_actions')) {
    function remove_all_actions(string $hook_name, $priority = false): bool {
        unset($GLOBALS['wp_mock_actions'][$hook_name]);
        return true;
    }
}

if (!function_exists('do_action')) {
    function do_action(string $hook_name, ...$args): void {
        if (!empty($GLOBALS['wp_mock_actions'][$hook_name])) {
            foreach ($GLOBALS['wp_mock_actions'][$hook_name] as $cb) {
                $cb(...$args);
            }
        }
    }
}

if (!function_exists('is_plugin_active')) {
    function is_plugin_active(string $plugin): bool {
        return false;
    }
}

if (!function_exists('wp_is_writable')) {
    function wp_is_writable(string $path): bool {
        return is_writable($path);
    }
}

if (!function_exists('wp_using_ext_object_cache')) {
    function wp_using_ext_object_cache($using = null): bool {
        global $_wp_using_ext_object_cache;
        $current = !empty($_wp_using_ext_object_cache) || !empty($GLOBALS['wp_mock_ext_object_cache']);
        if (null !== $using) {
            $_wp_using_ext_object_cache = (bool) $using;
            $GLOBALS['wp_mock_ext_object_cache'] = (bool) $using;
        }
        return $current;
    }
}

if (!function_exists('wp_cache_get')) {
    function wp_cache_get(string $key, string $group = '', bool $force = false, &$found = null) {
        $found = isset($GLOBALS['wp_mock_object_cache'][$group][$key]);
        return $found ? $GLOBALS['wp_mock_object_cache'][$group][$key] : false;
    }
}

if (!function_exists('wp_cache_set')) {
    function wp_cache_set(string $key, $data, string $group = '', int $expire = 0): bool {
        $GLOBALS['wp_mock_object_cache'][$group][$key] = $data;
        return true;
    }
}

if (!function_exists('wp_cache_add')) {
    function wp_cache_add(string $key, $data, string $group = '', int $expire = 0): bool {
        if (isset($GLOBALS['wp_mock_object_cache'][$group][$key])) {
            return false;
        }
        $GLOBALS['wp_mock_object_cache'][$group][$key] = $data;
        return true;
    }
}

if (!function_exists('wp_cache_incr')) {
    function wp_cache_incr(string $key, int $offset = 1, string $group = '') {
        if (!isset($GLOBALS['wp_mock_object_cache'][$group][$key])) {
            return false;
        }
        $val = (int) $GLOBALS['wp_mock_object_cache'][$group][$key] + $offset;
        $GLOBALS['wp_mock_object_cache'][$group][$key] = $val;
        return $val;
    }
}

if (!function_exists('wp_cache_delete')) {
    function wp_cache_delete(string $key, string $group = ''): bool {
        unset($GLOBALS['wp_mock_object_cache'][$group][$key]);
        return true;
    }
}

// Minimal SettingsManager stub if full plugin bootstrap isn't loaded
if (!class_exists('WebCareProScanner\\System\\SettingsManager')) {
    eval('
        namespace WebCareProScanner\\System;
        class SettingsManager {
            public static bool $suppress_firewall_ruleset_log = false;
            public static function get_settings(): array {
                return $GLOBALS["wp_mock_options"]["webcareproscan_settings"] ?? [];
            }
            public static function get(string $key, $default = null) {
                $settings = self::get_settings();
                return array_key_exists($key, $settings) ? $settings[$key] : $default;
            }
            public static function get_defaults(): array { return []; }
            public static function is_path_excluded(string $path): bool { return false; }
            public static function update_setting(string $key, $value): bool {
                $settings = self::get_settings();
                $settings[$key] = $value;
                $GLOBALS["wp_mock_options"]["webcareproscan_settings"] = $settings;
                return true;
            }
            public static function save_settings(array $settings): bool {
                $GLOBALS["wp_mock_options"]["webcareproscan_settings"] = $settings;
                return true;
            }
        }
    ');
}

if (!function_exists('is_blog_installed')) {
    function is_blog_installed(): bool {
        return true;
    }
}

if (!function_exists('wp_send_json_error')) {
    function wp_send_json_error($data = null, ?int $status_code = null, int $options = 0): void {
        if (!empty($GLOBALS['wp_mock_send_json_error']) && is_callable($GLOBALS['wp_mock_send_json_error'])) {
            call_user_func($GLOBALS['wp_mock_send_json_error'], $data, $status_code ?? 400);
            return;
        }
        throw new \RuntimeException('wp_send_json_error: ' . (is_array($data) ? ($data['message'] ?? 'error') : (string) $data), $status_code ?? 400);
    }
}

if (!function_exists('wp_send_json_success')) {
    function wp_send_json_success($data = null, ?int $status_code = null, int $options = 0): void {
        throw new \RuntimeException('wp_send_json_success: ' . (is_array($data) ? json_encode($data) : (string) $data), $status_code ?? 200);
    }
}

if (!function_exists('wp_doing_ajax')) {
    function wp_doing_ajax(): bool {
        return defined('DOING_AJAX') && DOING_AJAX;
    }
}

if (!function_exists('is_child_theme')) {
    function is_child_theme(): bool {
        return false;
    }
}

if (!function_exists('get_bloginfo')) {
    function get_bloginfo(string $show = '', string $filter = 'raw'): string {
        if ($show === 'name') {
            return 'WebCare Test Site';
        }
        return '';
    }
}

if (!function_exists('esc_url')) {
    function esc_url(string $url, ?array $protocols = null, string $_context = 'display'): string {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field(string $str): string {
        return trim(strip_tags($str));
    }
}

if (!class_exists('WP_Session_Tokens')) {
    class WP_Session_Tokens {
        private int $user_id;
        public function __construct(int $user_id) { $this->user_id = $user_id; }
        public static function get_instance(int $user_id): self { return new self($user_id); }
        public function destroy_all(): void {
            $GLOBALS['wp_mock_sessions_destroyed'][] = $this->user_id;
            delete_user_meta($this->user_id, 'session_tokens');
        }
    }
}

if (!function_exists('get_password_reset_key')) {
    function get_password_reset_key($user): string|WP_Error {
        return 'mock-reset-key-' . bin2hex(random_bytes(8));
    }
}

if (!function_exists('network_site_url')) {
    function network_site_url(string $path = '', ?string $scheme = null): string {
        return 'https://example.com/' . ltrim($path, '/');
    }
}

if (!function_exists('wp_mail')) {
    function wp_mail(string|array $to, string $subject, string $message, string|array $headers = '', string|array $attachments = []): bool {
        $GLOBALS['wp_mock_mails'][] = ['to' => $to, 'subject' => $subject, 'message' => $message];
        return true;
    }
}

if (!function_exists('wp_login_url')) {
    function wp_login_url(string $redirect = '', bool $force_reauth = false): string {
        return 'https://example.com/wp-login.php';
    }
}

if (!function_exists('rest_ensure_response')) {
    function rest_ensure_response($response) {
        if ($response instanceof WP_Error || $response instanceof WP_REST_Response) {
            return $response;
        }
        return new WP_REST_Response($response, 200);
    }
}

if (!function_exists('has_filter')) {
    function has_filter(string $hook_name, mixed $callback = false): bool|int {
        $callbacks = $GLOBALS['wp_mock_filters'][$hook_name] ?? [];
        if (empty($callbacks)) {
            return false;
        }
        if ($callback === false) {
            return true;
        }
        foreach ($callbacks as $priority => $entries) {
            foreach ($entries as $entry) {
                if (($entry['function'] ?? null) === $callback) {
                    return (int) $priority;
                }
            }
        }
        return false;
    }
}

if (!function_exists('has_action')) {
    function has_action(string $hook_name, mixed $callback = false): bool|int {
        return has_filter($hook_name, $callback);
    }
}

if (!function_exists('wp_safe_remote_post')) {
    function wp_safe_remote_post(string $url, array $args = []): array {
        $GLOBALS['wp_mock_http_requests'][] = ['method' => 'POST', 'url' => $url, 'args' => $args];
        if (!empty($GLOBALS['wp_mock_http_callback']) && is_callable($GLOBALS['wp_mock_http_callback'])) {
            return call_user_func($GLOBALS['wp_mock_http_callback'], $url, $args);
        }
        return [
            'response' => ['code' => 200, 'message' => 'OK'],
            'body'     => '{}',
        ];
    }
}

if (!function_exists('wp_safe_remote_get')) {
    function wp_safe_remote_get(string $url, array $args = []): array {
        $GLOBALS['wp_mock_http_requests'][] = ['method' => 'GET', 'url' => $url, 'args' => $args];
        if (!empty($GLOBALS['wp_mock_http_callback']) && is_callable($GLOBALS['wp_mock_http_callback'])) {
            return call_user_func($GLOBALS['wp_mock_http_callback'], $url, $args);
        }
        return [
            'response' => ['code' => 404, 'message' => 'Not Found'],
            'body'     => '',
        ];
    }
}

if (!function_exists('wp_safe_remote_request')) {
    function wp_safe_remote_request(string $url, array $args = []): array {
        return [
            'response' => ['code' => 200, 'message' => 'OK'],
            'body'     => '{"success":true,"result":[]}',
        ];
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($response): int {
        return is_array($response) ? (int) ($response['response']['code'] ?? 200) : 200;
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response): string {
        return is_array($response) ? (string) ($response['body'] ?? '') : '';
    }
}

if (!function_exists('wp_remote_retrieve_header')) {
    function wp_remote_retrieve_header($response, string $header): string {
        return is_array($response) ? (string) ($response['headers'][$header] ?? '') : '';
    }
}

if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event(int $timestamp, string $recurrence, string $hook, array $args = []): bool {
        $GLOBALS['wp_mock_cron'][$hook] = [
            'timestamp'  => $timestamp,
            'recurrence' => $recurrence,
            'args'       => $args,
        ];
        return true;
    }
}

if (!function_exists('wp_schedule_single_event')) {
    function wp_schedule_single_event(int $timestamp, string $hook, array $args = []): bool {
        $GLOBALS['wp_mock_cron'][$hook] = [
            'timestamp'  => $timestamp,
            'recurrence' => false,
            'args'       => $args,
        ];
        return true;
    }
}

if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled(string $hook, array $args = []): int|false {
        return isset($GLOBALS['wp_mock_cron'][$hook]) ? (int) $GLOBALS['wp_mock_cron'][$hook]['timestamp'] : false;
    }
}

if (!function_exists('wp_get_schedule')) {
    function wp_get_schedule(string $hook, array $args = []): string|false {
        if (!isset($GLOBALS['wp_mock_cron'][$hook])) {
            return false;
        }
        $rec = $GLOBALS['wp_mock_cron'][$hook]['recurrence'] ?? false;
        return is_string($rec) ? $rec : false;
    }
}

if (!function_exists('wp_unschedule_event')) {
    function wp_unschedule_event(int $timestamp, string $hook, array $args = []): bool {
        unset($GLOBALS['wp_mock_cron'][$hook]);
        return true;
    }
}

if (!function_exists('wp_clear_scheduled_hook')) {
    function wp_clear_scheduled_hook(string $hook, array $args = []): int|false {
        $had = isset($GLOBALS['wp_mock_cron'][$hook]);
        unset($GLOBALS['wp_mock_cron'][$hook]);
        return $had ? 1 : 0;
    }
}

if (!function_exists('wp_get_schedules')) {
    function wp_get_schedules(): array {
        return [
            'hourly'     => ['interval' => 3600, 'display' => 'Once Hourly'],
            'twicedaily' => ['interval' => 43200, 'display' => 'Twice Daily'],
            'daily'      => ['interval' => 86400, 'display' => 'Once Daily'],
        ];
    }
}

// Require target classes from plugin includes/
$includesDir = __DIR__ . '/../includes';

spl_autoload_register(static function (string $class) use ($includesDir): void {
    $prefix = 'WebCareProScanner\\';
    if (str_starts_with($class, $prefix)) {
        $relative = substr($class, strlen($prefix));
        $file = $includesDir . '/' . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

foreach ([
    '/Scan/ScanLock.php',
    '/Firewall/MicroWafCompiler.php',
    '/Security/PromptInjectionGuard.php',
    '/Api/MCPAntiLockoutValidator.php',
] as $relFile) {
    if (file_exists($includesDir . $relFile)) {
        require_once $includesDir . $relFile;
    }
}
