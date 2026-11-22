<?php
declare(strict_types=1);

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
$GLOBALS['wp_mock_transients'] = [];
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
        return $GLOBALS['wp_mock_transients'][$transient] ?? false;
    }
}

if (!function_exists('set_transient')) {
    function set_transient(string $transient, $value, int $expiration = 0): bool {
        $GLOBALS['wp_mock_transients'][$transient] = $value;
        return true;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient(string $transient): bool {
        unset($GLOBALS['wp_mock_transients'][$transient]);
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

if (!function_exists('wp_max_upload_size')) {
    function wp_max_upload_size(): int {
        return 134217728;
    }
}

if (!function_exists('is_multisite')) {
    function is_multisite(): bool {
        return false;
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
        public array $roles = [];
        public array $allcaps = [];
        public function __construct(int $id = 0, string $name = '') {
            $this->ID = $id;
            $this->user_login = $name ?: 'user_' . $id;
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
        if (!empty($GLOBALS['wp_mock_current_user']) && $GLOBALS['wp_mock_current_user']->ID === $user_id) {
            return $GLOBALS['wp_mock_current_user'];
        }
        return false;
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
        return mkdir($target, 0755, true);
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
        if (file_exists($file)) {
            @unlink($file);
        }
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
    class wpdb {
        public string $prefix = 'wp_';
        public array $queries = [];
        public array $mock_tables = [];
        public $mock_get_var_callback = null;

        public function prepare(string $query, ...$args): string {
            return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $query), $args);
        }

        public function get_var(string $query) {
            $this->queries[] = $query;
            if (is_callable($this->mock_get_var_callback)) {
                return ($this->mock_get_var_callback)($query);
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

if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled(string $hook, array $args = []): int|false {
        return false;
    }
}

if (!function_exists('wp_schedule_single_event')) {
    function wp_schedule_single_event(int $timestamp, string $hook, array $args = [], bool $wp_error = false): bool {
        return true;
    }
}

if (!function_exists('rest_ensure_response')) {
    function rest_ensure_response(mixed $response): mixed {
        return $response;
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

if (!function_exists('do_action')) {
    function do_action(string $hook_name, ...$args): void {
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

if (!function_exists('wp_clear_scheduled_hook')) {
    function wp_clear_scheduled_hook(string $hook, array $args = []): int {
        return 0;
    }
}

if (!function_exists('wp_schedule_single_event')) {
    function wp_schedule_single_event(int $timestamp, string $hook, array $args = [], bool $wp_error = false): bool {
        return true;
    }
}

if (!function_exists('wp_using_ext_object_cache')) {
    function wp_using_ext_object_cache(): bool {
        return !empty($GLOBALS['wp_mock_ext_object_cache']);
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
