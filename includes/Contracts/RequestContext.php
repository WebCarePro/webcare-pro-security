<?php
namespace WebCareProScanner\Contracts;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Normalized immutable-style request snapshot shared across WAF evaluators and custom rule engines.
 */
class RequestContext {

    /** @var string */
    public string $ip = '127.0.0.1';

    /** @var string */
    public string $method = 'GET';

    /** @var string */
    public string $uri = '';

    /** @var string */
    public string $cleanUri = '';

    /** @var string */
    public string $query = '';

    /** @var string */
    public string $userAgent = '';

    /** @var string */
    public string $referer = '';

    /** @var string */
    public string $cookieHeader = '';

    /** @var array<string, mixed> */
    public array $queryParams = [];

    /** @var array<string, mixed> */
    public array $formParams = [];

    /** @var array<string, mixed> */
    public array $jsonParams = [];

    /** @var array<string, mixed> */
    public array $cookies = [];

    /** @var array<string, mixed> */
    public array $rawBodyMetadata = [];

    /** @var array<string, string> */
    public array $headers = [];

    /** @var array<string, mixed> */
    public array $params = [];

    /** @var array<string, mixed> */
    public array $files = [];

    /** @var array<string, mixed> */
    public array $server = [];

    /** @var array<int, string> */
    public array $uploadedExtensions = [];

    /** @var string */
    public string $country = '';

    /** @var string */
    public string $asn = '';

    /** @var string */
    public string $ajaxAction = '';

    /** @var string */
    public string $restRoute = '';

    /** @var string */
    public string $targetSlug = '';

    /** @var bool */
    public bool $isLoggedIn = false;

    /** @var bool */
    public bool $isAdmin = false;

    /** @var string[] */
    public array $userRoles = [];

    /** @var string[] */
    public array $userCaps = [];

    /** @var bool */
    public bool $hasWooCart = false;

    /** @var bool */
    public bool $cf_proxied = false;

    /**
     * Optional constructor for synthetic / test contexts.
     *
     * @param string $ip
     * @param string $method
     * @param string $uri
     * @param string $userAgent
     * @param array<string, mixed> $params
     * @param array<string, mixed> $cookies
     * @param array<string, string> $headers
     * @param array<string, mixed> $files
     * @param array<string, mixed> $server
     */
    public function __construct(
        string $ip = '127.0.0.1',
        string $method = 'GET',
        string $uri = '',
        string $userAgent = '',
        array $params = [],
        array $cookies = [],
        array $headers = [],
        array $files = [],
        array $server = [],
        array $queryParams = [],
        array $formParams = [],
        array $jsonParams = []
    ) {
        $this->ip = $ip;
        $this->method = strtoupper($method);
        $this->uri = $uri;
        $q_pos = strpos($uri, '?');
        $raw_clean = strtolower($q_pos === false ? $uri : substr($uri, 0, $q_pos));
        if (strpos($raw_clean, '/.') !== false || strpos($raw_clean, '//') !== false) {
            $raw_clean = (string) preg_replace('#/+#', '/', $raw_clean);
            $p_parts = explode('/', $raw_clean);
            $p_stack = [];
            foreach ($p_parts as $p_seg) {
                if ($p_seg === '' || $p_seg === '.') {
                    continue;
                }
                if ($p_seg === '..') {
                    array_pop($p_stack);
                } else {
                    $p_stack[] = $p_seg;
                }
            }
            $raw_clean = '/' . implode('/', $p_stack);
        }
        $this->cleanUri = $raw_clean;
        $this->query = $q_pos === false ? '' : substr($uri, $q_pos + 1);
        $this->userAgent = $userAgent;
        $this->cookies = !empty($cookies) ? $cookies : (isset($_COOKIE) && is_array($_COOKIE) ? $_COOKIE : []);
        $this->headers = $headers;
        $this->files = $files;
        $this->server = !empty($server) ? $server : (isset($_SERVER) && is_array($_SERVER) ? $_SERVER : []);

        $this->queryParams = $queryParams;
        if (empty($this->queryParams) && $this->query !== '') {
            $parsed_q = [];
            parse_str($this->query, $parsed_q);
            if (is_array($parsed_q)) {
                $this->queryParams = $parsed_q;
            }
        }

        $this->formParams = $formParams;
        $this->jsonParams = $jsonParams;
        $this->rawBodyMetadata = [];

        $this->params = !empty($params) ? $params : array_merge($this->queryParams, $this->formParams, $this->jsonParams);
    }

    /**
     * Build a RequestContext from current PHP / WordPress superglobals.
     *
     * @return self
     */
    public static function from_globals(): self {
        $ctx = new self();

        $ctx->ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        $ctx->method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])))
            : 'GET';

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw URI decomposed cleanly before field sanitization
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $ctx->uri = str_replace(["\0", "\r", "\n"], '', $raw_uri);
        $q_pos    = strpos($raw_uri, '?');
        $raw_clean = strtolower(sanitize_text_field($q_pos === false ? $raw_uri : substr($raw_uri, 0, $q_pos)));
        if (strpos($raw_clean, '/.') !== false || strpos($raw_clean, '//') !== false) {
            $raw_clean = preg_replace('#/+#', '/', $raw_clean);
            $p_parts = explode('/', $raw_clean);
            $p_stack = [];
            foreach ($p_parts as $p_seg) {
                if ($p_seg === '' || $p_seg === '.') {
                    continue;
                }
                if ($p_seg === '..') {
                    array_pop($p_stack);
                } else {
                    $p_stack[] = $p_seg;
                }
            }
            $raw_clean = '/' . implode('/', $p_stack);
        }
        $ctx->cleanUri = $raw_clean;
        $ctx->query    = $q_pos === false ? '' : str_replace(["\0", "\r", "\n"], '', substr($raw_uri, $q_pos + 1));

        $ctx->userAgent    = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $ctx->referer      = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $ctx->cookieHeader = isset($_SERVER['HTTP_COOKIE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_COOKIE'])) : '';
        $remote_peer     = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $is_cf_peer      = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            && \WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($remote_peer);
        $ctx->country    = $is_cf_peer && isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY']))) : '';
        $raw_asn         = $is_cf_peer && isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : '';
        $ctx->asn        = $raw_asn !== '' ? ltrim(strtoupper($raw_asn), 'AS') : '';
        $ctx->cf_proxied = $is_cf_peer && !empty($_SERVER['HTTP_CF_RAY']);

        foreach ($_SERVER as $k => $v) {
            if (is_string($k)) {
                $ctx->server[$k] = $v;
                if (strpos($k, 'HTTP_') === 0 && is_string($v)) {
                    $hname = strtolower(str_replace('_', '-', substr($k, 5)));
                    $ctx->headers[$hname] = sanitize_text_field(wp_unslash($v));
                }
            }
        }
        if (isset($_SERVER['CONTENT_TYPE']) && is_string($_SERVER['CONTENT_TYPE'])) {
            $ctx->headers['content-type'] = sanitize_text_field(wp_unslash($_SERVER['CONTENT_TYPE']));
        }

        // 1. Parse Query Parameters strictly from $_GET (or parsed URI)
        if (!empty($_GET) && is_array($_GET)) {
            foreach ($_GET as $gk => $gv) {
                $k_clean = sanitize_key((string) $gk);
                if ($k_clean !== '') {
                    $ctx->queryParams[$k_clean] = $gv;
                }
            }
        } elseif ($ctx->query !== '') {
            $parsed_q = [];
            parse_str($ctx->query, $parsed_q);
            if (is_array($parsed_q)) {
                foreach ($parsed_q as $pqk => $pqv) {
                    $k_clean = sanitize_key((string) $pqk);
                    if ($k_clean !== '') {
                        $ctx->queryParams[$k_clean] = $pqv;
                    }
                }
            }
        }

        // 2. Parse Form Parameters strictly from $_POST
        if (!empty($_POST) && is_array($_POST)) {
            foreach ($_POST as $fk => $fv) {
                $k_clean = sanitize_key((string) $fk);
                if ($k_clean !== '') {
                    $ctx->formParams[$k_clean] = $fv;
                }
            }
        }

        // 3. Parse Cookies strictly from $_COOKIE (Never merged into $params)
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            foreach ($_COOKIE as $ck => $cv) {
                $k_clean = sanitize_key((string) $ck);
                if ($k_clean !== '') {
                    $ctx->cookies[$k_clean] = $cv;
                }
            }
        }

        // 4. Bounded body reader for JSON/REST/GraphQL
        $ct = $ctx->headers['content-type'] ?? '';
        $body_reader_class = '\\WebCareProScanner\\Firewall\\Core\\RequestBodyReader';
        if (class_exists($body_reader_class)) {
            $raw_body = $body_reader_class::get_bounded_body();
            $ctx->rawBodyMetadata = [
                'bytes_read'   => $body_reader_class::get_bytes_read(),
                'truncated'    => $body_reader_class::is_truncated(),
                'sha256'       => $body_reader_class::get_sha256(),
                'content_type' => $ct,
            ];

            // Invariant: Truncated JSON is NEVER parsed as complete payload
            if (!$body_reader_class::is_truncated() && stripos($ct, 'application/json') !== false && $raw_body !== '') {
                $decoded = json_decode($raw_body, true);
                if (is_array($decoded)) {
                    foreach ($decoded as $dk => $dv) {
                        $dkey = sanitize_key((string) $dk);
                        if ($dkey !== '') {
                            $ctx->jsonParams[$dkey] = $dv;
                        }
                    }
                }
            }
        }

        // Retain $params strictly as queryParams + formParams + jsonParams (EXCLUDING cookies)
        $ctx->params = array_merge($ctx->queryParams, $ctx->formParams, $ctx->jsonParams);

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch file extension extraction from $_FILES
        if (!empty($_FILES) && is_array($_FILES)) {
            $ctx->files = $_FILES;
            $queue = [];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch file metadata audit
            foreach ($_FILES as $fitem) {
                if (isset($fitem['name'])) {
                    $queue[] = $fitem['name'];
                }
            }
            while (!empty($queue)) {
                $next = array_shift($queue);
                if (is_array($next)) {
                    foreach ($next as $sub) {
                        $queue[] = $sub;
                    }
                } elseif (is_string($next) && $next !== '') {
                    $ext = strtolower(pathinfo($next, PATHINFO_EXTENSION));
                    if ($ext !== '') {
                        $ctx->uploadedExtensions[] = $ext;
                    }
                }
            }
            $ctx->uploadedExtensions = array_values(array_unique($ctx->uploadedExtensions));
        }

        // Canonical AJAX & REST tokens
        if (isset($ctx->params['action']) && is_string($ctx->params['action'])) {
            $ctx->ajaxAction = strtolower(trim(sanitize_text_field($ctx->params['action'])));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch REST query extraction
        $rest_q = isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? strtolower(trim(sanitize_text_field(wp_unslash($_GET['rest_route'])))) : '';
        if ($rest_q !== '') {
            $ctx->restRoute = '/' . ltrim($rest_q, '/');
        } elseif (($pos = strpos($ctx->cleanUri, '/wp-json')) !== false) {
            $ctx->restRoute = '/' . ltrim(substr($ctx->cleanUri, $pos + 8), '/');
        }

        // Resolve target plugin/theme slug heuristic from URI or REST namespace
        if (preg_match('#/wp-content/(?:plugins|themes)/([a-z0-9_-]+)#i', $ctx->cleanUri, $m)) {
            $ctx->targetSlug = strtolower($m[1]);
        } elseif ($ctx->restRoute !== '' && preg_match('#^/([a-z0-9_-]+)/v\d+#i', $ctx->restRoute, $m)) {
            $ctx->targetSlug = strtolower($m[1]);
        }

        // Login state & user roles/capabilities
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            $ctx->isLoggedIn = true;
            $ctx->isAdmin    = function_exists('current_user_can') && current_user_can('manage_options');
            $user            = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
            if ($user && !empty($user->roles) && is_array($user->roles)) {
                $ctx->userRoles = array_map('strtolower', $user->roles);
            }
            if ($user && !empty($user->allcaps) && is_array($user->allcaps)) {
                $ctx->userCaps = array_keys(array_filter($user->allcaps));
            }
        }

        // Ecommerce session cookie detection (WooCommerce, EDD, SureCart)
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch cookie snapshot
            $ctx->cookies = wp_unslash($_COOKIE);
            foreach (array_keys($_COOKIE) as $ck) {
                $ck_str = (string) $ck;
                if (
                    strpos($ck_str, 'wp_woocommerce_session_') === 0
                    || strpos($ck_str, 'woocommerce_items_in_cart') === 0
                    || strpos($ck_str, 'edd_items_in_cart') === 0
                    || strpos($ck_str, 'sc_cart_') === 0
                ) {
                    $ctx->hasWooCart = true;
                    break;
                }
            }
        }

        return $ctx;
    }
}
