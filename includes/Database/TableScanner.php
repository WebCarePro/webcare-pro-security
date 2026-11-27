<?php
namespace WebCareProScanner\Database;

use WebCareProScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class TableScanner {

    private $serialized_scanner;
    private ?string $last_error = null;

    // High risk injection patterns for database text columns
    private $patterns = [
        'script_tag_injection' => [
            'regex'      => '/<script[\s\S]*?>[\s\S]*?<\/script>/i',
            'severity'   => 'high',
            'confidence' => 85,
            'desc'       => 'Injected script element tag detected in database content.'
        ],
        'iframe_injection' => [
            'regex'      => '/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/i',
            'severity'   => 'high',
            'confidence' => 85,
            'desc'       => 'Injected iframe element tag detected in database content.'
        ],
        'malicious_event_handler' => [
            'regex'      => '/\b(onload|onerror|onclick|onmouseover)\s*=\s*["\']?\s*(javascript:|eval|window\.location|document\.cookie)/i',
            'severity'   => 'high',
            'confidence' => 90,
            'desc'       => 'Suspicious JavaScript event handler attribute detected in database content.'
        ],
        'base64_eval_payload' => [
            'regex'      => '/(eval\s*\(\s*base64_decode|assert\s*\(\s*base64_decode|\bdocument\.write\s*\(\s*unescape)/i',
            'severity'   => 'critical',
            'confidence' => 95,
            'desc'       => 'Encoded evaluation payload (eval/base64/unescape) detected in database column.'
        ],
        'hidden_seo_spam' => [
            'regex'      => '/style\s*=\s*["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute\s*;\s*left\s*:\s*-[0-9]{3,}px)[^"\']*["\']\s*>[^<]*<a\s+href/i',
            'severity'   => 'medium',
            'confidence' => 80,
            'desc'       => 'Hidden anchor link / hidden CSS styling detected (SEO link injection spam).'
        ],
    ];

    public function __construct() {
        $this->serialized_scanner = new SerializedDataScanner();
    }

    /**
     * Return the last sanitized database/runtime error observed by TableScanner, if any.
     */
    public function get_last_error(): ?string {
        return $this->last_error;
    }

    /**
     * Get all tables in the current WordPress database.
     *
     * @return array List of table names
     */
    public function get_tables() {
        global $wpdb;
        $this->last_error = null;
        if (isset($wpdb->last_error)) {
            $wpdb->last_error = '';
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $tables = $wpdb->get_col("SHOW TABLES");
        if (!empty($wpdb->last_error)) {
            $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
            return [];
        }
        if (!is_array($tables)) {
            return [];
        }

        // Whitelist / exclude our own security scanner internal tables (e.g. firewall logs, audit logs, scan issues)
        return array_values(array_filter($tables, function($t) {
            return stripos($t, 'webcareproscan_') === false;
        }));
    }

    /**
     * Get all text-like columns for a table, identify single-column integer primary keys
     * for keyset pagination, and resolve verified unique ORDER BY columns (PK or NOT-NULL
     * unique index) for safe offset pagination.
     *
     * @param string $table
     * @return array{columns: list<string>, primary_key: string|null, order_by_columns: list<string>, has_unique_ordering: bool, ordering_strategy: string}
     */
    public function get_table_metadata($table) {
        global $wpdb;
        $this->last_error = null;
        $columns = [];
        $primary_key = null;

        // Safely validate table name matches word characters only
        if (!preg_match('/^[a-zA-Z0-9_]+$/', (string) $table)) {
            return [
                'columns'             => [],
                'primary_key'         => null,
                'order_by_columns'    => [],
                'has_unique_ordering' => false,
                'ordering_strategy'   => 'invalid_table',
            ];
        }

        if (isset($wpdb->last_error)) {
            $wpdb->last_error = '';
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $cols_info = $wpdb->get_results("SHOW COLUMNS FROM `{$table}`");
        if (!empty($wpdb->last_error)) {
            $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
            return [
                'columns'             => [],
                'primary_key'         => null,
                'order_by_columns'    => [],
                'has_unique_ordering' => false,
                'ordering_strategy'   => 'metadata_error',
            ];
        }
        if (empty($cols_info)) {
            return [
                'columns'             => [],
                'primary_key'         => null,
                'order_by_columns'    => [],
                'has_unique_ordering' => false,
                'ordering_strategy'   => 'empty_columns',
            ];
        }

        $text_types = ['varchar', 'text', 'tinytext', 'mediumtext', 'longtext', 'json'];
        $pri_cols = [];
        $uni_not_null_cols = [];
        $col_nullable = [];
        $all_safe_cols = [];

        foreach ($cols_info as $col) {
            $field = (string) ($col->Field ?? '');
            if ($field === '' || !preg_match('/^[a-zA-Z0-9_]+$/', $field)) {
                continue;
            }
            $all_safe_cols[] = $field;
            $type = strtolower((string) ($col->Type ?? ''));
            $key = strtoupper((string) ($col->Key ?? ''));
            $is_nullable = strtoupper((string) ($col->Null ?? 'YES')) !== 'NO';
            $col_nullable[$field] = $is_nullable;

            if ($key === 'PRI') {
                $pri_cols[] = ['field' => $field, 'type' => $type];
            } elseif ($key === 'UNI' && !$is_nullable) {
                $uni_not_null_cols[] = $field;
            }

            foreach ($text_types as $text_type) {
                if (strpos($type, $text_type) !== false) {
                    $columns[] = $field;
                    break;
                }
            }
        }

        // Only use keyset pagination (WHERE pk > %d) for single-column integer primary keys;
        // composite or string/UUID primary keys fall back safely to unique ordered LIMIT/OFFSET.
        if (count($pri_cols) === 1 && preg_match('/\b(?:tiny|small|medium|big)?int\b/i', $pri_cols[0]['type'])) {
            $primary_key = $pri_cols[0]['field'];
        }

        $has_unique_ordering = false;
        $ordering_strategy = 'unsafe_no_unique_key';
        $order_by_columns = [];

        if (!empty($pri_cols)) {
            $order_by_columns = array_map(static fn(array $p): string => $p['field'], $pri_cols);
            $has_unique_ordering = true;
            $ordering_strategy = $primary_key !== null ? 'keyset_int_pk' : 'offset_pk';
        } elseif (!empty($uni_not_null_cols)) {
            $order_by_columns = [$uni_not_null_cols[0]];
            $has_unique_ordering = true;
            $ordering_strategy = 'offset_unique_index';
        } else {
            // Inspect composite/named unique indexes when no PRI or single NOT-NULL UNI column was found
            if (isset($wpdb->last_error)) {
                $wpdb->last_error = '';
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $index_rows = method_exists($wpdb, 'get_results') ? $wpdb->get_results("SHOW INDEX FROM `{$table}`") : [];
            if (!empty($wpdb->last_error)) {
                $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
                return [
                    'columns'             => [],
                    'primary_key'         => null,
                    'order_by_columns'    => [],
                    'has_unique_ordering' => false,
                    'ordering_strategy'   => 'metadata_error',
                ];
            }

            if (is_array($index_rows) && !empty($index_rows)) {
                $unique_indexes = [];
                foreach ($index_rows as $idx_row) {
                    if ((string) ($idx_row->Non_unique ?? '1') !== '0') {
                        continue;
                    }
                    $key_name = (string) ($idx_row->Key_name ?? '');
                    $col_name = (string) ($idx_row->Column_name ?? '');
                    if ($key_name === '' || $col_name === '') {
                        continue;
                    }
                    $unique_indexes[$key_name][] = [
                        'seq'      => (int) ($idx_row->Seq_in_index ?? 0),
                        'col'      => $col_name,
                        'nullable' => ($col_nullable[$col_name] ?? true) || strtoupper((string) ($idx_row->Null ?? '')) === 'YES',
                        'sub_part' => $idx_row->Sub_part ?? null,
                    ];
                }

                foreach ($unique_indexes as $idx_cols) {
                    usort($idx_cols, static fn(array $a, array $b): int => $a['seq'] <=> $b['seq']);
                    $candidate_cols = [];
                    $idx_valid = !empty($idx_cols);
                    foreach ($idx_cols as $ic) {
                        if (
                            $ic['nullable']
                            || !empty($ic['sub_part'])
                            || !preg_match('/^[a-zA-Z0-9_]+$/', $ic['col'])
                            || !in_array($ic['col'], $all_safe_cols, true)
                        ) {
                            $idx_valid = false;
                            break;
                        }
                        $candidate_cols[] = $ic['col'];
                    }
                    if ($idx_valid) {
                        $order_by_columns = $candidate_cols;
                        $has_unique_ordering = true;
                        $ordering_strategy = 'offset_unique_index';
                        break;
                    }
                }
            }

            if (!$has_unique_ordering) {
                // Table lacks a primary key or non-null unique index; retain full column list only for
                // single-batch reads and flag has_unique_ordering=false so multi-batch OFFSET is refused cleanly.
                $order_by_columns = $all_safe_cols;
            }
        }

        return [
            'columns'             => $columns,
            'primary_key'         => $primary_key,
            'order_by_columns'    => $order_by_columns,
            'has_unique_ordering' => $has_unique_ordering,
            'ordering_strategy'   => $ordering_strategy,
        ];
    }

    /**
     * Scan a batch of rows in a table.
     *
     * @param string $table
     * @param array $columns Text columns to scan
     * @param string|null $primary_key
     * @param int $last_id Keyset cursor or offset
     * @param int $batch_size
     * @param string $scan_id
     * @param list<string>|null $order_by_columns Unique ordering columns for LIMIT/OFFSET fallback
     * @param bool|null $has_unique_ordering Whether $order_by_columns is guaranteed unique (PRI or NOT-NULL UNIQUE index)
     * @return array{findings: Finding[], rows_scanned: int, next_cursor: int|null, unsafe_pagination?: bool}
     */
    public function scan_table_batch($table, $columns, $primary_key, $last_id = 0, $batch_size = 100, $scan_id = '', ?array $order_by_columns = null, ?bool $has_unique_ordering = null) {
        global $wpdb;
        $this->last_error = null;
        $findings = [];
        $batch_size = max(1, (int) $batch_size);
        $last_id = max(0, (int) $last_id);

        if (empty($columns) || !is_array($columns) || !preg_match('/^[a-zA-Z0-9_]+$/', (string) $table)) {
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }

        $safe_columns = array_values(array_filter(
            array_map(static fn($c): string => (string) $c, $columns),
            static fn(string $c): bool => (bool) preg_match('/^[a-zA-Z0-9_]+$/', $c)
        ));
        if (empty($safe_columns)) {
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }

        if ($primary_key !== null && $primary_key !== '' && !preg_match('/^[a-zA-Z0-9_]+$/', (string) $primary_key)) {
            $primary_key = null;
        }

        $select_cols = array_map(static fn(string $c): string => "`{$c}`", $safe_columns);
        if ($primary_key && !in_array("`{$primary_key}`", $select_cols, true)) {
            array_unshift($select_cols, "`{$primary_key}`");
        }
        $col_sql = implode(', ', $select_cols);
        $offset_mode_unique = true;

        // Keyset pagination when single integer primary key exists, otherwise unique ordered LIMIT/OFFSET
        if ($primary_key) {
            $raw_query = "SELECT {$col_sql} FROM `{$table}` WHERE `{$primary_key}` > %d ORDER BY `{$primary_key}` ASC LIMIT %d";
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $sql = $wpdb->prepare($raw_query, $last_id, $batch_size);
        } else {
            if ($order_by_columns === null || $has_unique_ordering === null) {
                $meta = $this->get_table_metadata((string) $table);
                if ($this->last_error !== null) {
                    return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
                }
                if ($order_by_columns === null) {
                    $order_by_columns = $meta['order_by_columns'] ?? [];
                }
                $offset_mode_unique = !empty($meta['has_unique_ordering']);
            } else {
                $offset_mode_unique = $has_unique_ordering;
            }

            $safe_order_cols = [];
            foreach ($order_by_columns as $order_col) {
                $order_col = (string) $order_col;
                if ($order_col !== '' && preg_match('/^[a-zA-Z0-9_]+$/', $order_col) && !in_array($order_col, $safe_order_cols, true)) {
                    $safe_order_cols[] = $order_col;
                }
            }
            if (empty($safe_order_cols)) {
                $safe_order_cols = $safe_columns;
                $offset_mode_unique = false;
            }

            if (!$offset_mode_unique && $last_id > 0) {
                $this->last_error = sprintf(
                    'Table %s has no primary key or non-null unique index and cannot be safely offset-paginated across batches.',
                    (string) $table
                );
                return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null, 'unsafe_pagination' => true];
            }

            $order_sql = implode(', ', array_map(static fn(string $c): string => "`{$c}` ASC", $safe_order_cols));

            $raw_query = "SELECT {$col_sql} FROM `{$table}` ORDER BY {$order_sql} LIMIT %d OFFSET %d";
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $sql = $wpdb->prepare($raw_query, $batch_size, $last_id);
        }

        if (isset($wpdb->last_error)) {
            $wpdb->last_error = '';
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results($sql, ARRAY_A);
        if (!empty($wpdb->last_error)) {
            $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }
        if (empty($rows)) {
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }

        $rows_scanned = count($rows);
        $next_cursor = null;

        foreach ($rows as $row) {
            $row_id = $primary_key && isset($row[$primary_key]) ? $row[$primary_key] : null;
            if ($primary_key && $row_id !== null) {
                $next_cursor = (int) $row_id;
            }

            // Skip internal system/code post types in posts tables (e.g. Simple Custom CSS & JS, oembed cache)
            $is_posts_table = (strpos($table, 'posts') !== false && strpos($table, 'postmeta') === false);
            if ($is_posts_table && isset($row['post_type'])) {
                $excluded_post_types = [
                    'custom-css-js', 'custom_css', 'oembed_cache', 'revision', 
                    'nav_menu_item', 'wp_navigation', 'wp_template', 'wp_template_part', 
                    'wp_global_styles', 'wplconsentlogs'
                ];
                if (in_array($row['post_type'], $excluded_post_types, true)) {
                    continue;
                }
            }

            // Skip cached transients and internal security scanner options in options tables
            $is_options_table = (strpos($table, 'options') !== false);
            if ($is_options_table && isset($row['option_name'])) {
                $opt_name = strtolower($row['option_name']);
                if (strpos($opt_name, '_transient_') === 0 ||
                    strpos($opt_name, '_site_transient_') === 0 ||
                    strpos($opt_name, 'rss_') === 0 ||
                    strpos($opt_name, 'feed_') === 0 ||
                    strpos($opt_name, 'cache_') === 0 ||
                    strpos($opt_name, 'webcareproscan_') === 0 ||
                    strpos($opt_name, 'webcare_') === 0) {
                    continue; // Skip transient/cache entries and plugin's own internal security telemetry options
                }
            }

            // Check if option/postmeta or custom snippets table legitimately stores custom code (e.g. Code Snippets, WPCode, header/footer scripts — audited deeply by SnippetCodeAuditor)
            $is_custom_code_storage = false;
            $is_snippets_table = (bool) preg_match('/(_snippets|_wpcode_snippets|_code_snippets|_hfcm_scripts)$/i', $table);
            if ($is_snippets_table) {
                $is_custom_code_storage = true;
            } elseif ($is_options_table && isset($row['option_name'])) {
                $is_custom_code_storage = (bool) preg_match('/^(header_script|footer_script|custom_js|custom_css|ihaf_|wpcode_|et_divi|theme_mods_)/i', $row['option_name']);
            } elseif (isset($row['meta_key'])) {
                $is_custom_code_storage = (bool) preg_match('/^(_custom_js|_custom_css|_elementor_data|_elementor_page_settings)$/i', $row['meta_key']);
            }

            foreach ($columns as $column) {
                if (!isset($row[$column]) || empty($row[$column])) {
                    continue;
                }

                $raw_val = (string) $row[$column];
                $strings_to_check = [];

                if (SerializedDataScanner::is_serialized($raw_val)) {
                    $pop_hit = $this->serialized_scanner->inspect_serialized_string($raw_val);
                    if ($pop_hit !== null) {
                        $findings[] = new Finding([
                            'engine'       => 'database-table',
                            'type'         => $pop_hit['type'] ?? 'serialized_object_injection',
                            'severity'     => $pop_hit['severity'] ?? 'critical',
                            'confidence'   => $pop_hit['confidence'] ?? 95,
                            'file_path'    => "{$table}.{$column}" . ($row_id !== null ? " [ID: {$row_id}]" : ''),
                            'description'  => $pop_hit['desc'] ?? 'Serialized PHP Object Injection gadget detected in database row.',
                            'evidence'     => $pop_hit['evidence'] ?? '',
                            'code_snippet' => substr($raw_val, 0, 180),
                        ]);
                    }
                    $strings_to_check = $this->serialized_scanner->extract_strings_safely($raw_val);
                } else {
                    // Unescape JSON-encoded HTML/script payloads (such as Elementor _elementor_data `<script>...<\/script>` or `\u003cscript`)
                    if ((str_starts_with(ltrim($raw_val), '[') || str_starts_with(ltrim($raw_val), '{')) && (str_contains($raw_val, '<\/') || str_contains($raw_val, '\u003c') || str_contains($raw_val, '\u003C'))) {
                        $unescaped_json = str_ireplace(['\/', '\u003c', '\u003e', '\u0022', '\u0027'], ['/', '<', '>', '"', "'"], $raw_val);
                        $strings_to_check = [$unescaped_json];
                    } else {
                        $strings_to_check = [$raw_val];
                    }
                }

                foreach ($strings_to_check as $str) {
                    if (strlen($str) < 10) continue;

                    foreach ($this->patterns as $rule_key => $rule) {
                        // In legitimate custom-code storage / Elementor JSON, still catch ALL exploit payloads including 2026 ClickFix, EtherHiding, skimmers, and external untrusted script tags!
                        if ($is_custom_code_storage && in_array($rule_key, ['script_tag_injection', 'iframe_injection'], true)) {
                            $has_exploit = preg_match('/(eval\s*\(|base64_decode\s*\(|document\.write\s*\(|String\.fromCharCode|\bwindow\[[\'"]ev|fetch\s*\(\s*[\'"]https?:|new\s+Function\s*\(|atob\s*\(|navigator\.clipboard|clipboardData\.setData|execCommand\s*\(\s*[\'"]copy|eth_call|JsonRpcProvider|bsc-dataseed|readContract|navigator\.sendBeacon|<script\b[^>]*\bsrc\s*=\s*(?:["\']\s*)?(?:https?:)?\/\/)/i', $str);
                            if (!$has_exploit) {
                                continue;
                            }
                        }

                        if (preg_match($rule['regex'], $str, $matches)) {
                            $snippet = substr($matches[0], 0, 150);

                            // Whitelist check: Legitimate media embeds (YouTube, Vimeo, Google Maps, WordPress.org)
                            if ($rule_key === 'iframe_injection') {
                                $is_trusted_embed = preg_match('/src=["\']https?:\/\/(www\.)?(youtube\.com|youtube-nocookie\.com|vimeo\.com|player\.vimeo\.com|wordpress\.org|maps\.google\.com|google\.com\/maps|spotify\.com|soundcloud\.com)\//i', $matches[0]);
                                if ($is_trusted_embed && !preg_match('/(display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i', $matches[0])) {
                                    continue;
                                }
                            }

                            if ($rule_key === 'script_tag_injection') {
                                if (strpos($table, 'post_smtp_logs') !== false || strpos($table, 'actionscheduler_logs') !== false) {
                                    continue;
                                }

                                // Benign data script tags (Schema.org JSON-LD)
                                if (preg_match('/<script[^>]*type\s*=\s*["\']?(?:application\/(?:ld\+json|json)|applic=\s*nation\/ld\+json)/i', $matches[0])) {
                                    if (!preg_match('/(eval\s*\(|base64_decode\s*\(|document\.write|window\[|\bjavascript:)/i', $matches[0])) {
                                        continue;
                                    }
                                }

                                // Strict hostname verification ONLY on external <script src=...> (supports quoted & unquoted attributes; NEVER skip inline scripts just because a comment mentions a CDN or MutationObserver!)
                                if (preg_match('/^<script\b[^>]*\bsrc\s*=\s*(?:"((?:https?:)?\/\/[^"\s>]+)"|\'((?:https?:)?\/\/[^\'\s>]+)\'|((?:https?:)?\/\/[^\s"\'=<>`]+))[^>]*>\s*<\/script>$/is', trim($matches[0]), $src_m)) {
                                    $raw_src = $src_m[1] !== '' ? $src_m[1] : ($src_m[2] !== '' ? $src_m[2] : ($src_m[3] ?? ''));
                                    $src_url = str_starts_with($raw_src, '//') ? 'https:' . $raw_src : $raw_src;
                                    $src_host = strtolower((string) wp_parse_url($src_url, PHP_URL_HOST));
                                    // phpcs:disable PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Allowlist of trusted CDN hostnames for malware/injection detection, not offloaded assets.
                                    $trusted_hosts = [
                                        'googletagmanager.com', 'www.googletagmanager.com', 'www.google-analytics.com', 'ssl.google-analytics.com',
                                        'www.clarity.ms', 'connect.facebook.net', 'cdnjs.cloudflare.com', 'code.jquery.com',
                                        'js.stripe.com', 'www.google.com', 'www.gstatic.com', 'www.recaptcha.net',
                                        'analytics.ahrefs.com', 'cdn.judge.me',
                                    ];
                                    // phpcs:enable PluginCheck.CodeAnalysis.Offloading.OffloadedContent
                                    if (in_array($src_host, $trusted_hosts, true)) {
                                        continue;
                                    }
                                }

                                // Benign local jQuery DOM handlers ONLY when free of ClickFix, EtherHiding, redirects, and decoders
                                if (preg_match('/<script\b[^>]*>([\s\S]*?)<\/script>/i', $matches[0], $script_body_match)) {
                                    $script_body = trim($script_body_match[1]);
                                    $has_exploit_sink = (bool) preg_match('/(eval\s*\(|base64_decode\s*\(|document\.write\s*\(|String\.fromCharCode|\bwindow\[[\'"]ev|fetch\s*\(\s*[\'"]https?:|new\s+Function\s*\(|atob\s*\(|fromCharCode|navigator\.sendBeacon|navigator\.clipboard|clipboardData|execCommand|eth_call|JsonRpcProvider|bsc-dataseed|readContract|WebSocket|serviceWorker|location\.replace|location\.href\s*=|document\.location)/i', $script_body);
                                    if (!$has_exploit_sink && !preg_match('/<script\b[^>]*\bsrc\s*=/i', $matches[0])) {
                                        if (preg_match('/(?:jQuery\s*\(|\$\s*\(|document\.addEventListener\s*\(\s*[\'"]DOMContentLoaded[\'"]|window\.addEventListener\s*\(\s*[\'"]load[\'"])/i', $script_body)) {
                                            continue;
                                        }
                                    }
                                }
                            }
                            $findings[] = new Finding([
                                'engine'      => 'database-table',
                                'type'        => $rule_key,
                                'severity'    => $rule['severity'],
                                'confidence'  => $rule['confidence'],
                                'file_path'   => "{$table}.{$column}" . ($row_id !== null ? " [ID: {$row_id}]" : ""),
                                'description' => $rule['desc'],
                                'evidence'    => "Snippet: " . esc_html($snippet),
                                'code_snippet'=> $snippet
                            ]);
                            break; // Avoid spamming multiple identical matches per string
                        }
                    }
                }
            }
        }

        // If no primary key was used, increment offset only when ordering is uniquely guaranteed
        $unsafe_pagination = false;
        if (!$primary_key) {
            if (!$offset_mode_unique && $rows_scanned >= $batch_size) {
                $unsafe_pagination = true;
                $next_cursor = null;
                $this->last_error = sprintf(
                    'Table %s lacks a primary key or non-null unique index; cannot safely offset-paginate beyond %d rows (marked incomplete).',
                    (string) $table,
                    $batch_size
                );
            } else {
                $next_cursor = $last_id + $rows_scanned;
            }
        } elseif ($next_cursor !== null && $next_cursor <= (int) $last_id) {
            $next_cursor = null;
        }

        return [
            'findings'          => $findings,
            'rows_scanned'      => $rows_scanned,
            'next_cursor'       => $rows_scanned < $batch_size ? null : $next_cursor,
            'unsafe_pagination' => $unsafe_pagination,
        ];
    }

    /**
     * Scan all custom and secondary WordPress tables across every row batch.
     * Excludes core options/comments tables (covered by OptionScanner/CommentScanner)
     * and user-excluded tables, while returning structured errors/incompleteness diagnostics.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @param \WebCareProScanner\Resource\ResourceMonitor|null $monitor
     * @return array{findings: Finding[], tables_scanned: int, rows_scanned: int, incomplete: bool, errors: list<string>}
     */
    public function scan_all_custom_tables(string $scan_id = '', int $batch_size = 250, ?\WebCareProScanner\Resource\ResourceMonitor $monitor = null): array {
        global $wpdb;
        $findings = [];
        $errors = [];
        $incomplete = false;
        $tables_scanned = 0;
        $rows_scanned = 0;
        $batch_size = max(1, $batch_size);

        $tables = $this->get_tables();
        if ($this->last_error !== null) {
            $errors[] = 'SHOW TABLES failed: ' . $this->last_error;
            return [
                'findings'       => [],
                'tables_scanned' => 0,
                'rows_scanned'   => 0,
                'incomplete'     => true,
                'errors'         => $errors,
            ];
        }

        $base_prefix = !empty($wpdb->base_prefix) ? (string) $wpdb->base_prefix : (string) ($wpdb->prefix ?? 'wp_');
        $quoted_base = preg_quote($base_prefix, '/');

        foreach ($tables as $tbl) {
            if ($monitor !== null && $monitor->is_nearing_limits()) {
                $incomplete = true;
                $errors[] = 'Custom table scan yielded early due to PHP memory/resource limit.';
                break;
            }

            // Skip WordPress core options & comments tables (audited by OptionScanner & CommentScanner)
            if (preg_match('/^' . $quoted_base . '(?:\d+_)?(?:options|comments)$/i', (string) $tbl) === 1) {
                continue;
            }

            if (class_exists('\\WebCareProScanner\\System\\SettingsManager') && \WebCareProScanner\System\SettingsManager::is_table_excluded((string) $tbl)) {
                continue;
            }

            $meta = $this->get_table_metadata((string) $tbl);
            if ($this->last_error !== null) {
                $incomplete = true;
                $errors[] = sprintf('%s metadata error: %s', (string) $tbl, $this->last_error);
                continue;
            }
            if (empty($meta['columns'])) {
                continue;
            }

            $tables_scanned++;
            $cursor = 0;
            while ($cursor !== null) {
                if ($monitor !== null && $monitor->throttle_and_check()) {
                    $incomplete = true;
                    $errors[] = sprintf('Custom table scan paused at %s due to resource ceiling.', (string) $tbl);
                    break 2;
                }

                $batch_res = $this->scan_table_batch(
                    (string) $tbl,
                    $meta['columns'],
                    $meta['primary_key'],
                    $cursor,
                    $batch_size,
                    $scan_id,
                    $meta['order_by_columns'] ?? null,
                    $meta['has_unique_ordering'] ?? null
                );

                $rows_scanned += (int) ($batch_res['rows_scanned'] ?? 0);
                if (!empty($batch_res['findings'])) {
                    $findings = array_merge($findings, $batch_res['findings']);
                }

                if ($this->last_error !== null) {
                    $incomplete = true;
                    $errors[] = sprintf('%s batch error: %s', (string) $tbl, $this->last_error);
                    break;
                }

                $next = $batch_res['next_cursor'] ?? null;
                if ($next === null || (int) $next <= $cursor) {
                    break;
                }
                $cursor = (int) $next;
            }
        }

        return [
            'findings'       => $findings,
            'tables_scanned' => $tables_scanned,
            'rows_scanned'   => $rows_scanned,
            'incomplete'     => $incomplete,
            'errors'         => $errors,
        ];
    }
}
