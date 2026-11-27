<?php
namespace WebCareProScanner\Database;

use WebCareProScanner\Findings\Finding;
use WebCareProScanner\Malware\WebshellDetector;
use WebCareProScanner\Malware\JavaScriptSecurityScanner;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Database Fileless PHP & JS Code Snippet Auditor.
 *
 * Audits code snippets stored in MySQL tables (wp_snippets, wp_posts wpcode/elementor_snippet,
 * and wp_options headers/footers) using AST/tokenizer WebshellDetector and
 * in-memory JavaScriptSecurityScanner.
 */
class SnippetCodeAuditor {

    private $webshell_detector;
    private $js_scanner;
    private ?string $last_error = null;

    public function __construct() {
        $this->webshell_detector = class_exists(WebshellDetector::class) ? new WebshellDetector() : null;
        $this->js_scanner        = class_exists(JavaScriptSecurityScanner::class) ? new JavaScriptSecurityScanner() : null;
    }

    /**
     * Return the last sanitized database/runtime error encountered during snippet scanning.
     */
    public function get_last_error(): ?string {
        return $this->last_error;
    }

    /**
     * Scan all known database code storage locations.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan(string $scan_id): array {
        $this->last_error = null;
        $findings = [];

        // 1. Audit Code Snippets table (wp_snippets)
        $snippets_findings = $this->audit_code_snippets_table($scan_id);
        $findings = array_merge($findings, $snippets_findings);

        // 2. Audit Custom Code Posts (wpcode, elementor_snippet, custom_css, wbcr-snippets, custom_css_js)
        $posts_findings = $this->audit_code_posts($scan_id);
        $findings = array_merge($findings, $posts_findings);

        // 3. Audit Header/Footer & Snippet Options in wp_options
        $options_findings = $this->audit_snippet_options($scan_id);
        $findings = array_merge($findings, $options_findings);

        return $findings;
    }

    /**
     * Audit wp_snippets table (Code Snippets plugin).
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_code_snippets_table(string $scan_id): array {
        global $wpdb;
        $findings = [];
        $snippets_table = $wpdb->prefix . 'snippets';

        try {
            // Audit both active=1 and staged inactive snippets across site and multisite tables, plus Header Footer Code Manager (hfcm_scripts)
            $candidate_tables = array_unique([
                $snippets_table,
                ($wpdb->base_prefix ?? $wpdb->prefix) . 'ms_snippets',
            ]);

            foreach ($candidate_tables as $tbl) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $tbl));
                if ($exists !== $tbl) {
                    continue;
                }
                if (isset($wpdb->last_error)) {
                    $wpdb->last_error = '';
                }
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $rows = $wpdb->get_results("SELECT id, name, code, active FROM `{$tbl}` LIMIT 500", OBJECT);
                if (!empty($wpdb->last_error)) {
                    $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
                    continue;
                }
                if (!is_array($rows)) {
                    continue;
                }
                foreach ($rows as $row) {
                    $id   = (int) ($row->id ?? 0);
                    $name = sanitize_text_field($row->name ?? "Snippet #{$id}");
                    $code = (string) ($row->code ?? '');
                    if (trim($code) === '') {
                        continue;
                    }
                    $state_tag  = !empty($row->active) ? 'active' : 'staged/inactive';
                    $context_id = "{$tbl}:#{$id} ({$name} [{$state_tag}])";
                    $findings   = array_merge($findings, $this->audit_code_string($code, $context_id, $scan_id, 'php'));
                }
            }

            // Header Footer Code Manager (wp_hfcm_scripts, 1M+ installs)
            $hfcm_table = $wpdb->prefix . 'hfcm_scripts';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $hfcm_table)) === $hfcm_table) {
                if (isset($wpdb->last_error)) {
                    $wpdb->last_error = '';
                }
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $hfcm_rows = $wpdb->get_results("SELECT script_id, name, snippet, status FROM `{$hfcm_table}` LIMIT 500", OBJECT);
                if (!empty($wpdb->last_error)) {
                    $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
                } elseif (is_array($hfcm_rows)) {
                    foreach ($hfcm_rows as $hrow) {
                        $hid   = (int) ($hrow->script_id ?? 0);
                        $hname = sanitize_text_field($hrow->name ?? "HFCM #{$hid}");
                        $hcode = (string) ($hrow->snippet ?? '');
                        if (trim($hcode) !== '') {
                            $findings = array_merge($findings, $this->audit_code_string($hcode, "{$hfcm_table}:#{$hid} ({$hname})", $scan_id, 'mixed'));
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            $this->last_error = substr(sanitize_text_field($e->getMessage()), 0, 180);
        }

        return $findings;
    }

    /**
     * Audit CPT rows storing code snippets (wpcode, elementor_snippet, wbcr-snippets, custom_css_js).
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_code_posts(string $scan_id): array {
        global $wpdb;
        $findings = [];

        try {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $rows = $wpdb->get_results(
                "SELECT ID, post_title, post_content, post_type 
                 FROM `{$wpdb->posts}` 
                 WHERE post_type IN ('wpcode', 'elementor_snippet', 'wbcr-snippets', 'custom-css-js', 'custom_css_js', 'custom_css', 'astra-advanced-hook', 'gp_elements', 'kadence_element') 
                   AND post_status IN ('publish', 'draft', 'private') 
                 LIMIT 500",
                OBJECT
            );

            // Also audit Woody Snippets code stored in wp_postmeta (wbcr_inp_snippet_code)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $woody_meta = $wpdb->get_results(
                "SELECT post_id, meta_value FROM `{$wpdb->postmeta}` WHERE meta_key = 'wbcr_inp_snippet_code' LIMIT 250",
                OBJECT
            );
            if (is_array($woody_meta)) {
                foreach ($woody_meta as $wm) {
                    $wcode = (string) ($wm->meta_value ?? '');
                    if (trim($wcode) !== '') {
                        $findings = array_merge($findings, $this->audit_code_string($wcode, "{$wpdb->postmeta}:post_#{$wm->post_id}:wbcr_inp_snippet_code", $scan_id, 'php'));
                    }
                }
            }

            if (empty($rows) || !is_array($rows)) {
                return $findings;
            }

            foreach ($rows as $row) {
                $id = (int) ($row->ID ?? 0);
                $title = sanitize_text_field($row->post_title ?? "Post #{$id}");
                $content = (string) ($row->post_content ?? '');
                $type = (string) ($row->post_type ?? '');

                if (empty(trim($content))) {
                    continue;
                }

                // Core custom_css only renders in <style> tags. Only scan if it breaks out of CSS with script/PHP
                if ($type === 'custom_css') {
                    if (!preg_match('/(?:<\/(?:style|css)>|<script|<\?(?:php|=))/i', $content)) {
                        continue;
                    }
                }

                $context_id = "{$wpdb->posts}:#{$id} [{$type}] ({$title})";
                $snippet_findings = $this->audit_code_string($content, $context_id, $scan_id, 'mixed');
                $findings = array_merge($findings, $snippet_findings);
            }
        } catch (\Throwable $e) {
            $this->last_error = substr(sanitize_text_field($e->getMessage()), 0, 180);
        }

        if (!empty($wpdb->last_error) && $this->last_error === null) {
            $this->last_error = substr(sanitize_text_field((string) $wpdb->last_error), 0, 180);
        }

        return $findings;
    }

    /**
     * Audit custom code and script injection options in wp_options.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_snippet_options(string $scan_id): array {
        global $wpdb;
        $findings = [];
        $options_table = $wpdb->prefix . 'options';

        $target_options = [
            'ihaf_insert_header',
            'ihaf_insert_footer',
            'wpcode_snippets',
            'wpcode_custom_snippets',
            'header_footer_scripts',
            'header_scripts',
            'footer_scripts',
            'et_divi', // Divi Builder integration code
            'wpex_custom_css',
        ];

        foreach ($target_options as $opt_name) {
            $raw_val = get_option($opt_name);
            if (empty($raw_val)) {
                continue;
            }

            // Handle serialized option structures (e.g. Divi theme options or wpcode arrays)
            if (is_array($raw_val)) {
                $this->recurse_array_code($raw_val, "{$options_table}:{$opt_name}", $scan_id, $findings);
            } elseif (is_string($raw_val) && !empty(trim($raw_val))) {
                $context_id = "{$options_table}:{$opt_name}";
                $snippet_findings = $this->audit_code_string($raw_val, $context_id, $scan_id, 'mixed');
                $findings = array_merge($findings, $snippet_findings);
            }
        }

        return $findings;
    }

    /**
     * Recursively scan nested arrays of options (such as Divi integration arrays).
     *
     * @param array $arr
     * @param string $prefix
     * @param string $scan_id
     * @param array $findings
     */
    private function recurse_array_code(array $arr, string $prefix, string $scan_id, array &$findings): void {
        foreach ($arr as $k => $v) {
            $curr_key = "{$prefix}[{$k}]";
            if (is_array($v)) {
                $this->recurse_array_code($v, $curr_key, $scan_id, $findings);
            } elseif (is_string($v) && strlen($v) > 20) {
                // Only scan strings that could conceivably contain scripts or PHP code
                if (preg_match('/(?:<script|<\?(?:php|=)|\beval\b|\bdocument\.write\b|function\s*\(|navigator\.clipboard)/i', $v)) {
                    $item_findings = $this->audit_code_string($v, $curr_key, $scan_id, 'mixed');
                    $findings = array_merge($findings, $item_findings);
                }
            }
        }
    }

    /**
     * Core Code Auditor: Normalizes code headers and executes WebshellDetector and JavaScriptSecurityScanner in memory.
     *
     * @param string $code
     * @param string $context_id
     * @param string $scan_id
     * @param string $mode 'php'|'js'|'mixed'
     * @return Finding[]
     */
    public function audit_code_string(string $code, string $context_id, string $scan_id, string $mode = 'mixed'): array {
        $findings = [];
        $unslashed_code = wp_unslash($code);

        // 1. PHP Code Inspection
        if ($mode === 'php' || $mode === 'mixed') {
            // Normalize header: Code Snippets & WPCode strip the opening <?php tag!
            // PHP's tokenizer treats code without <?php as raw T_INLINE_HTML, evading AST analysis.
            $php_code = $unslashed_code;
            if (!preg_match('/^\s*<\?(?:php|=)/i', $php_code)) {
                $php_code = "<?php\n" . $php_code;
            }

            $virtual_file = "/database_snippet/{$context_id}.php";
            $res = ($this->webshell_detector !== null) ? $this->webshell_detector->scan($virtual_file, $php_code, $scan_id) : null;
            if ($res === null && class_exists('\\WebCareProScanner\\Malware\\DeobfuscationEngine')) {
                $deobf = new \WebCareProScanner\Malware\DeobfuscationEngine();
                $res = $deobf->scan($virtual_file, $php_code, $scan_id);
            }
            if ($res === null && class_exists('\\WebCareProScanner\\Malware\\ObfuscationDetector')) {
                $obf = new \WebCareProScanner\Malware\ObfuscationDetector();
                $res = $obf->scan($virtual_file, $php_code, $scan_id);
            }
            if ($res !== null) {
                $findings[] = new Finding([
                    'engine'      => 'database-snippets',
                    'type'        => 'database_stored_webshell',
                    'severity'    => 'critical',
                    'confidence'  => $res->confidence ?? 99,
                    'file_path'   => $context_id,
                    'description' => "Database-stored executable PHP backdoor/webshell detected in code snippet. Attackers use snippet plugins for fileless persistence.",
                    'evidence'    => $res->evidence ?? $res->description,
                    'code_snippet'=> substr($unslashed_code, 0, 400),
                ]);
            }
        }

        // 2. JavaScript & External <script src="..."> Inspection
        if ($mode === 'js' || $mode === 'mixed') {
            if (stripos($unslashed_code, '<script') !== false && class_exists('\\WebCareProScanner\\Content\\HTMLAnalyzer')) {
                $html_analyzer = new \WebCareProScanner\Content\HTMLAnalyzer();
                foreach ($html_analyzer->detect_hidden_elements($unslashed_code) as $hh) {
                    if ($hh['type'] === 'remote_script_injection' || $hh['type'] === 'hidden_iframe') {
                        $findings[] = new Finding([
                            'engine'       => 'database-snippets',
                            'type'         => 'database_stored_js_trojan',
                            'severity'     => 'critical',
                            'confidence'   => $hh['confidence'] ?? 96,
                            'file_path'    => $context_id,
                            'description'  => $hh['desc'],
                            'evidence'     => $hh['snippet'],
                            'code_snippet' => substr($hh['snippet'], 0, 400),
                        ]);
                    }
                }
            }
            // Extract raw JS if wrapped in <script> tags, or evaluate raw JS
            $js_to_scan = $unslashed_code;
            if (preg_match_all('/<script\b[^>]*>([\s\S]*?)<\/script>/i', $unslashed_code, $matches)) {
                $js_to_scan = implode("\n;\n", $matches[1]);
            }

            if ($this->js_scanner !== null && !empty(trim($js_to_scan))) {
                $virtual_path = "/database_snippet/{$context_id}.js";
                $js_findings = $this->js_scanner->scan_content($js_to_scan, $virtual_path, $scan_id);
                foreach ($js_findings as $jf) {
                    $findings[] = new Finding([
                        'engine'      => 'database-snippets',
                        'type'        => 'database_stored_js_trojan',
                        'severity'    => $jf->severity ?? 'critical',
                        'confidence'  => $jf->confidence ?? 95,
                        'file_path'   => $context_id,
                        'description' => "Database-stored malicious client-side JavaScript detected in snippet (Magecart, ClickFix, or malvertising redirect).",
                        'evidence'    => $jf->evidence ?? $jf->description,
                        'code_snippet'=> substr($js_to_scan, 0, 400),
                    ]);
                }
            }
        }

        return $findings;
    }
}
