<?php
namespace WebCareProScanner\Content;

if (!defined('ABSPATH')) {
    exit;
}

class HTMLAnalyzer {

    /**
     * Inspect HTML content for hidden spam, CSS cloaking tricks, and deceptive elements.
     *
     * @param string $html
     * @return array List of findings details ['type', 'snippet', 'desc', 'severity', 'confidence']
     */
    public function detect_hidden_elements($html) {
        $detections = [];

        if (empty($html) || !is_string($html)) {
            return $detections;
        }

        // 1. Off-screen positioning (e.g. left:-9999px or top:-10000px) concealing external anchor links
        // Exclude accessible skip links (e.g. href="#content") and ensure the style directly applies to the link or its immediate wrapper
        if (preg_match('/(?:<a\s+[^>]*style\s*=\s*["\'][^"\']*(?:left|top)\s*:\s*-\s*[0-9]{3,}(?:px|em)[^"\']*["\'][^>]*href\s*=\s*["\']https?:\/\/|<(?:div|p|span|li)[^>]*style\s*=\s*["\'][^"\']*(?:left|top)\s*:\s*-\s*[0-9]{3,}(?:px|em)[^"\']*["\'][^>]*>\s*<a\s+[^>]*href\s*=\s*["\']https?:\/\/)/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_offscreen_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Off-screen negative CSS positioning hiding external anchor links.',
                'severity'   => 'high',
                'confidence' => 90
            ];
        }

        // 2. Invisible text tricks: display:none, visibility:hidden, opacity:0, font-size:0 wrapping external links
        // Tightened to apply directly to the anchor or immediate container (<div ...><a ...) to prevent matching entire document
        if (preg_match('/(?:<a\s+[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em)?)[^"\']*["\'][^>]*href\s*=\s*["\']https?:\/\/|<(?:div|p|span|li)[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em)?)[^"\']*["\'][^>]*>\s*<a\s+[^>]*href\s*=\s*["\']https?:\/\/)/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_hidden_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Invisible CSS styles (display:none, opacity:0, font-size:0) concealing links.',
                'severity'   => 'high',
                'confidence' => 88
            ];
        }

        // 3. Hidden or zero-dimension iframes (exclude legitimate video/audio/map embeds)
        if (preg_match('/<iframe[^>]*(?:width\s*=\s*["\']?[01]["\']?|height\s*=\s*["\']?[01]["\']?|style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\'])[^>]*>/i', $html, $matches)) {
            $is_trusted_embed = (bool) preg_match('/\bsrc\s*=\s*["\']?https?:\/\/(?:www\.)?(?:youtube\.com|youtube-nocookie\.com|player\.vimeo\.com|vimeo\.com|spotify\.com|soundcloud\.com|maps\.google\.com|google\.com\/maps)/i', $matches[0]);
            if (!$is_trusted_embed) {
                $detections[] = [
                    'type'       => 'hidden_iframe',
                    'snippet'    => substr($matches[0], 0, 150),
                    'desc'       => 'Concealed zero-dimension or hidden iframe element detected.',
                    'severity'   => 'critical',
                    'confidence' => 95
                ];
            }
        }

        // 4. Meta refresh cloaked redirect in content
        if (preg_match('/<meta\s+[^>]*http-equiv\s*=\s*\\\\?["\']?refresh\\\\?["\']?[^>]*content\s*=\s*\\\\?["\']?[0-9]*\s*;\s*url\s*=\s*([^"\'\\\\>\s]+)/i', $html, $m_meta)) {
            $target_url = trim($m_meta[1]);
            $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
            $target_host = wp_parse_url($target_url, PHP_URL_HOST) ?: '';

            if (!empty($target_host) && $home_host && strtolower($target_host) !== strtolower($home_host) && !str_ends_with(strtolower($target_host), '.' . strtolower($home_host))) {
                $detections[] = [
                    'type'       => 'content_meta_refresh_redirect',
                    'snippet'    => substr($m_meta[0], 0, 150),
                    'desc'       => sprintf('Malicious meta refresh redirect detected in content targeting external host "%s". Visitors are hijacked immediately.', esc_html($target_host)),
                    'severity'   => 'critical',
                    'confidence' => 99,
                ];
            }
        }

        // 5. Inline JavaScript redirect in content (<script>...window.location... or location.replace)
        if (preg_match_all('/<script\b[^>]*>(.*?)<\/script>/is', $html, $script_matches)) {
            $js_scanner = new \WebCareProScanner\Malware\JavaScriptSecurityScanner();
            foreach ($script_matches[1] as $idx => $script_body) {
                $script_body = trim($script_body);
                if (empty($script_body)) {
                    continue;
                }

                // Direct DOM redirect detection
                if (preg_match('/(?:window\.location(?:\.replace|\.href|\s*=)|location\.replace\s*\(|location\.href\s*=|document\.location\s*=)\s*[\'"`]?(https?:\/\/[^\s\'"`\);]+)/i', $script_body, $redir_m)) {
                    $dest_url = $redir_m[1];
                    $dest_host = wp_parse_url($dest_url, PHP_URL_HOST) ?: '';
                    $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';

                    if ($dest_host && $home_host && strtolower($dest_host) !== strtolower($home_host) && !str_ends_with(strtolower($dest_host), '.' . strtolower($home_host))) {
                        $detections[] = [
                            'type'       => 'content_dom_redirect',
                            'snippet'    => substr($script_matches[0][$idx], 0, 160),
                            'desc'       => sprintf('Inline JavaScript redirect in content hijacking visitors to external host "%s".', esc_html($dest_host)),
                            'severity'   => 'critical',
                            'confidence' => 96,
                        ];
                        continue;
                    }
                }

                // Run full JS security scanner on inline content
                $js_hits = $js_scanner->scan_content($script_body, 'inline_content_script', 'content_scan');
                foreach ($js_hits as $hit) {
                    $detections[] = [
                        'type'       => 'content_malicious_inline_js',
                        'snippet'    => substr($hit->code_snippet ?? $script_matches[0][$idx], 0, 160),
                        'desc'       => $hit->description . ' (' . $hit->evidence . ')',
                        'severity'   => $hit->severity,
                        'confidence' => $hit->confidence,
                    ];
                }
            }
        }

        // 8. JSON-LD Structured Data Schema Poisoning & GEO AI SEO Shield
        if (class_exists('\\WebCareProScanner\\Content\\GeoShieldService')) {
            $jsonld_hits = \WebCareProScanner\Content\GeoShieldService::audit_jsonld_schemas($html);
            if (!empty($jsonld_hits)) {
                $detections = array_merge($detections, $jsonld_hits);
            }

            // 9. GEO Invisible CSS Cloaking (Transparent text, contrast cloaking, abused sr-only)
            $geo_cloak_hits = \WebCareProScanner\Content\GeoShieldService::audit_geo_cloaking($html);
            if (!empty($geo_cloak_hits)) {
                $detections = array_merge($detections, $geo_cloak_hits);
            }
        }

        // 10. 2026–2027 Unicode Tag-Plane (U+E0000..U+E007F) & Stored Indirect Prompt Injection / MCP Poisoning
        if (preg_match('/(?:\xF3\xA0[\x80-\x81][\x80-\xBF]){8,}/', $html)) {
            $detections[] = [
                'type'       => 'unicode_tag_smuggling',
                'snippet'    => '[Invisible Unicode Tag-Plane U+E0000..U+E007F payload]',
                'desc'       => 'Invisible Unicode Tag-Plane ASCII smuggling payload detected in content (used for AI prompt injection & covert instructions).',
                'severity'   => 'critical',
                'confidence' => 96,
            ];
        }
        if (preg_match('/(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|<!--)[\s\S]{0,300}?(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<\|im_start\|>\s*system|\[INST\]\s*<<SYS>>|\b(?:wp_create_user|update_option)\b[\s\S]{0,80}\badministrator\b)/i', $html, $pi_match)) {
            $detections[] = [
                'type'       => 'indirect_prompt_injection',
                'snippet'    => substr($pi_match[0], 0, 160),
                'desc'       => 'Hidden Indirect Prompt Injection / AI Agent poisoning directive concealed in content.',
                'severity'   => 'critical',
                'confidence' => 95,
            ];
        }

        // 10. WordPress 6.5+ / 7.0+ Interactivity API & Gutenberg Block Directive Sanitization
        if (class_exists('\\WebCareProScanner\\Content\\BlockDirectiveSanitizer')) {
            $block_hits = \WebCareProScanner\Content\BlockDirectiveSanitizer::audit_content($html);
            if (!empty($block_hits)) {
                $detections = array_merge($detections, $block_hits);
            }
        }

        // 11. WordPress 7.0+ WP_HTML_Tag_Processor Deep Streaming Security Audit (with HTML-aware attribute fallback)
        // Handles quoted, single-quoted, and unquoted attribute values (e.g. <script src=https://evil.example/a.js>).
        $home_host = strtolower((string) (wp_parse_url(home_url(), PHP_URL_HOST) ?: ''));
        // phpcs:disable PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Allowlist of trusted CDN hostnames for malware/injection detection, not offloaded assets.
        $trusted_cdn_hosts = [
            'youtube.com', 'vimeo.com', 'cdnjs.cloudflare.com', 'code.jquery.com',
            'platform.twitter.com', 'connect.facebook.net', 'googletagmanager.com',
            'google-analytics.com', 'recaptcha.net', 'google.com', 'gstatic.com',
            'stripe.com', 'reviews.io', 'ordertracker.com', 'logwork.com',
            'trustpilot.com', 'yotpo.com', 'klaviyo.com', 'privy.com',
            'elfsight.com', 'judge.me', 'ahrefs.com',
        ];
        // phpcs:enable PluginCheck.CodeAnalysis.Offloading.OffloadedContent

        $inspect_external_script = static function (string $raw_src, string $snippet) use (&$detections, $home_host, $trusted_cdn_hosts): void {
            $decoded_src = self::decode_html_attribute_value($raw_src);
            $clean_src   = trim((string) preg_replace('/[\x00-\x20]+/', '', $decoded_src));
            if ($clean_src === '' || !preg_match('#^(?:https?:)?//#i', $clean_src)) {
                return;
            }
            $norm_src = str_starts_with($clean_src, '//') ? 'https:' . $clean_src : $clean_src;
            $src_host = rtrim(strtolower((string) (wp_parse_url($norm_src, PHP_URL_HOST) ?: '')), '.');
            if ($src_host === '') {
                return;
            }
            if ($home_host !== '' && ($src_host === $home_host || str_ends_with($src_host, '.' . $home_host))) {
                return;
            }
            foreach ($trusted_cdn_hosts as $cdn) {
                if ($src_host === $cdn || str_ends_with($src_host, '.' . $cdn)) {
                    return;
                }
            }
            $detections[] = [
                'type'       => 'remote_script_injection',
                'snippet'    => substr($snippet, 0, 150),
                'desc'       => sprintf('Remote JavaScript injection from untrusted host "%s" detected within content.', esc_html($src_host)),
                'severity'   => 'critical',
                'confidence' => 98,
            ];
        };

        $inspect_base_href = static function (string $raw_href, string $snippet) use (&$detections, $home_host): void {
            $decoded_href = self::decode_html_attribute_value($raw_href);
            $base_url     = trim((string) preg_replace('/[\x00-\x20]+/', '', $decoded_href));
            if ($base_url === '' || !preg_match('#^https?://#i', $base_url)) {
                return;
            }
            $base_host = rtrim(strtolower((string) (wp_parse_url($base_url, PHP_URL_HOST) ?: '')), '.');
            if ($base_host !== '' && $home_host !== '' && $base_host !== $home_host && !str_ends_with($base_host, '.' . $home_host)) {
                $detections[] = [
                    'type'       => 'content_base_href_hijack',
                    'snippet'    => substr($snippet, 0, 150),
                    'desc'       => sprintf('Malicious <base href> tag detected targeting external host "%s". All relative links, scripts, and form submissions will be stolen.', esc_html($base_host)),
                    'severity'   => 'critical',
                    'confidence' => 98,
                ];
            }
        };

        if (class_exists('\\WP_HTML_Tag_Processor')) {
            $processor = new \WP_HTML_Tag_Processor($html);
            while ($processor->next_tag()) {
                $tag_name = strtolower((string) $processor->get_tag());

                if ($tag_name === 'script') {
                    $script_src = $processor->get_attribute('src');
                    if (is_string($script_src) && $script_src !== '') {
                        // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Formatting detected malicious script snippet for scanner report.
                        $inspect_external_script($script_src, sprintf('<script src="%s">', esc_attr(substr($script_src, 0, 120))));
                    }
                } elseif ($tag_name === 'base') {
                    $base_href = $processor->get_attribute('href');
                    if (is_string($base_href) && $base_href !== '') {
                        $inspect_base_href($base_href, sprintf('<base href="%s">', esc_attr(substr($base_href, 0, 120))));
                    }
                }

                // Inspect interactive attributes for JavaScript protocol injection
                foreach (['href', 'src', 'action', 'formaction', 'data', 'poster'] as $attr) {
                    $attr_val = $processor->get_attribute($attr);
                    if (is_string($attr_val) && $attr_val !== '') {
                        $norm_attr = strtolower((string) (preg_replace('/[\x00-\x20]+/', '', self::decode_html_attribute_value($attr_val)) ?? ''));
                        // Ignore benign null-op UI placeholder links (e.g. Elementor/theme nav dropdowns using href="javascript:void(0);" or "javascript:;")
                        if (preg_match('/^javascript:(?:void\s*\(\s*0?\s*\)|;)*$/i', $norm_attr)) {
                            continue;
                        }
                        if (str_starts_with($norm_attr, 'javascript:') || str_starts_with($norm_attr, 'vbscript:') || str_starts_with($norm_attr, 'data:text/html')) {
                            $detections[] = [
                                'type'       => 'html_processor_javascript_uri',
                                'snippet'    => sprintf('<%s %s="%s">', esc_html($tag_name), esc_html($attr), esc_attr(substr($attr_val, 0, 80))),
                                'desc'       => sprintf('Executable javascript:/vbscript:/data: URI protocol found in <%s> attribute "%s".', esc_html($tag_name), esc_html($attr)),
                                'severity'   => 'critical',
                                'confidence' => 99,
                            ];
                        }
                    }
                }

                // Inspect inline style attributes via tag processor
                $style_val = $processor->get_attribute('style');
                if (is_string($style_val) && $style_val !== '') {
                    $norm_style = strtolower(str_replace(["\0", "\r", "\n", "\t", ' '], '', $style_val));
                    if (str_contains($norm_style, 'expression(') || str_contains($norm_style, '-moz-binding') || str_contains($norm_style, 'behavior:url(')) {
                        $detections[] = [
                            'type'       => 'html_processor_css_expression',
                            'snippet'    => sprintf('<%s style="%s">', esc_html($tag_name), esc_attr(substr($style_val, 0, 80))),
                            'desc'       => sprintf('Dynamic CSS expression execution vector detected in <%s> style attribute.', esc_html($tag_name)),
                            'severity'   => 'critical',
                            'confidence' => 97,
                        ];
                    }
                }
            }
        } else {
            // HTML-aware fallback parser when WP_HTML_Tag_Processor is absent (e.g. standalone CLI/unit-test runtime)
            foreach (self::extract_html_tag_attributes($html, ['script', 'base']) as $tag_entry) {
                if ($tag_entry['tag'] === 'script' && isset($tag_entry['attrs']['src']) && is_string($tag_entry['attrs']['src'])) {
                    $inspect_external_script($tag_entry['attrs']['src'], $tag_entry['raw']);
                } elseif ($tag_entry['tag'] === 'base' && isset($tag_entry['attrs']['href']) && is_string($tag_entry['attrs']['href'])) {
                    $inspect_base_href($tag_entry['attrs']['href'], $tag_entry['raw']);
                }
            }
        }

        return $detections;
    }

    /**
     * Multi-pass decode HTML character entities (up to 3 passes).
     */
    private static function decode_html_attribute_value(string $value): string {
        $norm = $value;
        for ($i = 0; $i < 3; $i++) {
            $decoded = html_entity_decode($norm, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($decoded === $norm) {
                break;
            }
            $norm = $decoded;
        }
        return $norm;
    }

    /**
     * HTML-aware tag & attribute extractor supporting quoted, single-quoted, and unquoted attribute values.
     *
     * @param string $html
     * @param list<string> $target_tags
     * @return list<array{tag: string, raw: string, attrs: array<string, string>}>
     */
    private static function extract_html_tag_attributes(string $html, array $target_tags): array {
        $stripped = preg_replace('/<!--[\s\S]*?-->/', '', $html) ?? $html;
        $tag_alt  = implode('|', array_map(static fn(string $t) => preg_quote(strtolower($t), '/'), $target_tags));
        $results  = [];

        if (!preg_match_all('/<(' . $tag_alt . ')\b((?:[^>"\']+|"[^"]*"|\'[^\']*\')*)>/i', $stripped, $tag_matches, PREG_SET_ORDER)) {
            return $results;
        }

        foreach ($tag_matches as $tm) {
            $tag_name  = strtolower($tm[1]);
            $attr_text = $tm[2] ?? '';
            $attrs     = [];

            if (preg_match_all('/\b([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?/', $attr_text, $attr_matches, PREG_SET_ORDER)) {
                foreach ($attr_matches as $am) {
                    $attr_key = strtolower($am[1]);
                    $attr_val = '';
                    if (isset($am[2]) && $am[2] !== '') {
                        $attr_val = $am[2];
                    } elseif (isset($am[3]) && $am[3] !== '') {
                        $attr_val = $am[3];
                    } elseif (isset($am[4]) && $am[4] !== '') {
                        $attr_val = $am[4];
                    }
                    if (!isset($attrs[$attr_key])) {
                        $attrs[$attr_key] = $attr_val;
                    }
                }
            }

            $results[] = [
                'tag'   => $tag_name,
                'raw'   => $tm[0],
                'attrs' => $attrs,
            ];
        }

        return $results;
    }
}
