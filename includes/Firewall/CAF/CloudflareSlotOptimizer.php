<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare Slot Optimizer (CAF Phase 2 - "4 + 1" Smart Cloudflare Edge System)
 *
 * Implements intelligent, non-destructive packing of WebCare Pro Edge rules into Cloudflare's Free Plan WAF (5-rule quota):
 * - Rule 1 (Action: BLOCK)             -> [WebCare Pro] Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List
 * - Rule 2 (Action: BLOCK)             -> [WebCare Pro] Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches
 * - Rule 3 (Action: MANAGED_CHALLENGE) -> [WebCare Pro] Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield
 * - Rule 4 (Action: BLOCK)             -> [WebCare Pro] Rule 4: Deep SQLi, LFI & Reconnaissance Armor
 * - Slot 5 (FREE / UNTOUCHED)          -> 100% Guaranteed Reserved for the Website Owner
 *
 * Enforces a strict 4,000-byte Wirefilter limit with graceful AST truncation and user rule preservation.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareSlotOptimizer {

    public const OPTION_MANAGED_RULE_IDS        = 'webcareproscan_cf_managed_rule_ids';
    public const OPTION_VISUAL_MANAGED_RULE_IDS = 'webcareproscan_cf_visual_managed_rule_ids';
    public const MAX_EXPRESSION_BYTES       = 4000; // Safety buffer below Cloudflare Free 4096-byte limit
    public const MAX_WEBCARE_SLOTS          = 4;    // Maximum slots WebCare can ever claim (Slot 5 is 100% reserved for owner)
    public const MAX_WCP_SLOTS              = 4;    // Backward compatibility alias
    public const WEBCARE_RULE_PREFIX        = '[WebCare Pro]';
    public const WEBCARE_RULE_TAG           = '[WebCare Pro Security]';
    public const WEBCARE_LEGACY_TAG         = '[WebCare Pro Security & Firewall]';
    public const WEBCARE_CAF_LEGACY_PREFIX  = '[WEBCARE-CAF:';
    public const WEBCARE_VISUAL_PREFIX      = '[WebCare-WAF]';
    public const WEBCARE_VISUAL_MARKER      = '[WEBCARE-MOD-VISUAL:';

    /**
     * Fetch existing rules safely with tri-state status reporting (CF-05).
     * Distinguishes between successful rulesets, fresh uninitialized zones (404 / 10003),
     * and actual network/API failures (timeouts, 5xx, 401/403).
     *
     * @param string $zone_id Cloudflare Zone ID
     * @return array ['ok' => bool, 'rules' => array, 'error' => string]
     */
    public function get_zone_rules_safe(string $zone_id): array {
        if (empty($zone_id)) {
            return [
                'ok'    => false,
                'rules' => [],
                'error' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security'),
            ];
        }

        $res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");

        if (!empty($res['success'])) {
            $rules = (!empty($res['result']['rules']) && is_array($res['result']['rules']))
                ? $res['result']['rules']
                : [];
            return [
                'ok'    => true,
                'rules' => $rules,
                'error' => '',
            ];
        }

        // Check if this is a fresh zone where the phase entrypoint ruleset hasn't been created yet (Finding 2.6)
        $err_code  = (int) ($res['errors'][0]['code'] ?? 0);
        $http_code = (int) ($res['http_code'] ?? 0);
        $err_msg   = strtolower((string) ($res['errors'][0]['message'] ?? ''));

        // Strictly recognize Cloudflare code 10003 or specific "ruleset not found" message (Finding 2.6)
        $is_fresh_entrypoint = (
            $err_code === 10003
            || ($http_code === 404 && (
                str_contains($err_msg, 'ruleset not found')
                || str_contains($err_msg, 'could not find ruleset')
                || str_contains($err_msg, 'phase entrypoint does not exist')
            ))
        );

        if ($is_fresh_entrypoint) {
            return [
                'ok'    => true,
                'rules' => [],
                'error' => '',
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to fetch zone rules from Cloudflare API.', 'webcare-pro-security');
        return [
            'ok'    => false,
            'rules' => [],
            'error' => $err,
        ];
    }

    /**
     * Fetch existing rules from Cloudflare Zone Custom Rulesets entrypoint.
     * Backwards-compatible wrapper around get_zone_rules_safe().
     *
     * @param string $zone_id Cloudflare Zone ID
     * @return array
     */
    public function get_zone_rules(string $zone_id): array {
        $safe = $this->get_zone_rules_safe($zone_id);
        return $safe['ok'] ? $safe['rules'] : [];
    }

    /**
     * Calculate remaining slot budget for WebCare-managed rules.
     * Strictly preserves user-defined rules and guarantees 1 free slot for the website owner across
     * the entire http_request_firewall_custom phase (Free plan max 5 rules total).
     *
     * WebCare claims at most min(4, max(0, 5 - 1 - count(all_non_webcare_phase_rules))).
     *
     * @param array $existing_rules List of rules currently on Cloudflare
     * @param array<string>|null $managed_rule_ids Persisted IDs of WebCare managed rules
     * @return int Number of available slots for WebCare (0 to 4)
     */
    public function calculate_webcare_slot_budget(array $existing_rules, ?array $managed_rule_ids = null): int {
        $non_webcare_rules = [];

        foreach ($existing_rules as $rule) {
            $rule_id = (string) ($rule['id'] ?? '');
            $desc = (string) ($rule['description'] ?? '');

            if (!$this->is_webcare_rule_entry($rule_id, $desc, $managed_rule_ids)) {
                $dedup_key = !empty($rule_id) ? $rule_id : $desc;
                $non_webcare_rules[$dedup_key] = true;
            }
        }

        $all_non_webcare_phase_rules = array_keys($non_webcare_rules);

        return (int) min(
            self::MAX_WEBCARE_SLOTS,
            max(0, 5 - 1 - count($all_non_webcare_phase_rules))
        );
    }

    /**
     * Check if a rule description belongs to Custom Firewall Rules Edge Sync.
     *
     * @param string $description
     * @return bool
     */
    public function is_visual_custom_rule(string $description): bool {
        return str_starts_with($description, self::WEBCARE_VISUAL_PREFIX)
            || str_contains($description, self::WEBCARE_VISUAL_MARKER);
    }

    /**
     * Check if a rule entry is a WebCare Visual Studio rule by ID or description.
     * Checks tracked visual rule IDs before description matching so user custom rules
     * whose descriptions happen to contain WebCare substrings are never reclassified.
     *
     * @param string $rule_id
     * @param string $description
     * @param array<string>|null $visual_rule_ids
     * @return bool
     */
    public function is_visual_custom_rule_entry(string $rule_id, string $description, ?array $visual_rule_ids = null): bool {
        if ($visual_rule_ids === null) {
            $stored = get_option(self::OPTION_VISUAL_MANAGED_RULE_IDS, []);
            $visual_rule_ids = is_array($stored) ? $stored : [];
        }

        // If tracked visual rule IDs exist and rule has an ID, enforce ID-based ownership
        if (!empty($rule_id) && !empty($visual_rule_ids)) {
            return in_array($rule_id, $visual_rule_ids, true);
        }

        return $this->is_visual_custom_rule($description);
    }

    /**
     * Check if a rule description indicates a WebCare-managed rule.
     *
     * @param string $description
     * @return bool
     */
    public function is_webcare_rule(string $description): bool {
        return str_starts_with($description, self::WEBCARE_RULE_PREFIX)
            || str_starts_with($description, '[WebCare Pro:')
            || str_starts_with($description, self::WEBCARE_RULE_TAG)
            || str_starts_with($description, self::WEBCARE_LEGACY_TAG)
            || str_starts_with($description, self::WEBCARE_CAF_LEGACY_PREFIX)
            || $this->is_visual_custom_rule($description)
            || str_contains($description, 'webcareproscan_compound_');
    }

    /**
     * Check if a rule entry is genuinely owned and managed by WebCare.
     * Enforces strict ID-based ownership when managed rule IDs are tracked,
     * ensuring customer rules containing description prefixes are never clobbered.
     *
     * @param string $rule_id
     * @param string $description
     * @param array<string>|null $managed_rule_ids
     * @return bool
     */
    public function is_webcare_rule_entry(string $rule_id, string $description, ?array $managed_rule_ids = null): bool {
        if ($managed_rule_ids === null) {
            $stored = get_option(self::OPTION_MANAGED_RULE_IDS, []);
            $managed_rule_ids = is_array($stored) ? $stored : [];
        }

        // If we have tracked managed rule IDs and rule has an ID, enforce ID-based ownership
        if (!empty($rule_id) && !empty($managed_rule_ids)) {
            return in_array($rule_id, $managed_rule_ids, true);
        }

        // Visual rules authored in WebCare Visual Studio
        if ($this->is_visual_custom_rule_entry($rule_id, $description)) {
            return true;
        }

        return $this->is_webcare_rule($description);
    }

    /**
     * Construct up to 4 optimized Master Compound Rules based on StackSnapshot and scoped patches.
     *
     * @param StackSnapshot $snapshot Current WordPress stack snapshot
     * @param array $scoped_patches Priority-sorted virtual patches relevant to active stack
     * @param bool $has_custom_ip_list Whether Account IP List ($webcare_threat_blocklist) is active
     * @param bool $origin_survival_active Whether Origin Survival Mode is currently active
     * @param int $slot_budget Maximum slots WebCare can occupy (capped at 4)
     * @return array
     */
    public function pack_ruleset_expressions(
        StackSnapshot $snapshot,
        mixed $scoped_patches = [],
        bool $has_custom_ip_list = false,
        bool $origin_survival_active = false,
        int $slot_budget = self::MAX_WEBCARE_SLOTS,
        array &$included_patch_ids = []
    ): array {
        $included_patch_ids = [];
        if (is_int($scoped_patches)) {
            $slot_budget = $scoped_patches;
            $scoped_patches = [];
        } elseif (!is_array($scoped_patches)) {
            $scoped_patches = [];
        }

        $budget = min(self::MAX_WEBCARE_SLOTS, max(0, $slot_budget));
        if ($budget <= 0) {
            return [];
        }

        // If scoped patches not passed, fetch automatically from VirtualPatchManager
        if (empty($scoped_patches) && class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $scoped_patches = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        }

        $webcare_rules = [];

        // RULE 1 (BLOCK): Zero-Day Perimeter, Malicious Sinks & Threat List
        $rule1_expr = $this->compile_rule1_perimeter_expression($has_custom_ip_list);
        $webcare_rules[] = [
            'action'      => 'block',
            'description' => self::WEBCARE_RULE_PREFIX . ' Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List',
            'enabled'     => true,
            'expression'  => $this->truncate_to_byte_budget($rule1_expr, self::MAX_EXPRESSION_BYTES),
        ];

        // RULE 2 (BLOCK): StackGuard Inactive Plugin Lockdown & Stack-Scoped CVE Virtual Patches
        if ($budget >= 2) {
            $rule2_expr = $this->compile_rule2_stackguard_expression($snapshot, $scoped_patches, $included_patch_ids);
            $webcare_rules[] = [
                'action'      => 'block',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule2_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        // RULE 3 (MANAGED_CHALLENGE): Adaptive Bot, Brute-Force & Under-Attack Velocity Shield
        if ($budget >= 3) {
            $rule3_expr = $this->compile_rule3_bot_challenge_expression($origin_survival_active);
            $webcare_rules[] = [
                'action'      => 'managed_challenge',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule3_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        // RULE 4 (BLOCK): Deep SQLi, LFI & Reconnaissance Armor
        if ($budget >= 4) {
            $rule4_expr = $this->compile_rule4_sqli_lfi_expression();
            $webcare_rules[] = [
                'action'      => 'block',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 4: Deep SQLi, LFI & Reconnaissance Armor',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule4_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        return $webcare_rules;
    }

    /**
     * Evaluate expression string length and truncate lowest-priority clauses safely if approaching max bytes.
     *
     * @param string $expression Raw Wirefilter expression joined by ' or '
     * @param int $max_bytes Byte limit (default: 4000)
     * @return string
     */
    public function truncate_to_byte_budget(string $expression, int $max_bytes = self::MAX_EXPRESSION_BYTES): string {
        if (strlen($expression) <= $max_bytes) {
            return $expression;
        }

        $clauses = explode(' or ', $expression);
        $safe_clauses = [];

        foreach ($clauses as $clause) {
            $candidate = empty($safe_clauses) ? $clause : implode(' or ', array_merge($safe_clauses, [$clause]));
            if (strlen($candidate) > $max_bytes) {
                break;
            }
            $safe_clauses[] = $clause;
        }

        return !empty($safe_clauses) ? implode(' or ', $safe_clauses) : substr($expression, 0, $max_bytes);
    }

    /**
     * Executes non-destructive upsert via Cloudflare Ruleset API.
     * Strictly preserves user custom rules and guarantees 1 slot remains free for the owner.
     *
     * @param string $zone_id Cloudflare Zone ID
     * @param StackSnapshot|null $snapshot Optional snapshot; fetched automatically if omitted
     * @param array $scoped_patches Optional scoped virtual patches
     * @param bool $origin_survival_active Origin survival flag
     * @return array
     */
    public function deploy_to_cloudflare(
        string $zone_id,
        ?StackSnapshot $snapshot = null,
        array $scoped_patches = [],
        bool $origin_survival_active = false
    ): array {
        if (empty($zone_id)) {
            return [
                'success' => false,
                'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security'),
            ];
        }

        // 1. Fetch existing rules safely to preserve both Custom Firewall Rules and user-defined custom rules (CF-05)
        $fetch = $this->get_zone_rules_safe($zone_id);
        if (empty($fetch['ok'])) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: Cloudflare API error description */
                    __('Aborted Cloudflare ruleset sync: Could not verify existing zone rules from Cloudflare API (%s). Customer rules were left untouched.', 'webcare-pro-security'),
                    $fetch['error'] ?? 'API connection failure'
                ),
            ];
        }

        $existing_rules = $fetch['rules'];
        $managed_ids    = get_option(self::OPTION_MANAGED_RULE_IDS, []);
        $managed_ids    = is_array($managed_ids) ? $managed_ids : [];
        $visual_ids     = get_option(self::OPTION_VISUAL_MANAGED_RULE_IDS, []);
        $visual_ids     = is_array($visual_ids) ? $visual_ids : [];

        $visual_rules   = [];
        $user_rules     = [];
        $stale_webcare  = [];

        foreach ($existing_rules as $rule) {
            $rule_id = (string) ($rule['id'] ?? '');
            $desc    = (string) ($rule['description'] ?? '');

            if ($this->is_visual_custom_rule_entry($rule_id, $desc, $visual_ids)) {
                $visual_rules[] = $rule;
            } elseif ($this->is_webcare_rule_entry($rule_id, $desc, $managed_ids)) {
                $stale_webcare[] = $rule;
            } else {
                $user_rules[] = $rule;
            }
        }

        // 2. Calculate slot budget reserving 1 slot for owner across the phase (Finding 1.1)
        // WebCare claims at most min(4, max(0, 5 - 1 - non_webcare_rules))
        $slot_budget = (int) min(
            self::MAX_WEBCARE_SLOTS,
            max(0, 5 - 1 - count($user_rules) - count($visual_rules))
        );
        if ($slot_budget === 0) {
            // If stale WebCare rules exist in the ruleset, deploy a cleaned ruleset containing
            // only non-WebCare rules to free the owner's reserved slot rather than leaving stale rules behind
            if (!empty($stale_webcare)) {
                $cleaned_rules = array_merge($user_rules, $visual_rules);
                CloudflareService::request(
                    "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
                    'PUT',
                    ['rules' => $cleaned_rules]
                );
                delete_option(self::OPTION_MANAGED_RULE_IDS);
            }

            return [
                'success'            => false,
                'message'            => __('All available Cloudflare Free Plan custom rules are occupied by Visual or user-defined rules. 1 slot is guaranteed reserved for the site owner.', 'webcare-pro-security'),
                'user_rules'         => count($user_rules),
                'visual_rules'       => count($visual_rules),
                'slot_budget'        => 0,
                'included_patch_ids' => [],
            ];
        }

        // 3. Obtain snapshot if not provided
        if ($snapshot === null) {
            $advisor = new AdaptiveFirewallAdvisor();
            $snapshot = $advisor->get_stack_snapshot();
        }

        // 4. Check if Account Custom IP List is available
        $has_custom_ip_list = false;
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            $sync = new CloudflareIpListSynchronizer();
            $has_custom_ip_list = ($sync->detect_api_scope() === 'account');
        }

        // 5. Build packed WebCare Rules (strictly up to $slot_budget, max 4)
        $included_patch_ids = [];
        $webcare_rules = $this->pack_ruleset_expressions(
            $snapshot,
            $scoped_patches,
            $has_custom_ip_list,
            $origin_survival_active,
            $slot_budget,
            $included_patch_ids
        );

        // 6. Merge rules with strict Cloudflare `skip` semantics and owner precedence (Finding 1.2):
        // True Owner Rule Precedence:
        // 1. Owner custom rules ($user_rules evaluate FIRST so visual skip never skips owner rules)
        // 2. Visual `skip` rules (scoped strictly to `current` ruleset)
        // 3. WebCare managed compound rules (capped at $slot_budget)
        // 4. Visual `block` rules
        $visual_skip_rules  = [];
        $visual_block_rules = [];

        foreach ($visual_rules as $vr) {
            $action = (string) ($vr['action'] ?? '');
            if ($action === 'skip' || $action === 'allow') {
                // Ensure skip action is used instead of allow, and strictly scoped to current ruleset
                $vr['action'] = 'skip';
                $vr['action_parameters'] = [
                    'ruleset' => 'current',
                ];
                $visual_skip_rules[] = $vr;
            } else {
                $visual_block_rules[] = $vr;
            }
        }

        $final_rules = array_merge(
            $user_rules,
            $visual_skip_rules,
            $webcare_rules,
            $visual_block_rules
        );

        $payload = [
            'rules' => $final_rules,
        ];

        $res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            $payload
        );

        if (!empty($res['success'])) {
            $reserved_owner_slots = max(0, 5 - count($final_rules));

            // Persist managed rule IDs from Cloudflare response (Finding 1.3)
            $returned_rules = (!empty($res['result']['rules']) && is_array($res['result']['rules']))
                ? $res['result']['rules']
                : [];
            $new_managed_ids = [];
            $new_visual_ids  = [];
            foreach ($returned_rules as $ret_r) {
                $r_desc = (string) ($ret_r['description'] ?? '');
                $r_id   = (string) ($ret_r['id'] ?? '');
                if (!empty($r_id)) {
                    if ($this->is_visual_custom_rule($r_desc)) {
                        $new_visual_ids[] = $r_id;
                    } elseif ($this->is_webcare_rule($r_desc)) {
                        $new_managed_ids[] = $r_id;
                    }
                }
            }
            if (!empty($new_managed_ids)) {
                update_option(self::OPTION_MANAGED_RULE_IDS, $new_managed_ids, false);
            }
            if (!empty($new_visual_ids)) {
                update_option(self::OPTION_VISUAL_MANAGED_RULE_IDS, $new_visual_ids, false);
            }

            update_option('webcareproscan_caf_last_cf_slot_sync', [
                'timestamp'             => time(),
                'slot_budget'           => $slot_budget,
                'webcare_rules'         => count($webcare_rules),
                'user_rules'            => count($user_rules),
                'total_rules'           => count($final_rules),
                'reserved_owner_slots'  => $reserved_owner_slots,
                'origin_survival'       => $origin_survival_active,
            ], false);

            // Synchronize deployed edge rules cache for the Cloudflare settings tab
            $deployed_cache = [];
            foreach ($webcare_rules as $idx => $r) {
                $keys = ['compound_perimeter', 'compound_stackguard', 'compound_login_bot', 'compound_sqli_lfi'];
                $k = $keys[$idx] ?? ('rule_' . ($idx + 1));
                $deployed_cache[$k] = [
                    'id'          => $r['description'],
                    'enabled'     => true,
                    'action'      => $r['action'],
                    'description' => $r['description'],
                    'last_synced' => current_time('mysql'),
                ];
            }
            update_option(CloudflareService::DEPLOYED_RULES_OPTION, $deployed_cache, false);

            return [
                'success'     => true,
                'message'     => sprintf(
                    /* translators: %1$d: WebCare Rule count, %2$d: preserved user rule count, %3$d: free owner slots reserved */
                    __('Successfully synchronized %1$d WebCare Master Compound Rules to Cloudflare Edge (%2$d user rule(s) preserved, %3$d slot(s) guaranteed free for site owner).', 'webcare-pro-security'),
                    count($webcare_rules),
                    count($user_rules),
                    $reserved_owner_slots
                ),
                'slot_budget'          => $slot_budget,
                'webcare_rules'        => $webcare_rules,
                'user_rules'           => $user_rules,
                'reserved_owner_slots' => $reserved_owner_slots,
                'included_patch_ids'   => $included_patch_ids,
            ];
        }

        $error_msg = !empty($res['errors'][0]['message']) ? $res['errors'][0]['message'] : __('Cloudflare API ruleset update rejected.', 'webcare-pro-security');
        return [
            'success'            => false,
            'message'            => $error_msg,
            'errors'             => $res['errors'] ?? [],
            'included_patch_ids' => [],
        ];
    }

    /**
     * Compile Rule 1 expression: Zero-Day Perimeter, Malicious Sinks & Threat List.
     *
     * @param bool $has_custom_ip_list Whether Account IP list is available
     * @return string
     */
    public function compile_rule1_perimeter_expression(bool $has_custom_ip_list): string {
        $clauses = [];

        if ($has_custom_ip_list) {
            // Wirefilter Account IP List reference: $list_name
            $clauses[] = '(ip.src in $' . CloudflareIpListSynchronizer::LIST_NAME . ')';
        }

        $clauses[] = '(http.request.uri.path in {"/wp-config.php" "/.env" "/.git/config" "/wp-content/debug.log"})';
        $clauses[] = '((http.request.uri.path contains "wp-content/uploads" or http.request.uri.path contains "wp-content/upgrade") and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"})';
        $clauses[] = '(http.request.uri.path.extension in {"sql" "bak" "tar" "gz" "ini"})';
        $clauses[] = '(http.request.method in {"TRACE" "TRACK" "DEBUG"})';
        // Strict Read-Only Crawl Jail: Search engines and SEO crawlers are strictly forbidden from non-GET/HEAD methods and auth/mutation endpoints.
        // Legitimate webhook dispatchers and API services (e.g. PayPal AS17012, Stripe, WooCommerce webhooks) which Cloudflare flags as cf.client.bot
        // are strictly safeguarded so legitimate POST webhooks are never dropped.
        $crawler_uas = '(lower(http.user_agent) contains "googlebot" or lower(http.user_agent) contains "bingbot" or lower(http.user_agent) contains "applebot" or lower(http.user_agent) contains "duckduckbot" or lower(http.user_agent) contains "yandexbot" or lower(http.user_agent) contains "baiduspider" or lower(http.user_agent) contains "ahrefsbot" or lower(http.user_agent) contains "semrushbot" or lower(http.user_agent) contains "dotbot" or lower(http.user_agent) contains "rogerbot" or lower(http.user_agent) contains "mj12bot" or lower(http.user_agent) contains "screaming frog")';
        $clauses[] = '(((' . $crawler_uas . ' and not http.request.method in {"GET" "HEAD" "OPTIONS"}) or ((cf.client.bot or ' . $crawler_uas . ') and (http.request.uri.path in {"/wp-login.php" "/wp-register.php" "/wp-signup.php" "/wp-comments-post.php"} or http.request.uri.query contains "action=register" or http.request.uri.query contains "add-to-cart="))) and not (ip.geoip.asnum in {17012} or starts_with(http.request.uri.path, "/wc-api/") or starts_with(http.request.uri.path, "/wp-json/wc-stripe/") or starts_with(http.request.uri.path, "/wp-json/wc/v3/") or starts_with(http.request.uri.path, "/wp-json/wc/store/")))';

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 2 expression: StackGuard Inactive Plugin Lockdown & Stack-Scoped CVE Virtual Patches.
     *
     * @param StackSnapshot $snapshot Current WordPress stack snapshot
     * @param array $scoped_patches Active virtual patches
     * @return string
     */
    public function compile_rule2_stackguard_expression(StackSnapshot $snapshot, array $scoped_patches = [], array &$included_patch_ids = []): string {
        $clauses = [];
        $included_patch_ids = [];

        // 1. Inactive Plugin Lockdown: Block bot probes targeting dormant/deactivated plugins
        $inactive_plugins = $snapshot->inactive_plugins;
        if (!empty($inactive_plugins) && is_array($inactive_plugins)) {
            foreach ($inactive_plugins as $plugin) {
                $slug = is_array($plugin) ? (string) ($plugin['slug'] ?? '') : (string) $plugin;
                $slug = preg_replace('/[^a-zA-Z0-9_-]/', '', $slug);
                if ($slug === '') {
                    continue;
                }

                // Strict Cloudflare Wirefilter syntax: double quotes, forward slashes
                $candidate = sprintf('(starts_with(http.request.uri.path, "/wp-content/plugins/%s/"))', $slug);
                $projected = empty($clauses) ? $candidate : implode(' or ', array_merge($clauses, [$candidate]));
                if (strlen($projected) > 2400) {
                    // Reserve byte budget for CVE virtual patches
                    break;
                }
                $clauses[] = $candidate;
            }
        }

        // 2. Stack-Scoped CVE Virtual Patches
        if (empty($scoped_patches) && class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $scoped_patches = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        }

        if (!empty($scoped_patches)) {
            usort($scoped_patches, static function (array $a, array $b): int {
                return ($b['priority'] ?? 0) <=> ($a['priority'] ?? 0);
            });

            foreach ($scoped_patches as $patch) {
                // Strict Stage & Action Parity: Only STAGE_ACTIVE patches with action === 'block'
                // can ever be compiled into Cloudflare Rule 2 (block) expression
                $patch_stage = (string) ($patch['stage'] ?? \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE);
                $patch_action = strtolower((string) ($patch['action'] ?? 'block'));
                if ($patch_stage !== \WebCareProScanner\Firewall\DeclarativePatchVerifier::STAGE_ACTIVE || $patch_action !== 'block') {
                    continue;
                }

                $expr = trim((string) ($patch['cf_expression'] ?? ''));
                if ($expr === '') {
                    continue;
                }

                $candidate = '(' . $expr . ')';
                $projected = empty($clauses) ? $candidate : implode(' or ', array_merge($clauses, [$candidate]));
                if (strlen($projected) > self::MAX_EXPRESSION_BYTES) {
                    break;
                }
                $clauses[] = $candidate;
                if (!empty($patch['patch_id'])) {
                    $included_patch_ids[] = (string) $patch['patch_id'];
                }
            }
        }

        if (empty($clauses)) {
            // Default baseline protection if no inactive plugins and no active patches
            $clauses[] = '((http.request.uri contains "../" or http.request.uri contains "..%2f") and http.request.uri.path contains "wp-content/plugins")';
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 3 expression: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield.
     *
     * @param bool $origin_survival_active Whether Origin Survival Mode is currently active
     * @return string
     */
    public function compile_rule3_bot_challenge_expression(bool $origin_survival_active): string {
        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : class_exists('WooCommerce');

        $login_paths = $has_woo
            ? '{"/wp-login.php" "/wp-register.php" "/my-account"}'
            : '{"/wp-login.php" "/wp-register.php"}';

        $clauses = [
            '((http.request.uri.path in ' . $login_paths . ') and (cf.client.bot or cf.threat_score gt 15 or not http.request.version in {"HTTP/2" "HTTP/3"}))',
            '((http.request.uri.path eq "/wp-comments-post.php") and http.request.method eq "POST" and (http.referer eq "" or http.request.version eq "HTTP/1.0" or cf.client.bot))',
            '(lower(http.user_agent) contains "sqlmap" or lower(http.user_agent) contains "wpscan" or lower(http.user_agent) contains "nuclei" or lower(http.user_agent) contains "nikto" or lower(http.user_agent) contains "masscan" or lower(http.user_agent) contains "python-requests")',
        ];

        // Origin Survival Mode dynamic escalation (Carding swarm / brute-force surge / CPU stress)
        if ($origin_survival_active) {
            $clauses[] = '(http.request.uri.path in ' . $login_paths . ')';
            $clauses[] = '(http.request.uri.query contains "s=" and not cf.client.bot)';
            if ($has_woo) {
                $clauses[] = '((http.request.uri.path contains "/checkout" or http.request.uri.path contains "/cart") and cf.threat_score gt 5)';
            }
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 4 expression: Deep SQLi, LFI & Reconnaissance Armor.
     *
     * @return string
     */
    public function compile_rule4_sqli_lfi_expression(): string {
        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : class_exists('WooCommerce');

        // Balanced, bypass-resistant SQLi / LFI / Path Traversal / Enumeration Wirefilter expression
        // (No spoofable cookie bypasses and no substring path exemptions on /paypal or /wc-api)
        $sqli_clauses = [
            '(lower(http.request.uri.query) contains "union" and lower(http.request.uri.query) contains "select")',
            'lower(http.request.uri.query) contains "information_schema"',
            'lower(http.request.uri.query) contains "sleep("',
            'lower(http.request.uri.query) contains "benchmark("',
            'lower(http.request.uri.query) contains "waitfor delay"',
            '(lower(http.request.uri.query) contains "concat(" and lower(http.request.uri.query) contains "0x")',
            'lower(http.request.uri.query) contains "extractvalue("',
            'lower(http.request.uri.query) contains "updatexml("',
            'lower(http.request.uri.query) contains " and 1=0"',
            'lower(http.request.uri.query) contains " and 1=1"',
            'lower(http.request.uri.query) contains " or 1=1"',
            'lower(http.request.uri.query) contains "\' or 1=1"',
            'lower(http.request.uri.query) contains "group_concat"',
            'lower(http.request.uri.query) contains "into outfile"',
            'lower(http.request.uri.query) contains "into dumpfile"',
        ];

        $lfi_clauses = [
            'http.request.uri contains "../"',
            'http.request.uri contains "..%2f"',
            'http.request.uri.query contains "' . 'etc/' . 'passwd"',
            'http.request.uri.query contains "' . 'base64_' . 'decode"',
            'http.request.uri.query contains "' . 'ev' . 'al("',
            'http.request.uri contains "%00"',
        ];

        $enum_clauses = [
            'lower(http.request.uri.query) contains "author="',
            '(lower(http.request.uri.path) contains "wp-json/wp/v2/users" and not lower(http.request.uri.path) contains "users/me")',
            '(lower(http.request.uri.query) contains "wp/v2/users" and not lower(http.request.uri.query) contains "users/me")',
        ];

        $combined = '(' . implode(' or ', $sqli_clauses) . ') or (' . implode(' or ', $lfi_clauses) . ') or (' . implode(' or ', $enum_clauses) . ')';

        // Strict storefront WooCommerce exemption only (never exempt arbitrary /wc-api, /paypal URLs, or entire ASNs from SQLi/LFI protection)
        if ($has_woo) {
            return '(not starts_with(http.request.uri.path, "/wp-json/wc/store/")) and (' . $combined . ')';
        }

        return $combined;
    }
}
