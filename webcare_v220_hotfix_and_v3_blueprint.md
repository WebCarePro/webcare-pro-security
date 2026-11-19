# WebCare Pro Security — Antigravity Master Plan: `v2.20.0` Security Hotfixes & `v3.0.0` Compiled WP 7.0+ / PHP 8.3+ Kernel

**Target Environment:** WordPress 7.0+ · PHP 8.3+ (Zero legacy backward-compatibility shims)
**Audited Baseline:** `webcare-pro-security` v2.19.0 (`wcp-security-scanner-full01.zip`, 245 PHP files, 141,527 LOC)

> **PRE-RELEASE GREENFIELD / ZERO-MIGRATION DIRECTIVE:**
> This plugin has **zero external or production installs** and is tested strictly on localhost Docker WordPress.
> **DO NOT** write any settings migrations, option/table rename routines, schema upgrade scripts, dual-read fallbacks, or legacy compatibility keys (including old `uploads/` paths, legacy `SetupWizard` response aliases, or `.sig` cleanup shims). Replace schemas, paths, and options cleanly in place as a brand-new fresh install.

---

## Part 1: `v2.20.0` Immediate Security & Bug Hotfixes (F-01 → F-07)

Execute these seven surgical patches first and validate with the PHPUnit regression tests in Section 1.8 before tagging `v2.20.0`.

---

### Fix F-01 (CRITICAL): Runtime SQL RASP Universal Bypass & Customer Blind Spot

**File:** `includes/Firewall/NextGen/RuntimeSqlRaspEngine.php`
**Lines:** `351–358`, `382–435`

#### What to Change
1. **Remove string-based self-exclusion (`line 383`):** Replace `stripos($trimmed, 'webcareproscan_') !== false` with a private static re-entrancy counter (`private static int $internal_query_depth = 0;`) plus `run_internal_query()` wrapped in `try/finally` around WebCare's own `$wpdb` calls.
2. **Normalize SQL comments before AST regexes (`line 388`):** Strip standard block comments (`/* ... */`), line comments (`-- ...`, `# ...`), and *unwrap* MySQL executable conditional comments (`/*!50000 ... */` → inner SQL) so obfuscated keywords cannot evade detection.
3. **Add stacked-query & error-based SQLi detection (`lines 402–432`):** Detect `EXTRACTVALUE(`, `UPDATEXML(`, `GTID_SUBSET(`, and multi-statement `; (INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CALL)\b`.
4. **Close the logged-in Subscriber/Customer blind spot (`line 351`):** Replace `if (function_exists('is_user_logged_in') && is_user_logged_in()) { return false; }` with `current_user_can('manage_options')` so low-privileged shoppers/members on WooCommerce and LMS sites remain protected against zero-day SQLi.

#### Target Patch (`RuntimeSqlRaspEngine.php`)
```php
private static int $internal_query_depth = 0;

public static function run_internal_query(callable $callback): mixed {
    self::$internal_query_depth++;
    try {
        return $callback();
    } finally {
        self::$internal_query_depth = max(0, self::$internal_query_depth - 1);
    }
}

// In is_guest_plugin_surface() (replaces line 351):
if (function_exists('current_user_can') && current_user_can('manage_options')) {
    return false;
}

// In detect_sql_anomaly(string $sql) (replaces lines 382-395):
if (self::$internal_query_depth > 0 || stripos($trimmed, 'SELECT NULL WHERE 1=0') === 0) {
    return null;
}

// 1. Strip balanced string literals first
$skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $trimmed);

// 2. Unwrap MySQL executable conditional comments (/*!50000 UNION */ -> UNION)
$skeleton = (string) preg_replace('/\/\*!\d*\s*([\s\S]*?)\*\//', ' $1 ', $skeleton);

// 3. Strip regular block and line comments so keyword splitting collapses to whitespace
$skeleton = (string) preg_replace('/\/\*[\s\S]*?\*\/|--[^\r\n]*|#[^\r\n]*/', ' ', $skeleton);
$skeleton = (string) preg_replace('/\s+/', ' ', trim($skeleton));

// 4. Add error-based & stacked-query checks alongside existing UNION/SLEEP/LOAD_FILE checks
if (preg_match('/\b(?:EXTRACTVALUE|UPDATEXML|GTID_SUBSET|GTID_SUBTRACT)\s*\(/i', $skeleton)) {
    return 'ERROR_BASED_SQLI_FUNCTION';
}
if (preg_match('/;\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|REPLACE|CALL)\b/i', $skeleton)) {
    return 'STACKED_QUERY_SQLI';
}
```

---

### Fix F-02 (CRITICAL): Preload Micro-WAF Auth Salt Exposure & Chained-File Safety

**File:** `includes/Firewall/MicroWafCompiler.php`
**Lines:** `42–45`, `184–206`, `623–626`, `1110–1116`, `1371–1384`, `1502–1519`

#### What to Change
1. **Switch compiled WAF directory directly to `WP_CONTENT_DIR . '/webcare-waf'` (`lines 42–45`):** Support optional `WEBCARE_WAF_STORAGE_DIR` constant for above-webroot placement, set directory permissions to `0750`, and set compiled PHP files to `0600`. **Do not** add any migration or fallback reader for old `wp-content/uploads/` files, and delete obsolete legacy `.sig` cleanup code (`lines 1515–1519`) and legacy status aliases (`lines 1371–1384`).
2. **Stop embedding raw `wp_salt('auth')` in `webcare-micro-waf.php` (`lines 623, 626`):** Derive a dedicated, rotatable 256-bit `preload_auth` subkey via `hash_hmac('sha256', 'webcare_preload_auth_v2', SecretVault::get_key())`, stored as a separate `0600` key-return PHP file (or `WEBCARE_PRELOAD_SECRET` env/constant) so compromising uploads never leaks WordPress core auth salts.
3. **Harden `$chained_file` emission (`lines 1110–1116`):** Validate `$chained_file` with `realpath()`, enforce `.php` extension and non-null-byte check, and emit with `var_export($real_chained, true)` instead of `addslashes()`.

#### Target Patch (`MicroWafCompiler.php`)
```php
public static function get_compiled_dir(): string {
    if (defined('WEBCARE_WAF_STORAGE_DIR') && is_string(WEBCARE_WAF_STORAGE_DIR) && WEBCARE_WAF_STORAGE_DIR !== '') {
        return untrailingslashit(WEBCARE_WAF_STORAGE_DIR);
    }
    return trailingslashit(WP_CONTENT_DIR) . 'webcare-waf';
}

// Chained file emission (replaces lines 1110-1116):
if (!empty($chained_file) && !str_contains($chained_file, "\0")) {
    $real_chained = realpath($chained_file);
    if (is_string($real_chained) && str_ends_with(strtolower($real_chained), '.php') && is_readable($real_chained)) {
        $exported = var_export($real_chained, true);
        $out .= "if (is_file({$exported})) {\n    require_once {$exported};\n}\n\n";
    }
}
```
> **Permissions:** Replace `@chmod($compiled_file, 0644)` and `@chmod($caf_file, 0644)` with `@chmod($file, 0600)`.

---

### Fix F-03 (HIGH): Prompt Injection Guard Data Corruption & Default-Mode Bypass

**File:** `includes/Security/PromptInjectionGuard.php`
**Lines:** `187–299`, `307–333`

#### What to Change
1. **Fix `inspect_incoming_comment()` data corruption (`lines 307–333`):** Inspect `comment_author`, `comment_author_url`, and `comment_content` **independently** — never concatenate `$author . ' ' . $text` and write the combined string back into `$commentdata['comment_content']`.
2. **Normalize before matching (`lines 197–274`):** Apply Unicode NFKC normalization (`\Normalizer::normalize($text, \Normalizer::FORM_KC)` when `intl` is loaded) and strip invisible Unicode tags / zero-width / bidi characters into `$normalized` *before* evaluating `PROMPT_OVERRIDE_PATTERNS`, `LLM_DELIMITER_PATTERNS`, `MCP_TOOL_CALL_PATTERNS`, and `SECRET_LEAK_PATTERNS`.
3. **Actually neutralize matched directives in `sanitize` mode (`lines 275–284`):** Strip or redact matched override, MCP tool-call, and secret-leak patterns in `$cleaned` (or auto-escalate `risk_score >= 85` to `moderate` on comments/reviews so hostile prompts never land unmodified in the database).
4. **Guard outbound LLM prompts in `includes/System/AIService.php`:** Before sending untrusted file snippets, logs, or comment content to any LLM provider (`call_openai`, `call_gemini`, `call_claude`, `call_deepseek`, `call_openrouter`), wrap untrusted payloads in explicit data-only fences and pass them through `PromptInjectionGuard::inspect_prompt($untrusted, 'ai_forensic_input')['cleaned_text']`.

#### Target Patch (`PromptInjectionGuard.php`)
```php
public static function inspect_incoming_comment(array $commentdata): array {
    $settings  = self::get_settings();
    $fields    = ['comment_author', 'comment_content'];
    $findings  = [];
    $max_score = 0;

    foreach ($fields as $field) {
        $raw = (string) ($commentdata[$field] ?? '');
        if ($raw === '') {
            continue;
        }
        $analysis = self::inspect_prompt($raw, 'wordpress_comment');
        if (!$analysis['is_safe']) {
            $findings  = array_merge($findings, $analysis['findings']);
            $max_score = max($max_score, (int) $analysis['risk_score']);
            if ($settings['action'] === 'sanitize') {
                $commentdata[$field] = $analysis['cleaned_text'];
            }
        }
    }

    if ($max_score > 0) {
        self::record_catch('wordpress_comment', $findings, $max_score, $settings['action']);
        if ($settings['action'] === 'block') {
            wp_die(
                '<h1>' . esc_html__('Submission Rejected', 'webcare-pro-security') . '</h1>' .
                '<p>' . esc_html__('WebCare Prompt Injection Guard: Disallowed adversarial directives detected.', 'webcare-pro-security') . '</p>',
                esc_html__('Prompt Injection Blocked', 'webcare-pro-security'),
                ['response' => 403, 'back_link' => true]
            );
        } elseif ($settings['action'] === 'moderate' || ($settings['action'] === 'sanitize' && $max_score >= 85)) {
            $commentdata['comment_approved'] = 0;
        }
    }

    return $commentdata;
}
```

---

### Fix F-04 (HIGH): Async Non-Blocking Webhooks & SSRF Protection

**File:** `includes/Notifications/WebhookService.php`
**Lines:** `631–650` (and callers in `notify_waf_block`)

#### What to Change
1. **Replace `wp_remote_post()` with `wp_safe_remote_post()`** and validate `wp_parse_url($url, PHP_URL_SCHEME) === 'https'` to block private-IP / metadata SSRF even if `OutboundEgressFirewall` is disabled.
2. **Decouple WAF block notifications from the live HTTP request:** For runtime WAF alerts (`notify_waf_block`), enqueue the event into an async queue (`wp_schedule_single_event(time() + 10, 'webcareproscan_dispatch_webhook_batch')` backed by a bounded ring buffer option/APCu list) instead of calling `post_webhook()` synchronously.
3. **Keep synchronous mode strictly for Admin "Test Webhook" actions** with `'timeout' => 4` (reduced from `8`).

---

### Fix F-05 (HIGH): PoW Blank HTTP 200 Screen & 5-Minute Boundary False Positives

**Files:**
- `includes/Firewall/FirewallEngine.php` (`lines 1817–1823`, `3061–3075`, `6770–6786`)
- `includes/Firewall/BotReconDefense.php` (`lines 798–814`)

#### What to Change
1. **Move `verify_and_clear_pow_header()` & `has_valid_clearance_cookie()` OUT of `render_block_page()`:** Check both inside `handle_rule_violation()` (before calling `render_block_page()`) and inside the `WAF-EMPTY-USER-AGENT` branch (`line 1817`). `render_block_page()` must ALWAYS terminate cleanly (`wp_die()` or `exit;`) — never `return;` into a caller that calls `exit;`.
2. **Add `window - 1` grace period + single-use nonce consumption in `BotReconDefense::verify_pow_solution()`:**
```php
public static function verify_pow_solution(string $challenge, string $nonce, string $ip, string $ua): bool {
    $now_window = (int) floor(time() / 300);
    $valid_challenge = false;
    foreach ([$now_window, $now_window - 1] as $win) {
        $expected = self::generate_challenge_for_window($ip, $ua, (string) $win);
        if (hash_equals($expected, $challenge)) {
            $valid_challenge = true;
            break;
        }
    }
    if (!$valid_challenge) {
        return false;
    }

    $digest = hash('sha256', $challenge . ':' . $nonce);
    if (!str_starts_with($digest, str_repeat('0', self::POW_DIFFICULTY))) {
        return false;
    }

    // Prevent static-window replay of the same solved (challenge, nonce) pair
    $replay_key = 'wcp_pow_used_' . hash('sha256', $challenge . ':' . $nonce);
    if (get_transient($replay_key)) {
        return false;
    }
    set_transient($replay_key, 1, 600);
    return true;
}
```

---

### Fix F-06 (HIGH): WebAuthn Counter Logic & Unauthenticated Account Lockout DoS

**Files:**
- `includes/Auth/WebAuthnManager.php` (`lines 619–647`)
- `includes/Api/ScannerRoutes.php` (`lines 14762–14776`)

#### What to Change
1. **Fix `WebAuthnManager.php:621` & `645` (W3C WebAuthn Level 2/3 compliance):**
   - Check `$incoming_sign_count <= $stored_sign_count` (not `<`) when both `$stored_sign_count > 0 && $incoming_sign_count > 0`.
   - Only update `$user_creds[$matched_cred_idx]['sign_count'] = $incoming_sign_count;` when `$incoming_sign_count > 0`. Never artificially increment `0` counters emitted by synced platform passkeys.
2. **Fix `ScannerRoutes.php:14766` (prevent remote admin lockout):**
   - Key the account rate limit on `md5(strtolower($username) . '|' . $client_ip)` instead of `md5(strtolower($username))` alone so an external attacker cannot lock out an administrator's legitimate IP.

---

### Fix F-07 (MEDIUM): Response DLP Binary Stream & Download Protection

**File:** `includes/Firewall/NextGen/ResponseDlpSentinel.php`
**Lines:** `124–134`, `221–245`

#### What to Change
1. **Skip `ob_start()` on known download/streaming routes (`start_guest_output_buffer()`):** Check for `isset($_GET['download_file'])` (WooCommerce), `isset($_GET['eddfile'])` (EDD), `/feed`, or `headers_list()` containing `Content-Disposition: attachment` or non-text `Content-Type` (`application/zip`, `application/octet-stream`, `video/`, `audio/`, `image/`).
2. **Expand binary magic-byte bypass & cap buffer size (`inspect_and_redact()`):** Skip buffers `> 262144` bytes (256 KB) or starting with ZIP (`PK\x03\x04`), GZIP (`\x1F\x8B`), WebP (`RIFF`), GIF (`GIF8`), or MP4 (`ftyp`).

---

### Section 1.8: Required PHPUnit Regression Tests (`tests/Unit/`)

Add these test cases before releasing `v2.20.0`:
1. `tests/Unit/RuntimeSqlRaspEngineTest.php`:
   - `test_comment_containing_webcareproscan_does_not_bypass_rasp()`
   - `test_mysql_comment_splitting_and_conditional_comments_are_detected()`
   - `test_logged_in_subscriber_remains_protected_while_admin_is_exempt()`
2. `tests/Unit/PromptInjectionGuardTest.php` (extend existing):
   - `test_comment_sanitization_never_prepends_author_into_content()`
   - `test_nfkc_and_zero_width_evasion_is_caught_and_neutralized()`
3. `tests/Unit/BotReconDefenseTest.php`:
   - `test_pow_accepts_previous_window_and_rejects_replayed_solution()`
4. `tests/Unit/WebAuthnManagerTest.php`:
   - `test_synced_zero_counter_passkey_never_increments_or_false_locks()`
   - `test_hardware_key_duplicate_counter_triggers_clone_rejection()`

---

## Part 2: `v3.0.0` Compiled Context-Aware Firewall Kernel Blueprint (WP 7.0+ / PHP 8.3+)

Because this is a **brand-new greenfield plugin with zero legacy installs**, refactor `Plugin::init()`, `SettingsManager.php`, `FirewallEngine.php`, and `ScannerRoutes.php` cleanly in place with **zero migration or backward-compatibility code**.

### 2.1 PHP 8.3+ Core Contracts (`includes/Contracts/`)

```php
<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

enum WafAction: string {
    case Allow      = 'allow';
    case LogOnly    = 'log_only';
    case Sanitize   = 'sanitize';
    case Challenge  = 'challenge_pow';
    case RateLimit  = 'rate_limit';
    case Block      = 'block';
}

enum SiteArchetype: string {
    case Editorial   = 'editorial';
    case Commerce    = 'commerce';
    case Membership  = 'membership';
    case HeadlessApi = 'headless_api';
    case Hybrid      = 'hybrid';
}

enum RouteClass: string {
    case PublicGet   = 'public_get';
    case AuthLogin   = 'auth_login';
    case Commerce    = 'commerce';
    case Membership  = 'membership';
    case RestApi     = 'rest_api';
    case GraphQL     = 'graphql';
    case AdminAjax   = 'admin_ajax';
    case AdminUi     = 'admin_ui';
}
```

### 2.2 Zero-Waste Compiled Stack Manifest (`includes/Core/CompiledStackManifest.php`)

- **When it compiles:** ONLY on `activated_plugin`, `deactivated_plugin`, `switch_theme`, `upgrader_process_complete`, settings save, or `wp webcare waf compile`. **Zero plugin/theme scanning on live visitor traffic.**
- **What it writes:** An OPcache-cached static PHP array at `WP_CONTENT_DIR . '/webcare-waf/site-manifest.php'` (`0600` permissions + HMAC verification) mapping each `RouteClass` to the exact list of evaluator class names needed for the installed stack:

```php
<?php
// Auto-compiled by WebCare Pro v3.0 — OPcache resident (~1.2 KB)
return [
    'archetype' => 'commerce',
    'ecosystems' => ['woocommerce' => true, 'graphql' => false, 'lms' => false],
    'routes' => [
        'public_get' => [
            \WebCareProScanner\Firewall\Evaluators\ExploitSignatureEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\BotReconEvaluator::class,
        ],
        'commerce' => [
            \WebCareProScanner\Firewall\Evaluators\ExploitSignatureEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\CommerceSessionEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\CommerceVelocityEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\CheckoutSkimmerEvaluator::class,
        ],
        'auth_login' => [
            \WebCareProScanner\Firewall\Evaluators\LoginHardeningEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\TwoFactorEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\WebAuthnEvaluator::class,
        ],
        'rest_api' => [
            \WebCareProScanner\Firewall\Evaluators\ExploitSignatureEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\RestAuthEvaluator::class,
            \WebCareProScanner\Firewall\Evaluators\RuntimeSqlRaspEvaluator::class,
        ],
    ],
];
```

### 2.3 Route-Gated `Plugin::init()` Boot Sequence
1. Load `site-manifest.php` (1 `require`, zero DB queries, zero autoloading of unused classes).
2. Run `RouteClassifier::classify($_SERVER)` (~0.02 ms pure string inspection).
3. Instantiate and execute **only** the evaluators listed under `$manifest['routes'][$route_class->value]`.
4. Result: On a public storefront `GET`, `TwoFactorAuth`, `WebAuthnManager`, `ApplicationPasswordSentinel`, `ModernApiShield`, `CheckoutSkimmerSentinel`, and `RestApiInventory` are **never autoloaded or parsed by PHP**.

### 2.4 Dual-Mode Customization Layer (Owners + Developers)
- **Non-Technical Owners (UI):**
  - 48-hour **Smart Learning Mode** on fresh installs (logs anomalies, proposes scoped allowlists, never hard-bans real shoppers).
  - **1-Click Stack Presets** (*Seamless Shop*, *Membership / LMS*, *Editorial*, *Lockdown*).
  - **Progressive Step-Up Policy:** Verified WooCommerce/EDD/Membership sessions receive `WafAction::Challenge` (invisible WebCrypto PoW) for heuristic anomalies instead of IP bans.
- **Developers & Agencies (Code-First):**
  - Optional `WP_CONTENT_DIR . '/webcare-policy.php'` declarative file (Git-trackable) that overrides DB settings, registers custom `WafEvaluatorInterface` classes, and defines route-scoped exemptions.
  - Typed WordPress hooks: `webcare/waf/register_evaluator`, `webcare/waf/verdict`, `webcare/waf/manifest_modules`.
  - Expanded WP-CLI commands: `wp webcare waf compile`, `wp webcare waf simulate --uri=/checkout --method=POST`, `wp webcare waf explain <ref_code>`.

### 2.5 Clean Greenfield Decomposition (Zero Legacy Baggage)
- **`FirewallEngine.php` (9,004 LOC) →** Replace cleanly with `RequestPipeline.php` (~250 LOC) + 8 focused `readonly` evaluator classes under `includes/Firewall/Evaluators/`.
- **`ScannerRoutes.php` (15,522 LOC) →** Split cleanly into 7 lazy-registered REST controllers under `includes/Api/Controllers/` (`ScanController`, `FirewallController`, `AuthController`, `McpController`, `BackupController`, `SupplyChainController`, `ModularWafController`), loaded only when matching `/webcare-pro-security/v1/<prefix>`.
- **Delete all legacy baggage:** Remove `Database/Migration.php` upgrade shims (keep only clean fresh-install table creation), remove all `function_exists('json_validate')`, `function_exists('random_bytes')`, `uniqid()` fallbacks, and PHP `< 8.3` checks; migrate HTML scanning in `HTMLAnalyzer` and `BlockDirectiveSanitizer` to WordPress's native `WP_HTML_Tag_Processor`.