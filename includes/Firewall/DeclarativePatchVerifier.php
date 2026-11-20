<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * DeclarativePatchVerifier
 *
 * Implements PR-K: Ed25519 Asymmetric Signature Verification, Manifest Schema Validation,
 * Key Rotation/Revocation, and Staged Patch Promotion Policy.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
final class DeclarativePatchVerifier {

    public const SUPPORTED_SCHEMA_VERSION = '1.0.0';

    /**
     * Bundled Pinned Ed25519 Public Verification Keys (Key ID => Hex-encoded 32-byte public key).
     * Includes primary signing key and secondary rotation key.
     */
    private const PINNED_PUBLIC_KEYS = [
        'wcp-ed25519-v1' => 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        'wcp-ed25519-v2' => '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29',
    ];

    /**
     * Revoked Key IDs (Compromised or retired keys that must always be rejected).
     */
    private const REVOKED_KEY_IDS = [
        'wcp-ed25519-legacy-revoked',
    ];

    /**
     * Staged Promotion States:
     * - shadow: rule runs in observe-only telemetry mode without blocking
     * - staged: canary deployment evaluated on representative non-critical routes
     * - active: fully enforced blocking mode
     * - revoked: disabled due to regression or upstream retraction
     */
    public const STAGE_SHADOW  = 'shadow';
    public const STAGE_STAGED  = 'staged';
    public const STAGE_ACTIVE  = 'active';
    public const STAGE_REVOKED = 'revoked';

    /**
     * Verify and validate an Ed25519-signed declarative virtual patch manifest.
     *
     * @param array<string, mixed> $patch Declarative patch manifest
     * @param int $min_allowed_sequence Minimum monotonic feed sequence (anti-rollback)
     * @return array{valid: bool, error: string|null, patch: array<string, mixed>|null}
     */
    public static function verify_patch_manifest(array $patch, int $min_allowed_sequence = 0): array {
        // 1. Validate required fields presence
        $required_fields = [
            'schema_version', 'patch_id', 'feed_sequence', 'component',
            'match', 'action', 'published_at', 'expires_at', 'key_id', 'signature'
        ];
        foreach ($required_fields as $field) {
            if (!isset($patch[$field])) {
                return ['valid' => false, 'error' => "Missing required patch manifest field: {$field}", 'patch' => null];
            }
        }

        // 2. Schema version check
        if ((string) $patch['schema_version'] !== self::SUPPORTED_SCHEMA_VERSION) {
            return ['valid' => false, 'error' => "Unsupported schema version: {$patch['schema_version']}", 'patch' => null];
        }

        // 3. Key ID validation (reject revoked and unknown keys)
        $key_id = (string) $patch['key_id'];
        if (in_array($key_id, self::REVOKED_KEY_IDS, true)) {
            return ['valid' => false, 'error' => "Signing key {$key_id} has been revoked.", 'patch' => null];
        }

        $public_key_hex = self::PINNED_PUBLIC_KEYS[$key_id] ?? null;
        if ($public_key_hex === null) {
            return ['valid' => false, 'error' => "Unknown or untrusted signing key ID: {$key_id}", 'patch' => null];
        }

        // 4. Anti-rollback monotonic sequence validation
        $sequence = (int) $patch['feed_sequence'];
        if ($sequence < $min_allowed_sequence) {
            return ['valid' => false, 'error' => "Feed sequence {$sequence} is rolled back or replayed (min allowed: {$min_allowed_sequence}).", 'patch' => null];
        }

        // 5. Expiration validation
        $expires_at = is_numeric($patch['expires_at']) ? (int) $patch['expires_at'] : strtotime((string) $patch['expires_at']);
        if ($expires_at <= 0 || time() > $expires_at) {
            return ['valid' => false, 'error' => "Virtual patch {$patch['patch_id']} has expired.", 'patch' => null];
        }

        // 6. Component specification validation
        $component = $patch['component'];
        if (!is_array($component) || empty($component['slug']) || empty($component['type'])) {
            return ['valid' => false, 'error' => 'Ambiguous or invalid component specification in patch manifest.', 'patch' => null];
        }

        // 7. Match structure validation
        $match = $patch['match'];
        if (!is_array($match) || empty($match['route']) || empty($match['predicate'])) {
            return ['valid' => false, 'error' => 'Invalid declarative match criteria.', 'patch' => null];
        }

        // 8. Bounded action validation
        $action = (string) $patch['action'];
        $allowed_actions = ['block', 'challenge', 'rate_limit', 'log'];
        if (!in_array($action, $allowed_actions, true)) {
            return ['valid' => false, 'error' => "Invalid action '{$action}'. Allowed: " . implode(', ', $allowed_actions), 'patch' => null];
        }

        // 9. Ed25519 Cryptographic Signature Verification
        $signature_hex = (string) $patch['signature'];
        if (!self::verify_ed25519_signature($patch, $signature_hex, $public_key_hex)) {
            AuditLogger::log_event(
                'VPATCH_INVALID_SIGNATURE',
                sprintf('Ed25519 signature verification failed for virtual patch %s.', $patch['patch_id'])
            );
            return ['valid' => false, 'error' => "Invalid Ed25519 signature for patch {$patch['patch_id']}.", 'patch' => null];
        }

        return ['valid' => true, 'error' => null, 'patch' => $patch];
    }

    /**
     * Compute deterministic canonical payload representation and verify Ed25519 signature.
     *
     * @param array<string, mixed> $patch
     * @param string $signature_hex Hex-encoded 64-byte Ed25519 signature
     * @param string $public_key_hex Hex-encoded 32-byte Ed25519 public key
     * @return bool
     */
    public static function verify_ed25519_signature(array $patch, string $signature_hex, string $public_key_hex): bool {
        // Strip signature before building canonical representation
        $data_to_sign = $patch;
        unset($data_to_sign['signature']);

        // Canonical deterministic JSON
        ksort($data_to_sign);
        $canonical_message = (string) json_encode($data_to_sign, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $signature_bytes = @hex2bin($signature_hex);
        $public_key_bytes = @hex2bin($public_key_hex);

        if ($signature_bytes === false || strlen($signature_bytes) !== 64 || $public_key_bytes === false || strlen($public_key_bytes) !== 32) {
            return false;
        }

        // Prefer native sodium crypto if available (PHP 8.3/8.4 standard)
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            try {
                return sodium_crypto_sign_verify_detached($signature_bytes, $canonical_message, $public_key_bytes);
            } catch (\Throwable $e) {
                return false;
            }
        }

        return false;
    }

    /**
     * Helper to sign a declarative patch manifest for testing or authoring.
     *
     * @param array<string, mixed> $patch
     * @param string $secret_key_hex 64-byte Ed25519 secret key
     * @return string Hex-encoded 64-byte signature
     */
    public static function sign_patch_manifest(array $patch, string $secret_key_hex): string {
        $data_to_sign = $patch;
        unset($data_to_sign['signature']);
        ksort($data_to_sign);
        $canonical_message = (string) json_encode($data_to_sign, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $secret_key_bytes = (string) hex2bin($secret_key_hex);
        if (function_exists('sodium_crypto_sign_detached')) {
            $sig = sodium_crypto_sign_detached($canonical_message, $secret_key_bytes);
            return bin2hex($sig);
        }

        return '';
    }

    /**
     * Staged Promotion Evaluation:
     * High-confidence vendor patches with exact affected ranges promote automatically to active.
     * Lower-confidence or broad heuristic rules start in shadow mode and require explicit owner promotion.
     *
     * @param array<string, mixed> $patch
     * @param bool $owner_opt_in_auto Whether site owner permits auto-enforcement of verified patches
     * @return string Staged promotion stage (shadow, staged, active)
     */
    public static function determine_initial_stage(array $patch, bool $owner_opt_in_auto = true): string {
        $confidence = (string) ($patch['confidence'] ?? 'medium');
        $is_exact_vendor = !empty($patch['vendor_verified']);

        if ($confidence === 'high' && $is_exact_vendor && $owner_opt_in_auto) {
            return self::STAGE_ACTIVE;
        }

        return self::STAGE_SHADOW;
    }
}
