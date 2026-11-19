<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Firewall\FirewallEngine;
use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AuthPolicyEvaluator
 *
 * Enforces login hardening, credential security, password complexity,
 * registration verification, and lost password flood protection.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AuthPolicyEvaluator {

    /**
     * Mask generic login errors.
     */
    public static function mask_login_errors(string $error): string {
        return FirewallEngine::mask_login_errors($error);
    }

    /**
     * Validate registration username against forbidden patterns.
     */
    public static function validate_registration_username(bool $valid, string $username): bool {
        return FirewallEngine::validate_registration_username($valid, $username);
    }

    /**
     * Filter registration errors.
     */
    public static function filter_registration_errors(WP_Error $errors, string $sanitized_user_login, string $user_email): WP_Error {
        return FirewallEngine::filter_registration_errors($errors, $sanitized_user_login, $user_email);
    }

    /**
     * Check if login uses a forbidden administrative username.
     *
     * @param mixed $user
     * @param string $username
     * @param string $password
     * @return mixed
     */
    public static function check_forbidden_username_login(mixed $user, string $username, string $password): mixed {
        return FirewallEngine::check_forbidden_username_login($user, $username, $password);
    }

    /**
     * Validate user password policy on profile update.
     */
    public static function validate_user_password_policy(WP_Error $errors, bool $update, \stdClass $user): void {
        FirewallEngine::validate_user_password_policy($errors, $update, $user);
    }

    /**
     * Validate reset password policy.
     *
     * @param mixed $user
     */
    public static function validate_reset_password_policy(WP_Error $errors, mixed $user): void {
        FirewallEngine::validate_reset_password_policy($errors, $user);
    }

    /**
     * Check password complexity.
     */
    public static function check_password_strength(string $password): bool {
        return FirewallEngine::check_password_strength($password);
    }

    /**
     * Check if password has been compromised in known data breaches (HIBP).
     */
    public static function is_password_pwned(string $password): bool {
        return FirewallEngine::is_password_pwned($password);
    }

    /**
     * Check lostpassword flood before processing.
     */
    public static function check_lostpassword_flood(): void {
        FirewallEngine::check_lostpassword_flood();
    }

    /**
     * Check lostpassword form submission.
     */
    public static function check_lostpassword_submission(): void {
        FirewallEngine::check_lostpassword_submission();
    }
}
