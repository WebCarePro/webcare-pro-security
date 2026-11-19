<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

enum WafAction: string {
    case Allow      = 'allow';
    case LogOnly    = 'log_only';
    case Sanitize   = 'sanitize';
    case Challenge  = 'challenge_pow';
    case RateLimit  = 'rate_limit';
    case Block      = 'block';

    /**
     * Check if this action terminates request processing immediately.
     */
    public function is_terminal(): bool {
        return match ($this) {
            self::Challenge, self::RateLimit, self::Block => true,
            self::Allow, self::LogOnly, self::Sanitize    => false,
        };
    }
}
