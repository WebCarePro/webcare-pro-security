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
}
