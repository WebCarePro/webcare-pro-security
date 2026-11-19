<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

enum SiteArchetype: string {
    case Editorial   = 'editorial';
    case Commerce    = 'commerce';
    case Membership  = 'membership';
    case HeadlessApi = 'headless_api';
    case Hybrid      = 'hybrid';
}
