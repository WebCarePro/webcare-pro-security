<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WafVerdict
 *
 * Immutable value object representing a security evaluation outcome.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final readonly class WafVerdict {

    /**
     * @param WafAction            $action     The evaluated action.
     * @param string               $rule_id    Unique rule identifier (e.g. 'SQLI-CORE', 'XSS-01').
     * @param string               $message    Human-readable explanation of the finding.
     * @param array<string, mixed> $context    Forensic payload details and match data.
     * @param int                  $risk_score Heuristic risk rating (0-100).
     */
    public function __construct(
        public WafAction|string $action,
        public string $rule_id = '',
        public string $message = '',
        public array $context = [],
        public int $risk_score = 0
    ) {}

    public function get_action_value(): string {
        return $this->action instanceof WafAction ? $this->action->value : (string) $this->action;
    }

    public function __get(string $name): mixed {
        return match ($name) {
            'ruleId' => $this->rule_id,
            'reason' => $this->message,
            'category' => (string) ($this->context['category'] ?? 'Next-Gen Threat Defense'),
            'severity' => (string) ($this->context['severity'] ?? 'high'),
            'statusCode' => (int) ($this->context['status_code'] ?? ($this->getActionEnum() === WafAction::RateLimit ? 429 : 403)),
            'banTtl' => (int) ($this->context['ban_ttl'] ?? 86400),
            'syncCloudflare' => !empty($this->context['sync_cloudflare']),
            'exemptRules' => isset($this->context['exempt_rules']) && is_array($this->context['exempt_rules']) ? $this->context['exempt_rules'] : [],
            default => null,
        };
    }

    public function __isset(string $name): bool {
        return in_array($name, ['ruleId', 'reason', 'category', 'severity', 'statusCode', 'banTtl', 'syncCloudflare', 'exemptRules'], true);
    }

    private function getActionEnum(): WafAction {
        if ($this->action instanceof WafAction) {
            return $this->action;
        }
        return WafAction::tryFrom($this->action) ?? WafAction::Block;
    }

    /**
     * Helper to instantiate an Allow verdict.
     */
    public static function allow(): self {
        return new self(action: WafAction::Allow);
    }

    /**
     * Helper to instantiate a Block verdict.
     *
     * @param string               $rule_id Rule identifier.
     * @param string               $message Reason for block.
     * @param array<string, mixed> $context Forensics.
     * @param int                  $risk_score Threat score.
     */
    public static function block(string $rule_id, string $message, array $context = [], int $risk_score = 100): self {
        return new self(
            action: WafAction::Block,
            rule_id: $rule_id,
            message: $message,
            context: $context,
            risk_score: $risk_score
        );
    }

    /**
     * Helper to instantiate a PoW challenge verdict.
     *
     * @param string               $rule_id Rule identifier.
     * @param string               $message Reason for challenge.
     * @param array<string, mixed> $context Forensics.
     */
    public static function challenge(string $rule_id, string $message, array $context = []): self {
        return new self(
            action: WafAction::Challenge,
            rule_id: $rule_id,
            message: $message,
            context: $context,
            risk_score: 50
        );
    }

    /**
     * Helper to instantiate a RateLimit verdict.
     *
     * @param string               $rule_id Rule identifier.
     * @param string               $message Reason.
     * @param array<string, mixed> $context Forensics.
     */
    public static function rate_limit(string $rule_id, string $message, array $context = []): self {
        return new self(
            action: WafAction::RateLimit,
            rule_id: $rule_id,
            message: $message,
            context: $context,
            risk_score: 75
        );
    }

    /**
     * Helper to instantiate a Sanitize verdict.
     *
     * @param string               $rule_id Rule identifier.
     * @param string               $message Reason.
     * @param array<string, mixed> $context Forensics including sanitized values.
     */
    public static function sanitize(string $rule_id, string $message, array $context = []): self {
        return new self(
            action: WafAction::Sanitize,
            rule_id: $rule_id,
            message: $message,
            context: $context,
            risk_score: 30
        );
    }

    /**
     * Helper to instantiate a LogOnly verdict.
     *
     * @param string               $rule_id Rule identifier.
     * @param string               $message Reason.
     * @param array<string, mixed> $context Forensics.
     */
    public static function log_only(string $rule_id, string $message, array $context = []): self {
        return new self(
            action: WafAction::LogOnly,
            rule_id: $rule_id,
            message: $message,
            context: $context,
            risk_score: 20
        );
    }

    /**
     * Whether this verdict is terminal and must halt the pipeline immediately.
     */
    public function is_terminal(): bool {
        return $this->getActionEnum()->is_terminal();
    }
}
