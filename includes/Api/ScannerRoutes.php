<?php
namespace WebCareProScanner\Api;

if (!defined('ABSPATH')) {
    exit;
}

use WebCareProScanner\Scanner\Engine;
use WebCareProScanner\Filesystem\FileScanner;
use WebCareProScanner\Integrity\CoreIntegrity;
use WebCareProScanner\Integrity\ImportantFileFIM;
use WebCareProScanner\Integrity\PluginIntegrity;
use WebCareProScanner\Integrity\ThemeIntegrity;
use WebCareProScanner\Database\DatabaseScanner;
use WebCareProScanner\Content\ContentScanner;
use WebCareProScanner\WordPress\WordPressSecurityScanner;
use WebCareProScanner\WordPress\UserScanner;
use WebCareProScanner\WordPress\UpdateScanner;
use WebCareProScanner\System\ServerInfo;
use WebCareProScanner\Backup\DatabaseBackup;
use WebCareProScanner\Findings\CorrelationEngine;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Quarantine\CoreRepairManager;
use WebCareProScanner\Scan\ScanLock;
use WebCareProScanner\Filesystem\UploadsScanner;
use WebCareProScanner\WordPress\CronScanner;
use WebCareProScanner\WordPress\PersistenceScanner;
use WebCareProScanner\Forensics\AttackChainEngine;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Firewall\VirtualPatchSynthesizer;
use WebCareProScanner\Firewall\HtaccessVaultManager;
use WebCareProScanner\Firewall\HtaccessShield;
use WebCareProScanner\Firewall\RedirectCanaryEngine;
use WebCareProScanner\Filesystem\PathValidator;
use WebCareProScanner\Reports\IncidentReportEngine;

if (!defined('ABSPATH')) {
    exit;
}

class ScannerRoutes {
    const NAMESPACE = 'webcare-pro-security/v1';

    public static function register() {
        if (class_exists(RestRouter::class)) {
            RestRouter::register();
        }
    }

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    


    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    /**
     * Build a method-specific Rule #37 allowlist update, removing equivalent legacy route-only entries.
     *
     * @param array<int,string> $lines
     * @param string            $route
     * @param string            $method
     * @return array{lines:array<int,string>,changed:bool,added:bool,legacy_route_replaced:bool}
     */
    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    


    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 13. Whitelist & False-Positive Endpoints
    // ==========================================

    

    

    

    // ==========================================
    // 14. Behavioral Baseline Engine Endpoints
    // ==========================================

    

    

    

    // ==========================================
    // 15. Transactional Remediation & Rollback
    // ==========================================

    

    

    // ==========================================
    // 16. Model Context Protocol (MCP) Agent Service
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17. Supply-Chain Defense & SBOM Sentinel Handlers
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17.5. Behavioral WAF, Bot Traps & Rate Limiting (Pillar 3)
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17.6. Zero-Trust Identity & Session Forensics (Pillar 4)
    // ==========================================

    

    

    

    

    

    

    

    // ==========================================
    // 18. Unified WebCare Vault Status & Rotator
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 16. Plugin Self-Defense & Anti-Tamper Endpoints
    // ==========================================

    

    

    

    

    // =========================================================================
    // Pillar 5: Continuous Threat Intel Network & Automated Virtual Patching Ecosystem
    // =========================================================================

    

    

    

    

    

    

    

    

    

    

    

    // =========================================================================
    // 20. 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes Handlers
    // =========================================================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // Phase 5: 72-Hour Reinfection Watchdog Handlers
    // ==========================================

    

    

    

    

    // ==========================================
    // Phase 5: "Time-Machine" Local Snapshots Handlers
    // ==========================================

    

    

    

    

    

    

    // ==========================================
    // Phase 5: Domain Reputation & SSL Sentinel Handlers
    // ==========================================

    

    

    // ==========================================
    // Phase 6: Threat Correlation Hierarchy Handlers
    // ==========================================

    

    // ==========================================
    // Phase 6: WebAuthn Passkeys (Biometric FIDO2) Handlers
    // ==========================================

    

    

    

    

    

    

    

    // ==========================================
    // Phase 6: Server Security Verification & Caddy
    // ==========================================

    

    

    // ==========================================
    // 21. Activity & Forensic Audit Log Handlers
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

}
