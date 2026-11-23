<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Admin\RouteRegistry;

final class RouteRegistryTest extends TestCase {
    #[\Override]
    protected function setUp(): void {
        parent::setUp();
        RouteRegistry::reset_cache();
    }

    public function test_get_schema_returns_valid_structure(): void {
        $schema = RouteRegistry::get_schema();
        $this->assertIsArray($schema);
        $this->assertNotEmpty($schema['version']);
        $this->assertNotEmpty($schema['pillars']);
        $this->assertCount(8, $schema['pillars']); // 7 pillars + 1 hidden setup
    }

    public function test_pillars_contain_canonical_ids(): void {
        $pillars = RouteRegistry::get_pillars();
        $ids = array_column($pillars, 'id');

        $expected = [
            'webcare-pro-security',
            'webcare-pro-firewall',
            'webcare-pro-logs',
            'webcare-pro-scanner',
            'webcare-pro-login',
            'webcare-pro-backups',
            'webcare-pro-settings',
            'webcare-pro-setup',
        ];

        $this->assertSame($expected, $ids);
    }

    public function test_is_valid_route_validates_correctly(): void {
        $this->assertTrue(RouteRegistry::is_valid_route('webcare-pro-firewall'));
        $this->assertTrue(RouteRegistry::is_valid_route('webcare-pro-firewall', 'cloudflare'));
        $this->assertTrue(RouteRegistry::is_valid_route('webcare-pro-firewall', 'server', 'server-rules'));

        $this->assertFalse(RouteRegistry::is_valid_route('invalid-pillar'));
        $this->assertFalse(RouteRegistry::is_valid_route('webcare-pro-firewall', 'invalid-tab'));
        $this->assertFalse(RouteRegistry::is_valid_route('webcare-pro-firewall', 'server', 'nonexistent-section'));

        // Strict Schema Invariant: Section cannot exist without a valid tab
        $this->assertFalse(RouteRegistry::is_valid_route('webcare-pro-firewall', '', 'server-rules'));
        $this->assertFalse(RouteRegistry::is_valid_route('webcare-pro-firewall', '', 'honeypots'));
    }

    public function test_resolve_bundle_returns_allowed_bundle(): void {
        $this->assertSame('firewall', RouteRegistry::resolve_bundle('webcare-pro-firewall'));
        $this->assertSame('scan', RouteRegistry::resolve_bundle('webcare-pro-scanner'));
        $this->assertSame('waf-logs', RouteRegistry::resolve_bundle('webcare-pro-logs'));
        $this->assertSame('auth', RouteRegistry::resolve_bundle('webcare-pro-login'));
        $this->assertSame('vault', RouteRegistry::resolve_bundle('webcare-pro-backups'));
        $this->assertSame('settings', RouteRegistry::resolve_bundle('webcare-pro-settings'));
        $this->assertSame('wizard', RouteRegistry::resolve_bundle('webcare-pro-setup'));
        $this->assertSame('index', RouteRegistry::resolve_bundle('unknown-page'));
    }

    public function test_url_generation(): void {
        $url1 = RouteRegistry::url('webcare-pro-firewall');
        $this->assertStringContainsString('page=webcare-pro-firewall', $url1);
        $this->assertStringNotContainsString('tab=', $url1); // default tab is omitted

        $url2 = RouteRegistry::url('webcare-pro-firewall', 'cloudflare');
        $this->assertStringContainsString('page=webcare-pro-firewall', $url2);
        $this->assertStringContainsString('tab=cloudflare', $url2);

        $url3 = RouteRegistry::url('webcare-pro-firewall', 'server', 'server-rules');
        $this->assertStringContainsString('tab=server', $url3);
        $this->assertStringContainsString('section=server-rules', $url3);

        $url4 = RouteRegistry::url('webcare-pro-security', '', '', ['rescue' => '1']);
        $this->assertStringContainsString('rescue=1', $url4);

        // Strict Schema Invariant: &section= is never emitted without a valid tab
        $urlNoTab = RouteRegistry::url('webcare-pro-firewall', '', 'honeypots');
        $this->assertStringNotContainsString('section=', $urlNoTab);
        $this->assertSame(admin_url('admin.php?page=webcare-pro-firewall'), $urlNoTab);

        // Discard invalid sections for a tab
        $urlInvalidSec = RouteRegistry::url('webcare-pro-firewall', 'server', 'nonexistent-sec');
        $this->assertStringNotContainsString('section=', $urlInvalidSec);
        $this->assertStringContainsString('tab=server', $urlInvalidSec);

        // Discard invalid tab even when no section is supplied
        $urlInvalidTab = RouteRegistry::url('webcare-pro-firewall', 'completely-bogus-tab');
        $this->assertStringNotContainsString('tab=completely-bogus-tab', $urlInvalidTab);
        $this->assertSame(admin_url('admin.php?page=webcare-pro-firewall'), $urlInvalidTab);

        // Discard section if tab is empty
        $urlDiscardSec = RouteRegistry::url('webcare-pro-firewall', '', 'server-rules');
        $this->assertStringNotContainsString('section=', $urlDiscardSec);

        // Security: Reserved keys in extraArgs cannot overwrite canonical params
        $urlEvilExtra = RouteRegistry::url('webcare-pro-firewall', 'traffic', '', [
            'page'    => 'evil-page',
            'tab'     => 'evil-tab',
            'section' => 'evil-sec',
            'valid'   => 'ok',
        ]);
        $this->assertStringContainsString('page=webcare-pro-firewall', $urlEvilExtra);
        $this->assertStringNotContainsString('page=evil-page', $urlEvilExtra);
        $this->assertStringContainsString('tab=traffic', $urlEvilExtra);
        $this->assertStringNotContainsString('tab=evil-tab', $urlEvilExtra);
        $this->assertStringNotContainsString('section=evil-sec', $urlEvilExtra);
        $this->assertStringContainsString('valid=ok', $urlEvilExtra);
    }

    public function test_all_pillars_have_valid_structure_and_default_tabs(): void {
        $pillars = RouteRegistry::get_pillars();
        $allowedBundles = ['index', 'firewall', 'scan', 'waf-logs', 'auth', 'vault', 'settings', 'wizard'];

        foreach ($pillars as $pillar) {
            $this->assertNotEmpty($pillar['id']);
            $this->assertContains($pillar['bundle'], $allowedBundles, "Pillar {$pillar['id']} bundle is disallowed.");

            if (!empty($pillar['default_tab'])) {
                $tabIds = array_column($pillar['tabs'], 'id');
                $this->assertContains($pillar['default_tab'], $tabIds, "Pillar {$pillar['id']} default_tab not found in tabs.");
            }

            foreach ($pillar['tabs'] as $tab) {
                if (!empty($tab['sections']) && !empty($tab['default_section'])) {
                    $secIds = array_column($tab['sections'], 'id');
                    $this->assertContains($tab['default_section'], $secIds, "Tab {$tab['id']} in pillar {$pillar['id']} default_section not found in sections.");
                }
            }
        }
    }
}
