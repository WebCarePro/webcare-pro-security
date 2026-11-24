<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\OutboundEgressFirewall;

final class OutboundWebhookApprovalTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Reset settings option
        update_option('webcareproscan_egress_settings', [
            'mode'                          => 'enforce',
            'block_ssrf_metadata'           => true,
            'block_exfil_webhooks'          => true,
            'block_suspicious_tld'          => true,
            'allowed_hosts'                 => [],
            'approved_third_party_webhooks' => [
                [
                    'url_prefix'  => 'https://hooks.external.example.com/api/v1/notify',
                    'plugin_slug' => 'trusted-addon',
                ],
            ],
        ]);
    }

    public function testApprovedWebhookRequiresHttpsAndExactOriginAndPathBoundary(): void
    {
        $settings = OutboundEgressFirewall::get_settings();

        $approvedCaller = [
            'type' => 'plugin',
            'name' => 'Trusted Addon',
            'slug' => 'trusted-addon',
        ];

        $unapprovedCaller = [
            'type' => 'plugin',
            'name' => 'Rogue Addon',
            'slug' => 'rogue-addon',
        ];

        // Caller matching approved slug and exact path prefix
        $this->assertTrue(OutboundEgressFirewall::is_authorized_notification_webhook('https://hooks.external.example.com/api/v1/notify', $settings, $approvedCaller));
        $this->assertTrue(OutboundEgressFirewall::is_authorized_notification_webhook('https://hooks.external.example.com/api/v1/notify/extra', $settings, $approvedCaller));

        // Substring / path boundary traversal attack should fail (e.g. notify-bypass)
        $this->assertFalse(OutboundEgressFirewall::is_authorized_notification_webhook('https://hooks.external.example.com/api/v1/notify-bypass', $settings, $approvedCaller));

        // Unapproved caller slug with matching URL should fail
        $this->assertFalse(OutboundEgressFirewall::is_authorized_notification_webhook('https://hooks.external.example.com/api/v1/notify', $settings, $unapprovedCaller));

        // HTTP (non-HTTPS) should fail
        $this->assertFalse(OutboundEgressFirewall::is_authorized_notification_webhook('http://hooks.external.example.com/api/v1/notify', $settings, $approvedCaller));

        // Different host should fail
        $this->assertFalse(OutboundEgressFirewall::is_authorized_notification_webhook('https://other.external.example.com/api/v1/notify', $settings, $approvedCaller));
    }

    public function testUpdateSettingsRejectsEmptySlugOrNonHttps(): void
    {
        $input = [
            'mode' => 'enforce',
            'approved_third_party_webhooks' => [
                [
                    'url_prefix'  => 'http://insecure.example.com/webhook',
                    'plugin_slug' => 'valid-slug',
                ],
                [
                    'url_prefix'  => 'https://secure.example.com/webhook',
                    'plugin_slug' => '',
                ],
                [
                    'url_prefix'  => 'https://secure.example.com/webhook',
                    'plugin_slug' => 'legit-plugin',
                ],
            ],
        ];

        OutboundEgressFirewall::update_settings($input);
        $saved = OutboundEgressFirewall::get_settings();

        $this->assertCount(1, $saved['approved_third_party_webhooks']);
        $this->assertSame('https://secure.example.com/webhook', $saved['approved_third_party_webhooks'][0]['url_prefix']);
        $this->assertSame('legit-plugin', $saved['approved_third_party_webhooks'][0]['plugin_slug']);
    }
}
