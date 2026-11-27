<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;

final class BoundaryValidationRegressionTest extends TestCase
{
    private array $origServer;
    private array $origOptions;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->origServer = $_SERVER;
        $this->origOptions = $GLOBALS['wp_mock_options'] ?? [];
        ClientIpResolver::reset_client_ip_cache();
        remove_all_filters('webcareproscan_settings');
    }

    #[\Override]
    protected function tearDown(): void
    {
        $_SERVER = $this->origServer;
        $GLOBALS['wp_mock_options'] = $this->origOptions;
        ClientIpResolver::reset_client_ip_cache();
        remove_all_filters('webcareproscan_settings');
        parent::tearDown();
    }

    public function testCloudflareOriginSecretPreservesSpecialCharactersAndPercentSequences(): void
    {
        $rawSecret = 'sec!@#%2F%3Cscript%3E+&=~*';

        add_filter('webcareproscan_settings', static function (array $s) use ($rawSecret): array {
            $s['waf_cloudflare_proxy_trust_mode'] = 'enabled';
            $s['waf_cloudflare_origin_secret'] = $rawSecret;
            return $s;
        });

        $_SERVER['REMOTE_ADDR'] = '103.21.244.5'; // Verified Cloudflare CIDR
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.77';
        $_SERVER['HTTP_X_ORIGIN_SECRET'] = $rawSecret;

        $this->assertSame(
            '198.51.100.77',
            ClientIpResolver::get_client_ip(),
            'Exact Cloudflare origin secret with special chars and percent sequences must verify without lossy sanitization.'
        );

        // Control chars must fail closed even when prefix matches
        ClientIpResolver::reset_client_ip_cache();
        $_SERVER['HTTP_X_ORIGIN_SECRET'] = $rawSecret . "\n";
        $this->assertSame(
            '103.21.244.5',
            ClientIpResolver::get_client_ip(),
            'Origin secret containing control characters must be rejected.'
        );
    }

    public function testBotReconDefensePreservesEncodedRequestUriBeforePathParsing(): void
    {
        $settings = [
            'waf_block_fake_bots'   => true,
            'waf_block_ai_scrapers' => false,
        ];

        // Spoofed Googlebot IP
        $spoofedIp = '198.51.100.222';
        $googleUa = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        // 1. Unknown DNS verdict (pending async verification) must NOT auto-block as BOT-FAKE-CRAWLER-SPOOF
        delete_transient('webcareproscan_bot_dns_v2_' . md5($spoofedIp . '_googlebot'));
        $_SERVER['REQUEST_URI'] = '/robots.txt';
        $this->assertNull(
            BotReconDefense::inspect_bot($spoofedIp, $googleUa, $settings),
            'Pending/unknown DNS state must not falsely block a crawler before background FCrDNS resolves.'
        );

        // 2. Confirmed conflicting PTR/forward-DNS verdict blocks as BOT-FAKE-CRAWLER-SPOOF and preserves raw encoded REQUEST_URI
        set_transient('webcareproscan_bot_dns_v2_' . md5($spoofedIp . '_googlebot'), 'conflicting', 300);
        $_SERVER['REQUEST_URI'] = '/%3Cscript%3E/robots.txt';
        $resEncoded = BotReconDefense::inspect_bot($spoofedIp, $googleUa, $settings);
        $this->assertIsArray(
            $resEncoded,
            'Confirmed conflicting crawler DNS verdict must block even on percent-encoded URI paths.'
        );
        $this->assertSame('/%3Cscript%3E/robots.txt', $_SERVER['REQUEST_URI']);
    }

    public function testExploitSignatureEngineRejectsInvalidHostnamesWithoutCorruptingValidHosts(): void
    {
        $settings = [
            'waf_block_sensitive_file_probes' => true,
        ];

        // 1. Invalid HTTP_HOST containing path/tag characters or whitespace padding must be ignored cleanly
        $_SERVER['HTTP_HOST'] = 'evil.com/<script>alert(1)</script>';
        $this->assertNull(
            ExploitSignatureEngine::check_sensitive_file_probe('/normal-page', $settings),
            'Invalid HTTP_HOST must not break evaluation on benign URI.'
        );
        $this->assertNull(
            ExploitSignatureEngine::check_sensitive_file_probe('/evil.zip', $settings),
            'Invalid HTTP_HOST must not be partially sanitized into matching /evil.zip.'
        );

        foreach ([' myshopsite.example ', 'myshopsite.example ', ' [::1]:8443'] as $paddedHost) {
            $_SERVER['HTTP_HOST'] = $paddedHost;
            $this->assertNull(
                ExploitSignatureEngine::check_sensitive_file_probe('/myshopsite.zip', $settings),
                'Whitespace-padded HTTP_HOST must be rejected without trimming: ' . $paddedHost
            );
        }

        // 2. Valid hostname with port still matches dynamic host-based backup archive probes
        $_SERVER['HTTP_HOST'] = 'MyShopSite.example:8443';
        $hit = ExploitSignatureEngine::check_sensitive_file_probe('/myshopsite.zip', $settings);
        $this->assertIsArray($hit, 'Valid HTTP_HOST with port must match host-derived backup probe /myshopsite.zip.');
        $this->assertSame('WAF-SENSITIVE-FILE-PROBE', $hit['id'] ?? '');
    }
}
