<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\BotReconDefense;

class BotReconDefenseTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $_COOKIE = [];
    }

    public function testPowValidationAcceptsCurrentWindow(): void {
        $ip = '203.0.113.195';
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
        $challenge = BotReconDefense::generate_challenge($ip, $ua);

        // Find a valid nonce satisfying difficulty (BotReconDefense::POW_DIFFICULTY leading zeros)
        $zeros = str_repeat('0', BotReconDefense::POW_DIFFICULTY);
        $nonce = 0;
        while (true) {
            $digest = hash('sha256', $challenge . ':' . (string) $nonce);
            if (strpos($digest, $zeros) === 0) {
                break;
            }
            $nonce++;
        }

        $isValid = BotReconDefense::verify_pow_solution($challenge, (string) $nonce, $ip, $ua);
        $this->assertTrue($isValid, 'Valid PoW solution in current window must be verified.');

        // Verify anti-replay: immediate subsequent verification with the same nonce must fail
        $isReplay = BotReconDefense::verify_pow_solution($challenge, (string) $nonce, $ip, $ua);
        $this->assertFalse($isReplay, 'Replaying consumed PoW nonce must fail.');
    }

    public function testPowValidationAcceptsPreviousWindowGrace(): void {
        $ip = '203.0.113.195';
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
        $curWindow = (int) floor(time() / 300);
        $prevChallenge = BotReconDefense::generate_challenge($ip, $ua, $curWindow - 1);

        $zeros = str_repeat('0', BotReconDefense::POW_DIFFICULTY);
        $nonce = 0;
        while (true) {
            $digest = hash('sha256', $prevChallenge . ':' . (string) $nonce);
            if (strpos($digest, $zeros) === 0) {
                break;
            }
            $nonce++;
        }

        $isValid = BotReconDefense::verify_pow_solution($prevChallenge, (string) $nonce, $ip, $ua);
        $this->assertTrue($isValid, 'Valid PoW solution from previous window (window - 1) must be accepted during rollover.');
    }
}
