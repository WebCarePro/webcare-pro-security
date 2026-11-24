<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use WebCareProScanner\Auth\StrictCborDecoder;
use WebCareProScanner\Auth\WebAuthnManager;

final class WebAuthnSecurityTest extends TestCase
{
    public function testStrictCborDecoderParsesPrimitives(): void
    {
        // Unsigned int 23
        $this->assertSame(23, StrictCborDecoder::decode("\x17"));
        // Unsigned int 24 (additional info 24)
        $this->assertSame(24, StrictCborDecoder::decode("\x18\x18"));
        // Negative int -1
        $this->assertSame(-1, StrictCborDecoder::decode("\x20"));
        // Byte string 'hello' (major 2, len 5)
        $this->assertSame('hello', StrictCborDecoder::decode("\x45hello"));
        // UTF-8 text string 'world' (major 3, len 5)
        $this->assertSame('world', StrictCborDecoder::decode("\x65world"));
        // Array [1, 2]
        $this->assertSame([1, 2], StrictCborDecoder::decode("\x82\x01\x02"));
        // Map {'a' => 1}
        $this->assertSame(['a' => 1], StrictCborDecoder::decode("\xa1\x61a\x01"));
    }

    public function testStrictCborDecoderRejectsIndefiniteLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Indefinite-length CBOR items are rejected');
        // Indefinite array: 0x9f
        StrictCborDecoder::decode("\x9f\x01\xff");
    }

    public function testStrictCborDecoderRejectsDuplicateKeys(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate key');
        // Map of 2 pairs: {'k' => 1, 'k' => 2}
        StrictCborDecoder::decode("\xa2\x61k\x01\x61k\x02");
    }

    public function testStrictCborDecoderRejectsExcessiveNestingDepth(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('depth exceeded limit');
        // 9 levels of nested arrays: [[[[[[[[[1]]]]]]]]]
        $cbor = str_repeat("\x81", 9) . "\x01";
        StrictCborDecoder::decode($cbor);
    }
}
