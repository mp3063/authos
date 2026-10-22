<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class DebugRoutesTest extends TestCase
{
    #[Test]
    #[DataProvider('debugPaths')]
    public function it_does_not_expose_debug_routes(string $path): void
    {
        $this->get($path)->assertNotFound();
    }

    public static function debugPaths(): array
    {
        return [
            'test' => ['/test'],
            'test-db' => ['/test-db'],
        ];
    }
}
