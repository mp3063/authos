<?php

namespace Tests\Unit\Services;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class NoFirstUserFallbackTest extends TestCase
{
    #[Test]
    public function it_has_no_first_user_fallback_in_app_code(): void
    {
        $matches = [];

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__, 3).'/app', \FilesystemIterator::SKIP_DOTS)) as $file) {
            $path = $file->getPathname();

            if ($file->getExtension() !== 'php' || str_contains($path, '/app/Console/')) {
                continue;
            }

            if (str_contains((string) file_get_contents($path), 'User::first()')) {
                $matches[] = $path;
            }
        }

        $this->assertSame([], $matches);
    }
}
