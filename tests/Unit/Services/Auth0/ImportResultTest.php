<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth0;

use App\Services\Auth0\Migration\ImportResult;
use Tests\TestCase;

class ImportResultTest extends TestCase
{
    private ImportResult $result;

    protected function setUp(): void
    {
        parent::setUp();

        $this->result = new ImportResult;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_successful_imports(): void
    {
        $this->result->addSuccess('item1', 1);
        $this->result->addSuccess('item2', 2);

        $this->assertEquals(2, $this->result->getSuccessCount());
        $this->assertCount(2, $this->result->getSuccessful());
        $this->assertEquals([1, 2], $this->result->getSuccessfulIds());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_failed_imports(): void
    {
        $this->result->addFailure('item1', new \Exception('Error 1'));
        $this->result->addFailure('item2', new \Exception('Error 2'));

        $this->assertEquals(2, $this->result->getFailureCount());
        $this->assertCount(2, $this->result->getFailed());
        $this->assertTrue($this->result->hasFailures());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_skipped_imports(): void
    {
        $this->result->addSkipped('Already exists');
        $this->result->addSkipped('Invalid data');

        $this->assertEquals(2, $this->result->getSkippedCount());
        $this->assertCount(2, $this->result->getSkipped());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_success_rate(): void
    {
        $this->result->addSuccess('item1', 1);
        $this->result->addSuccess('item2', 2);
        $this->result->addFailure('item3', new \Exception('Error'));
        $this->result->addSkipped('Skipped');

        $this->assertEquals(50.0, $this->result->getSuccessRate());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_provides_summary(): void
    {
        $this->result->addSuccess('item1', 1);
        $this->result->addFailure('item2', new \Exception('Error'));
        $this->result->addSkipped('Skipped');

        $summary = $this->result->getSummary();

        $this->assertEquals(3, $summary['total']);
        $this->assertEquals(1, $summary['successful']);
        $this->assertEquals(1, $summary['failed']);
        $this->assertEquals(1, $summary['skipped']);
        $this->assertEquals(33.33, round($summary['success_rate'], 2));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_if_all_imports_successful(): void
    {
        $this->result->addSuccess('item1', 1);
        $this->result->addSuccess('item2', 2);

        $this->assertTrue($this->result->isSuccessful());

        $this->result->addFailure('item3', new \Exception('Error'));

        $this->assertFalse($this->result->isSuccessful());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_error_messages(): void
    {
        $this->result->addFailure('item1', new \Exception('Error 1'));
        $this->result->addFailure('item2', new \Exception('Error 2'));

        $messages = $this->result->getErrorMessages();

        $this->assertCount(2, $messages);
        $this->assertEquals('Error 1', $messages[0]);
        $this->assertEquals('Error 2', $messages[1]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_merges_results(): void
    {
        $this->result->addSuccess('item1', 1);
        $this->result->addFailure('item2', new \Exception('Error'));

        $other = new ImportResult;
        $other->addSuccess('item3', 3);
        $other->addSkipped('Skipped');

        $this->result->merge($other);

        $this->assertEquals(2, $this->result->getSuccessCount());
        $this->assertEquals(1, $this->result->getFailureCount());
        $this->assertEquals(1, $this->result->getSkippedCount());
    }
}
