<?php

namespace Tests\Unit\Services\BulkImport;

use App\Services\BulkImport\Parsers\ExcelParser;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ExcelParserTest extends TestCase
{
    private ExcelParser $parser;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->parser = new ExcelParser;
    }

    #[Test]
    public function generated_file_parses_back_to_the_same_records(): void
    {
        $records = [
            ['email' => 'ana@example.com', 'name' => 'Ana', 'role' => 'user'],
            ['email' => 'bob@example.com', 'name' => 'Bob', 'role' => 'admin'],
        ];

        $path = $this->parser->generate($records, 'users.xlsx');
        $parsed = iterator_to_array($this->parser->parse(Storage::path($path)));

        $this->assertSame([2 => $records[0], 3 => $records[1]], $parsed);
    }

    #[Test]
    public function headers_are_lowercased_and_trimmed(): void
    {
        $path = $this->parser->generate([[' Email ' => 'ana@example.com', 'NAME' => 'Ana']], 'headers.xlsx');

        $parsed = iterator_to_array($this->parser->parse(Storage::path($path)));

        $this->assertSame([2 => ['email' => 'ana@example.com', 'name' => 'Ana']], $parsed);
    }

    #[Test]
    public function empty_rows_are_skipped(): void
    {
        $path = $this->parser->generate([
            ['email' => 'ana@example.com', 'name' => 'Ana'],
            ['email' => '', 'name' => ''],
            ['email' => 'bob@example.com', 'name' => 'Bob'],
        ], 'gaps.xlsx');

        $parsed = iterator_to_array($this->parser->parse(Storage::path($path)));

        $this->assertSame([2, 4], array_keys($parsed));
    }

    #[Test]
    public function missing_file_throws(): void
    {
        $this->expectException(\RuntimeException::class);

        iterator_to_array($this->parser->parse('/nonexistent/file.xlsx'));
    }

    #[Test]
    public function generating_without_records_throws(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->parser->generate([], 'empty.xlsx');
    }
}
