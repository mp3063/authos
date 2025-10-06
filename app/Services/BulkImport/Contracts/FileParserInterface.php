<?php

namespace App\Services\BulkImport\Contracts;

use Generator;
use Illuminate\Http\UploadedFile;

interface FileParserInterface
{
    /**
     * Parse the uploaded file and return records
     *
     * @return Generator<int, array>
     */
    public function parse(UploadedFile|string $file): Generator;

    /**
     * Generate a file from records
     */
    public function generate(array $records, string $filename): string;

    /**
     * Get supported file extensions
     */
    public function getSupportedExtensions(): array;

    /**
     * Validate file format
     */
    public function canParse(UploadedFile $file): bool;
}
