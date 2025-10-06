<?php

namespace App\Services\BulkImport\Parsers;

use App\Services\BulkImport\Contracts\FileParserInterface;
use Generator;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

class JsonParser implements FileParserInterface
{
    /**
     * Parse the JSON file and yield records one by one
     */
    public function parse(UploadedFile|string $file): Generator
    {
        $filePath = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (! file_exists($filePath)) {
            throw new \RuntimeException("File not found: {$filePath}");
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new \RuntimeException("Unable to read file: {$filePath}");
        }

        $data = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Invalid JSON: '.json_last_error_msg());
        }

        if (! is_array($data)) {
            throw new \RuntimeException('JSON root must be an array');
        }

        // Support both array of objects and {"users": [...]} format
        $records = isset($data['users']) ? $data['users'] : $data;

        if (! is_array($records)) {
            throw new \RuntimeException('JSON must contain an array of records');
        }

        $rowNumber = 0;
        foreach ($records as $record) {
            $rowNumber++;

            if (! is_array($record)) {
                throw new \RuntimeException("Record at index {$rowNumber} is not an object");
            }

            // Normalize keys (lowercase)
            $record = array_change_key_case($record, CASE_LOWER);

            yield $rowNumber => $record;
        }
    }

    /**
     * Generate a JSON file from records
     */
    public function generate(array $records, string $filename): string
    {
        if (empty($records)) {
            throw new \RuntimeException('No records to export');
        }

        $path = 'exports/'.$filename;
        $fullPath = Storage::path($path);

        // Ensure directory exists
        $directory = dirname($fullPath);
        if (! is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        $json = json_encode(['users' => $records], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        if ($json === false) {
            throw new \RuntimeException('Failed to encode JSON: '.json_last_error_msg());
        }

        if (file_put_contents($fullPath, $json) === false) {
            throw new \RuntimeException("Unable to write file: {$fullPath}");
        }

        return $path;
    }

    /**
     * Get supported file extensions
     */
    public function getSupportedExtensions(): array
    {
        return ['json'];
    }

    /**
     * Validate if file can be parsed
     */
    public function canParse(UploadedFile $file): bool
    {
        return in_array(
            strtolower($file->getClientOriginalExtension()),
            $this->getSupportedExtensions()
        );
    }
}
