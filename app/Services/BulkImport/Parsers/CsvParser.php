<?php

namespace App\Services\BulkImport\Parsers;

use App\Services\BulkImport\Contracts\FileParserInterface;
use Generator;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

class CsvParser implements FileParserInterface
{
    /**
     * Parse the CSV file and yield records one by one
     */
    public function parse(UploadedFile|string $file): Generator
    {
        $filePath = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (! file_exists($filePath)) {
            throw new \RuntimeException("File not found: {$filePath}");
        }

        $handle = fopen($filePath, 'r');
        if ($handle === false) {
            throw new \RuntimeException("Unable to open file: {$filePath}");
        }

        try {
            // Read header row
            $headers = fgetcsv($handle);
            if ($headers === false) {
                throw new \RuntimeException('Unable to read CSV headers');
            }

            // Normalize headers (trim whitespace, lowercase)
            $headers = array_map(fn ($h) => trim(strtolower($h)), $headers);

            $rowNumber = 1; // Start at 1 for data rows (header is row 0)

            // Read and yield each data row
            while (($row = fgetcsv($handle)) !== false) {
                $rowNumber++;

                // Skip empty rows
                if (empty(array_filter($row))) {
                    continue;
                }

                // Combine headers with values
                $record = array_combine($headers, $row);

                if ($record === false) {
                    throw new \RuntimeException("Failed to parse row {$rowNumber}");
                }

                yield $rowNumber => $record;
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Generate a CSV file from records
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

        $handle = fopen($fullPath, 'w');
        if ($handle === false) {
            throw new \RuntimeException("Unable to create file: {$fullPath}");
        }

        try {
            // Write header row
            $headers = array_keys($records[0]);
            fputcsv($handle, $headers);

            // Write data rows
            foreach ($records as $record) {
                fputcsv($handle, $record);
            }
        } finally {
            fclose($handle);
        }

        return $path;
    }

    /**
     * Get supported file extensions
     */
    public function getSupportedExtensions(): array
    {
        return ['csv'];
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
