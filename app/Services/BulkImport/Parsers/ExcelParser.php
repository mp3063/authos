<?php

namespace App\Services\BulkImport\Parsers;

use App\Services\BulkImport\Contracts\FileParserInterface;
use Generator;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;

class ExcelParser implements FileParserInterface
{
    /**
     * Parse the Excel file and yield records one by one
     */
    public function parse(UploadedFile|string $file): Generator
    {
        $filePath = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (! file_exists($filePath)) {
            throw new \RuntimeException("File not found: {$filePath}");
        }

        try {
            $spreadsheet = IOFactory::load($filePath);
            $worksheet = $spreadsheet->getActiveSheet();

            // Get header row
            $headers = [];
            $highestColumn = $worksheet->getHighestColumn();
            $headerRow = 1;

            for ($col = 'A'; $col <= $highestColumn; $col++) {
                $value = $worksheet->getCell($col.$headerRow)->getValue();
                if ($value === null) {
                    break;
                }
                $headers[] = trim(strtolower((string) $value));
            }

            if (empty($headers)) {
                throw new \RuntimeException('No headers found in Excel file');
            }

            // Get highest row
            $highestRow = $worksheet->getHighestRow();

            // Iterate through rows
            for ($rowNumber = 2; $rowNumber <= $highestRow; $rowNumber++) {
                $row = [];
                $isEmpty = true;

                foreach ($headers as $colIndex => $header) {
                    $col = chr(65 + $colIndex); // Convert 0,1,2... to A,B,C...
                    $value = $worksheet->getCell($col.$rowNumber)->getValue();

                    if ($value !== null && $value !== '') {
                        $isEmpty = false;
                    }

                    $row[$header] = $value;
                }

                // Skip empty rows
                if ($isEmpty) {
                    continue;
                }

                yield $rowNumber => $row;
            }
        } catch (\PhpOffice\PhpSpreadsheet\Reader\Exception $e) {
            throw new \RuntimeException('Failed to read Excel file: '.$e->getMessage());
        }
    }

    /**
     * Generate an Excel file from records
     */
    public function generate(array $records, string $filename): string
    {
        if (empty($records)) {
            throw new \RuntimeException('No records to export');
        }

        $spreadsheet = new Spreadsheet;
        $worksheet = $spreadsheet->getActiveSheet();

        // Write headers
        $headers = array_keys($records[0]);
        $col = 'A';
        foreach ($headers as $header) {
            $worksheet->setCellValue($col.'1', $header);
            $col++;
        }

        // Style headers
        $worksheet->getStyle('A1:'.chr(64 + count($headers)).'1')
            ->getFont()
            ->setBold(true);

        // Write data
        $rowNumber = 2;
        foreach ($records as $record) {
            $col = 'A';
            foreach ($headers as $header) {
                $value = $record[$header] ?? '';
                $worksheet->setCellValue($col.$rowNumber, $value);
                $col++;
            }
            $rowNumber++;
        }

        // Auto-size columns
        foreach (range('A', chr(64 + count($headers))) as $col) {
            $worksheet->getColumnDimension($col)->setAutoSize(true);
        }

        // Save file
        $path = 'exports/'.$filename;
        $fullPath = Storage::path($path);

        // Ensure directory exists
        $directory = dirname($fullPath);
        if (! is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        $writer = new Xlsx($spreadsheet);
        $writer->save($fullPath);

        return $path;
    }

    /**
     * Get supported file extensions
     */
    public function getSupportedExtensions(): array
    {
        return ['xlsx', 'xls'];
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
