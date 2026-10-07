<?php

namespace App\Exports;

use Illuminate\Support\Collection;
use Maatwebsite\Excel\Concerns\FromCollection;

class AuditLogsExport implements FromCollection
{
    public function __construct(private Collection $logs) {}

    public function collection(): Collection
    {
        return $this->logs;
    }
}
