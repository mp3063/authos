<?php

namespace App\Exports;

use App\Models\AuthenticationLog;
use Maatwebsite\Excel\Concerns\FromCollection;

class AuditLogsExport implements FromCollection
{
    /**
     * @return \Illuminate\Support\Collection
     */
    public function collection()
    {
        return AuthenticationLog::all();
    }
}
