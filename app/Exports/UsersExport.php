<?php

namespace App\Exports;

use App\Models\User;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Collection;
use Maatwebsite\Excel\Concerns\FromView;
use Maatwebsite\Excel\Concerns\WithHeadings;
use Maatwebsite\Excel\Concerns\FromCollection;
use Maatwebsite\Excel\Concerns\WithMapping;
use Maatwebsite\Excel\Concerns\WithStyles;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;

class UsersExport implements FromCollection, WithHeadings, WithMapping, WithStyles
{
    protected Collection $users;
    protected bool $includeRoles;
    protected bool $includeApplications;
    protected bool $includeActivity;

    public function __construct(Collection $users, bool $includeRoles = true, bool $includeApplications = true, bool $includeActivity = false)
    {
        $this->users = $users;
        $this->includeRoles = $includeRoles;
        $this->includeApplications = $includeApplications;
        $this->includeActivity = $includeActivity;
    }

    public function collection()
    {
        return $this->users;
    }

    public function headings(): array
    {
        $headings = [
            'ID',
            'Name',
            'Email',
            'Created At',
            'Last Login',
            'MFA Enabled',
            'Status',
        ];

        if ($this->includeRoles) {
            $headings[] = 'Roles';
            $headings[] = 'Custom Roles';
        }

        if ($this->includeApplications) {
            $headings[] = 'Applications';
            $headings[] = 'Application Login Counts';
        }

        if ($this->includeActivity) {
            $headings[] = 'Total Logins';
            $headings[] = 'Failed Logins (30d)';
            $headings[] = 'Password Changed At';
        }

        return $headings;
    }

    public function map($user): array
    {
        $row = [
            $user->id,
            $user->name,
            $user->email,
            $user->created_at->format('Y-m-d H:i:s'),
            $user->last_login_at ? $user->last_login_at->format('Y-m-d H:i:s') : 'Never',
            $user->hasMfaEnabled() ? 'Yes' : 'No',
            $user->is_active ? 'Active' : 'Inactive',
        ];

        if ($this->includeRoles) {
            $row[] = $user->roles->pluck('name')->join(', ');
            $row[] = $user->customRoles->pluck('name')->join(', ');
        }

        if ($this->includeApplications) {
            $row[] = $user->applications->pluck('name')->join(', ');
            $loginCounts = $user->applications->map(function ($app) {
                return $app->name . ': ' . ($app->pivot->login_count ?? 0);
            })->join(', ');
            $row[] = $loginCounts;
        }

        if ($this->includeActivity) {
            $totalLogins = $user->applications->sum('pivot.login_count');
            $row[] = $totalLogins;
            $row[] = 'N/A'; // Would need to calculate failed logins
            $row[] = $user->password_changed_at ? $user->password_changed_at->format('Y-m-d H:i:s') : 'Never';
        }

        return $row;
    }

    public function styles(Worksheet $sheet)
    {
        return [
            // Style the first row as bold text
            1 => ['font' => ['bold' => true]],
        ];
    }
}