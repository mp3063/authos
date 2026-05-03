<?php

namespace App\Filament\Resources\ScheduledComplianceReportResource\Pages;

use App\Filament\Resources\ScheduledComplianceReportResource;
use App\Models\User;
use Filament\Facades\Filament;
use Filament\Resources\Pages\CreateRecord;

class CreateScheduledComplianceReport extends CreateRecord
{
    protected static string $resource = ScheduledComplianceReportResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        /** @var User|null $currentUser */
        $currentUser = Filament::auth()->user();

        $data['created_by_user_id'] = $currentUser?->id;

        // Org-scoped users always schedule for their own org regardless of any tampering.
        if ($currentUser && ! $currentUser->isSuperAdmin() && $currentUser->organization_id) {
            $data['organization_id'] = $currentUser->organization_id;
        }

        return $data;
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('index');
    }
}
