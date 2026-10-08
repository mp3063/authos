<?php

namespace App\Filament\Resources\OrganizationBrandingResource\Pages;

use App\Filament\Concerns\ForcesCallerOrganization;
use App\Filament\Resources\OrganizationBrandingResource;
use Filament\Resources\Pages\CreateRecord;

class CreateOrganizationBranding extends CreateRecord
{
    use ForcesCallerOrganization;

    protected static string $resource = OrganizationBrandingResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        return $this->forceCallerOrganization($data);
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
