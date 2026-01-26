<?php

namespace App\Filament\Resources\OrganizationBrandingResource\Pages;

use App\Filament\Resources\OrganizationBrandingResource;
use Filament\Resources\Pages\CreateRecord;

class CreateOrganizationBranding extends CreateRecord
{
    protected static string $resource = OrganizationBrandingResource::class;

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
