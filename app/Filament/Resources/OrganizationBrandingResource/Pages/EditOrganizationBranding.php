<?php

namespace App\Filament\Resources\OrganizationBrandingResource\Pages;

use App\Filament\Resources\OrganizationBrandingResource;
use Filament\Actions;
use Filament\Resources\Pages\EditRecord;

class EditOrganizationBranding extends EditRecord
{
    protected static string $resource = OrganizationBrandingResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\ViewAction::make(),
            Actions\DeleteAction::make(),
        ];
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
