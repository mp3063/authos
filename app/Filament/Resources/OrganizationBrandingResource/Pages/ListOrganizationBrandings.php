<?php

namespace App\Filament\Resources\OrganizationBrandingResource\Pages;

use App\Filament\Resources\OrganizationBrandingResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;

class ListOrganizationBrandings extends ListRecords
{
    protected static string $resource = OrganizationBrandingResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }
}
