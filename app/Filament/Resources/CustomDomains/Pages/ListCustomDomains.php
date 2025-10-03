<?php

namespace App\Filament\Resources\CustomDomains\Pages;

use App\Filament\Resources\CustomDomains\CustomDomainResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListCustomDomains extends ListRecords
{
    protected static string $resource = CustomDomainResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
        ];
    }
}
