<?php

namespace App\Filament\Resources\CustomDomains\Pages;

use App\Filament\Resources\CustomDomains\CustomDomainResource;
use Filament\Actions\DeleteAction;
use Filament\Resources\Pages\EditRecord;

class EditCustomDomain extends EditRecord
{
    protected static string $resource = CustomDomainResource::class;

    protected function getHeaderActions(): array
    {
        return [
            DeleteAction::make(),
        ];
    }
}
