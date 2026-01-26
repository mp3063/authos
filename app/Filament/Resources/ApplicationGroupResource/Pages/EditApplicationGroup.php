<?php

namespace App\Filament\Resources\ApplicationGroupResource\Pages;

use App\Filament\Resources\ApplicationGroupResource;
use Filament\Actions;
use Filament\Resources\Pages\EditRecord;

class EditApplicationGroup extends EditRecord
{
    protected static string $resource = ApplicationGroupResource::class;

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
