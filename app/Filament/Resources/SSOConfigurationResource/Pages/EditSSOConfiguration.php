<?php

namespace App\Filament\Resources\SSOConfigurationResource\Pages;

use App\Filament\Resources\SSOConfigurationResource;
use Filament\Actions;
use Filament\Resources\Pages\EditRecord;

class EditSSOConfiguration extends EditRecord
{
    protected static string $resource = SSOConfigurationResource::class;

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
