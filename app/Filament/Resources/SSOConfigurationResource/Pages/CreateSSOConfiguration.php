<?php

namespace App\Filament\Resources\SSOConfigurationResource\Pages;

use App\Filament\Resources\SSOConfigurationResource;
use Filament\Resources\Pages\CreateRecord;

class CreateSSOConfiguration extends CreateRecord
{
    protected static string $resource = SSOConfigurationResource::class;

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
