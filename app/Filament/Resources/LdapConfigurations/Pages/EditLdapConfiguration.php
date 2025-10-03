<?php

namespace App\Filament\Resources\LdapConfigurations\Pages;

use App\Filament\Resources\LdapConfigurations\LdapConfigurationResource;
use Filament\Actions\DeleteAction;
use Filament\Resources\Pages\EditRecord;

class EditLdapConfiguration extends EditRecord
{
    protected static string $resource = LdapConfigurationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            DeleteAction::make(),
        ];
    }
}
