<?php

namespace App\Filament\Resources\LdapConfigurations\Pages;

use App\Filament\Resources\LdapConfigurations\LdapConfigurationResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListLdapConfigurations extends ListRecords
{
    protected static string $resource = LdapConfigurationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
        ];
    }
}
