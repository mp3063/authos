<?php

namespace App\Filament\Resources\LdapConfigurations\Pages;

use App\Filament\Resources\LdapConfigurations\LdapConfigurationResource;
use Filament\Resources\Pages\CreateRecord;

class CreateLdapConfiguration extends CreateRecord
{
    protected static string $resource = LdapConfigurationResource::class;
}
