<?php

namespace App\Filament\Resources\LdapConfigurations\Pages;

use App\Filament\Concerns\ForcesCallerOrganization;
use App\Filament\Resources\LdapConfigurations\LdapConfigurationResource;
use Filament\Resources\Pages\CreateRecord;

class CreateLdapConfiguration extends CreateRecord
{
    use ForcesCallerOrganization;

    protected static string $resource = LdapConfigurationResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        return $this->forceCallerOrganization($data);
    }
}
