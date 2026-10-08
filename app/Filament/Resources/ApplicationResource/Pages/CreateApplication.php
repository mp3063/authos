<?php

namespace App\Filament\Resources\ApplicationResource\Pages;

use App\Filament\Concerns\ForcesCallerOrganization;
use App\Filament\Resources\ApplicationResource;
use Filament\Resources\Pages\CreateRecord;

class CreateApplication extends CreateRecord
{
    use ForcesCallerOrganization;

    protected static string $resource = ApplicationResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        return $this->forceCallerOrganization($data);
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('index');
    }
}
