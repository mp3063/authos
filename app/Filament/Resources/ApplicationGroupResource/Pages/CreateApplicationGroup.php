<?php

namespace App\Filament\Resources\ApplicationGroupResource\Pages;

use App\Filament\Concerns\ForcesCallerOrganization;
use App\Filament\Resources\ApplicationGroupResource;
use Filament\Resources\Pages\CreateRecord;

class CreateApplicationGroup extends CreateRecord
{
    use ForcesCallerOrganization;

    protected static string $resource = ApplicationGroupResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        return $this->forceCallerOrganization($data);
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
