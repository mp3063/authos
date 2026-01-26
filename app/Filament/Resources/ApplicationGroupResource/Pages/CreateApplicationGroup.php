<?php

namespace App\Filament\Resources\ApplicationGroupResource\Pages;

use App\Filament\Resources\ApplicationGroupResource;
use Filament\Resources\Pages\CreateRecord;

class CreateApplicationGroup extends CreateRecord
{
    protected static string $resource = ApplicationGroupResource::class;

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
