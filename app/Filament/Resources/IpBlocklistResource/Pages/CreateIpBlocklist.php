<?php

namespace App\Filament\Resources\IpBlocklistResource\Pages;

use App\Filament\Resources\IpBlocklistResource;
use Filament\Resources\Pages\CreateRecord;

class CreateIpBlocklist extends CreateRecord
{
    protected static string $resource = IpBlocklistResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $data['blocked_by'] = auth()->id();
        $data['blocked_at'] = now();

        return $data;
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('index');
    }
}
