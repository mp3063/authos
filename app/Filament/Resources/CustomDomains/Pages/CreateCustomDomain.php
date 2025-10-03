<?php

namespace App\Filament\Resources\CustomDomains\Pages;

use App\Filament\Resources\CustomDomains\CustomDomainResource;
use App\Models\CustomDomain;
use Filament\Resources\Pages\CreateRecord;

class CreateCustomDomain extends CreateRecord
{
    protected static string $resource = CustomDomainResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        // Generate verification code automatically
        $data['verification_code'] = CustomDomain::generateVerificationCode();

        return $data;
    }
}
