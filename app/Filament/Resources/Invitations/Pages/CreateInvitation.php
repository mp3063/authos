<?php

namespace App\Filament\Resources\Invitations\Pages;

use App\Filament\Concerns\ForcesCallerOrganization;
use App\Filament\Resources\Invitations\InvitationResource;
use Filament\Resources\Pages\CreateRecord;

class CreateInvitation extends CreateRecord
{
    use ForcesCallerOrganization;

    protected static string $resource = InvitationResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $data = $this->forceCallerOrganization($data);

        $data['inviter_id'] = auth()->id();

        return $data;
    }
}
