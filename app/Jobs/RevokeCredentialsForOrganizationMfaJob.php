<?php

namespace App\Jobs;

use App\Models\Organization;
use App\Services\Auth\MfaEnforcementRevoker;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class RevokeCredentialsForOrganizationMfaJob implements ShouldQueue
{
    use Queueable;

    public bool $deleteWhenMissingModels = true;

    public function __construct(public Organization $organization) {}

    public function handle(MfaEnforcementRevoker $revoker): void
    {
        $revoker->revokeForOrganization($this->organization);
    }
}
