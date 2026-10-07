<?php

namespace App\Models\Concerns;

use App\Models\CustomDomain;
use App\Models\LdapConfiguration;
use App\Models\MigrationJob;
use App\Models\OrganizationBranding;
use App\Models\Webhook;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

trait HasEnterpriseIntegrations
{
    public function branding(): HasOne
    {
        return $this->hasOne(OrganizationBranding::class);
    }

    public function customDomains(): HasMany
    {
        return $this->hasMany(CustomDomain::class);
    }

    public function ldapConfigurations(): HasMany
    {
        return $this->hasMany(LdapConfiguration::class);
    }

    public function webhooks(): HasMany
    {
        return $this->hasMany(Webhook::class);
    }

    public function migrationJobs(): HasMany
    {
        return $this->hasMany(MigrationJob::class);
    }
}
