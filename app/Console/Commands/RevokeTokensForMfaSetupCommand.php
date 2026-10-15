<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\Auth\MfaEnforcementRevoker;
use Illuminate\Console\Command;

class RevokeTokensForMfaSetupCommand extends Command
{
    protected $signature = 'auth:revoke-tokens-for-mfa-setup {--dry-run : Report what would be revoked without changing anything}';

    protected $description = 'Revoke tokens and SSO sessions of members who must set up MFA';

    public function handle(MfaEnforcementRevoker $revoker): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $totals = $revoker->revokeForAllOrganizations($dryRun);

        $this->info(($dryRun ? 'Would revoke' : 'Revoked').':');
        $this->line("Access tokens: {$totals['access']}");
        $this->line("Refresh tokens: {$totals['refresh']}");
        $this->line("SSO sessions: {$totals['sso']}");

        return self::SUCCESS;
    }
}
