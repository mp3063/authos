<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class RevokeTokensForMfaSetupCommand extends Command
{
    protected $signature = 'auth:revoke-tokens-for-mfa-setup {--dry-run : Report what would be revoked without changing anything}';

    protected $description = 'Revoke tokens and SSO sessions of members who must set up MFA';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $totals = ['access' => 0, 'refresh' => 0, 'sso' => 0];

        Organization::query()->chunkById(100, function ($organizations) use ($dryRun, &$totals) {
            foreach ($organizations as $organization) {
                if (! $organization->requiresMfa()) {
                    continue;
                }

                $organization->organizationUsers()->chunkById(500, function ($users) use ($dryRun, &$totals) {
                    $userIds = $users->filter(fn (User $user) => $user->mustSetUpMfa())->pluck('id')->all();

                    if ($userIds !== []) {
                        $this->revoke($userIds, $dryRun, $totals);
                    }
                });
            }
        });

        $this->info(($dryRun ? 'Would revoke' : 'Revoked').':');
        $this->line("Access tokens: {$totals['access']}");
        $this->line("Refresh tokens: {$totals['refresh']}");
        $this->line("SSO sessions: {$totals['sso']}");

        return self::SUCCESS;
    }

    /**
     * @param  array<int, int|string>  $userIds
     * @param  array{access: int, refresh: int, sso: int}  $totals
     */
    private function revoke(array $userIds, bool $dryRun, array &$totals): void
    {
        $accessTokens = DB::table('oauth_access_tokens')
            ->whereIn('user_id', $userIds)
            ->where('revoked', false);
        $refreshTokens = DB::table('oauth_refresh_tokens')
            ->where('revoked', false)
            ->whereIn('access_token_id', DB::table('oauth_access_tokens')->whereIn('user_id', $userIds)->select('id'));
        $sessions = SSOSession::query()->whereIn('user_id', $userIds)->active();

        $totals['access'] += (clone $accessTokens)->count();
        $totals['refresh'] += (clone $refreshTokens)->count();
        $totals['sso'] += (clone $sessions)->count();

        if ($dryRun) {
            return;
        }

        $refreshTokens->update(['revoked' => true]);
        $accessTokens->update(['revoked' => true]);
        $sessions->get()->each->logout();
    }
}
