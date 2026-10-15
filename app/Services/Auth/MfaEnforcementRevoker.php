<?php

namespace App\Services\Auth;

use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class MfaEnforcementRevoker
{
    private const NONE = ['access' => 0, 'refresh' => 0, 'sso' => 0];

    public function __construct(private int $chunkSize = 500) {}

    /**
     * @return array{access: int, refresh: int, sso: int}
     */
    public function revokeForAllOrganizations(bool $dryRun = false): array
    {
        $totals = self::NONE;

        Organization::query()->chunkById(100, function (Collection $organizations) use ($dryRun, &$totals) {
            foreach ($organizations as $organization) {
                $totals = $this->sum($totals, $this->revokeForOrganization($organization, $dryRun));
            }
        });

        return $totals;
    }

    /**
     * @return array{access: int, refresh: int, sso: int}
     */
    public function revokeForOrganization(Organization $organization, bool $dryRun = false): array
    {
        $totals = self::NONE;

        if (! $organization->requiresMfa()) {
            return $totals;
        }

        $organization->organizationUsers()->withTrashed()->chunkById($this->chunkSize, function (Collection $users) use ($organization, $dryRun, &$totals) {
            $userIds = $users
                ->each(fn (User $user) => $user->setRelation('organization', $organization))
                ->filter(fn (User $user) => $user->mustSetUpMfa())
                ->modelKeys();

            if ($userIds !== []) {
                $totals = $this->sum($totals, $this->revoke($userIds, $dryRun));
            }
        });

        return $totals;
    }

    /**
     * @return array{access: int, refresh: int, sso: int}
     */
    public function revokeForUser(User $user): array
    {
        return $user->mustSetUpMfa() ? $this->revoke([$user->getKey()], false) : self::NONE;
    }

    /**
     * @return array{access: int, refresh: int, sso: int}
     */
    public function revokeAllForUser(User $user): array
    {
        return $this->revoke([$user->getKey()], false);
    }

    /**
     * @param  array<int, int|string>  $userIds
     * @return array{access: int, refresh: int, sso: int}
     */
    private function revoke(array $userIds, bool $dryRun): array
    {
        $accessTokens = DB::table('oauth_access_tokens')
            ->whereIn('user_id', $userIds)
            ->where('revoked', false);
        $refreshTokens = DB::table('oauth_refresh_tokens')
            ->where('revoked', false)
            ->whereIn('access_token_id', DB::table('oauth_access_tokens')->whereIn('user_id', $userIds)->select('id'));
        $sessions = SSOSession::query()->whereIn('user_id', $userIds)->active();

        $counts = [
            'access' => (clone $accessTokens)->count(),
            'refresh' => (clone $refreshTokens)->count(),
            'sso' => (clone $sessions)->count(),
        ];

        if (! $dryRun) {
            $refreshTokens->update(['revoked' => true]);
            $accessTokens->update(['revoked' => true]);
            $sessions->get()->each->logout();
        }

        return $counts;
    }

    /**
     * @param  array{access: int, refresh: int, sso: int}  $totals
     * @param  array{access: int, refresh: int, sso: int}  $counts
     * @return array{access: int, refresh: int, sso: int}
     */
    private function sum(array $totals, array $counts): array
    {
        return [
            'access' => $totals['access'] + $counts['access'],
            'refresh' => $totals['refresh'] + $counts['refresh'],
            'sso' => $totals['sso'] + $counts['sso'],
        ];
    }
}
