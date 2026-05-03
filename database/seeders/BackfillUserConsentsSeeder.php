<?php

namespace Database\Seeders;

use App\Models\User;
use App\Models\UserConsent;
use Illuminate\Database\Seeder;

class BackfillUserConsentsSeeder extends Seeder
{
    /**
     * One-off backfill: every existing user with an organization gets a
     * 'terms' consent recorded as of now. This ensures the GDPR PDF
     * doesn't appear empty on first generation post-deploy.
     *
     * Idempotent — running twice does nothing additional thanks to the
     * unique (user_id, consent_type) constraint enforced by updateOrCreate.
     */
    public function run(): void
    {
        $count = 0;
        User::query()
            ->whereNotNull('organization_id')
            ->select(['id', 'organization_id', 'created_at'])
            ->chunkById(500, function ($users) use (&$count): void {
                foreach ($users as $user) {
                    UserConsent::query()->updateOrCreate(
                        [
                            'user_id' => $user->id,
                            'consent_type' => UserConsent::TYPE_TERMS,
                        ],
                        [
                            'organization_id' => $user->organization_id,
                            'terms_version' => 'backfill-pre-mvp',
                            'given_at' => $user->created_at ?? now(),
                            'withdrawn_at' => null,
                        ],
                    );
                    $count++;
                }
            });

        $this->command?->info("Backfilled terms consent for {$count} users");
    }
}
