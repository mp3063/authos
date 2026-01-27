<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\InvitationService;
use Illuminate\Console\Command;

class CleanupExpiredInvitations extends Command
{
    protected $signature = 'invitations:cleanup-expired';

    protected $description = 'Delete expired invitation records';

    public function handle(InvitationService $invitationService): int
    {
        $this->info('Cleaning up expired invitations...');

        $deleted = $invitationService->cleanupExpiredInvitations();

        $this->info("Deleted {$deleted} expired invitation(s).");

        return self::SUCCESS;
    }
}
