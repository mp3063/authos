<?php

namespace Tests\Integration\Security;

use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobProcessed;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class PermissionTeamResetTest extends IntegrationTestCase
{
    #[Test]
    public function it_resets_the_permission_team_when_the_app_terminates(): void
    {
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId('org-1');

        app()->terminate();

        $this->assertNull($registrar->getPermissionsTeamId());
    }

    #[Test]
    public function it_resets_the_permission_team_between_queue_jobs(): void
    {
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId('org-1');

        event(new JobProcessed('sync', Mockery::mock(Job::class)));

        $this->assertNull($registrar->getPermissionsTeamId());
    }
}
