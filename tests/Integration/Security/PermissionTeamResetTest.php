<?php

namespace Tests\Integration\Security;

use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
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

        event(new JobProcessed('sync', Mockery::mock(Job::class)->shouldIgnoreMissing()));

        $this->assertNull($registrar->getPermissionsTeamId());
    }

    #[Test]
    public function it_starts_every_queue_job_without_a_team_left_by_a_retried_job(): void
    {
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId('org-1');

        event(new JobExceptionOccurred('sync', Mockery::mock(Job::class)->shouldIgnoreMissing(), new \RuntimeException('boom')));
        event(new JobProcessing('sync', Mockery::mock(Job::class)->shouldIgnoreMissing()));

        $this->assertNull($registrar->getPermissionsTeamId());
    }
}
