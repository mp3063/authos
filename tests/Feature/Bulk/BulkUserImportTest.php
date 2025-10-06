<?php

namespace Tests\Feature\Bulk;

use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class BulkUserImportTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    public function test_imports_valid_users(): void
    {
        $records = [
            ['email' => 'user1@example.com', 'name' => 'User One', 'role' => 'user'],
            ['email' => 'user2@example.com', 'name' => 'User Two', 'role' => 'user'],
            ['email' => 'user3@example.com', 'name' => 'User Three', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals('completed', $job->status);
        $this->assertEquals(3, $job->processed_records);
        $this->assertEquals(3, $job->successful_records);
        $this->assertDatabaseHas('users', ['email' => 'user1@example.com']);
        $this->assertDatabaseHas('users', ['email' => 'user2@example.com']);
        $this->assertDatabaseHas('users', ['email' => 'user3@example.com']);
    }

    public function test_skips_invalid_users(): void
    {
        $records = [
            ['email' => 'valid@example.com', 'name' => 'Valid User', 'role' => 'user'],
            ['email' => 'invalid-email', 'name' => 'Invalid User', 'role' => 'user'],
            ['email' => '', 'name' => 'No Email', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals('completed_with_errors', $job->status);
        $this->assertEquals(1, $job->successful_records);
        $this->assertEquals(2, $job->failed_records);
        $this->assertDatabaseHas('users', ['email' => 'valid@example.com']);
        $this->assertDatabaseMissing('users', ['email' => 'invalid-email']);
    }

    public function test_updates_existing_users(): void
    {
        User::factory()->for($this->organization)->create([
            'email' => 'existing@example.com',
            'name' => 'Old Name',
        ]);

        $records = [
            ['email' => 'existing@example.com', 'name' => 'New Name', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
                'options' => ['duplicate_strategy' => 'update'],
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $user = User::where('email', 'existing@example.com')->first();

        $this->assertEquals('New Name', $user->name);
    }

    public function test_assigns_roles_to_imported_users(): void
    {
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'web']);

        $records = [
            ['email' => 'user@example.com', 'name' => 'User', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $user = User::where('email', 'user@example.com')->first();

        $this->assertTrue($user->hasRole('User'));
    }

    public function test_sends_invitations_when_enabled(): void
    {
        Notification::fake();

        $records = [
            ['email' => 'user@example.com', 'name' => 'User', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
                'options' => ['send_invitations' => true],
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        Notification::assertSentTo(
            User::where('email', 'user@example.com')->first(),
            \App\Notifications\UserInvitationNotification::class
        );
    }

    public function test_tracks_progress_during_import(): void
    {
        $records = array_map(function ($i) {
            return ['email' => "user{$i}@example.com", 'name' => "User {$i}", 'role' => 'user'];
        }, range(1, 10));

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals(10, $job->processed_records);
        $this->assertNotNull($job->completed_at);
    }

    public function test_generates_error_report(): void
    {
        $records = [
            ['email' => 'valid@example.com', 'name' => 'Valid', 'role' => 'user'],
            ['email' => 'invalid-email', 'name' => 'Invalid', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertNotNull($job->error_file_path);
        $this->assertCount(1, $job->errors);
    }

    public function test_handles_large_import_in_batches(): void
    {
        Queue::fake();

        $records = array_map(function ($i) {
            return ['email' => "user{$i}@example.com", 'name' => "User {$i}", 'role' => 'user'];
        }, range(1, 500));

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        // Verify users were created
        $this->assertEquals(500, User::where('organization_id', $this->organization->id)->count());
    }

    public function test_sets_default_password_for_imported_users(): void
    {
        $records = [
            ['email' => 'user@example.com', 'name' => 'User', 'role' => 'user'],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $user = User::where('email', 'user@example.com')->first();

        $this->assertNotNull($user->password);
    }

    public function test_handles_custom_fields(): void
    {
        $records = [
            [
                'email' => 'user@example.com',
                'name' => 'User',
                'role' => 'user',
                'phone' => '+1234567890',
                'job_title' => 'Developer',
            ],
        ];

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($job);
        $processor->handle();

        $user = User::where('email', 'user@example.com')->first();

        $this->assertEquals('+1234567890', $user->phone ?? null);
    }
}
