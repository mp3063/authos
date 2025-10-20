<?php

namespace Database\Seeders;

use App\Models\Organization;
use App\Models\User;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        $this->call([
            OrganizationSeeder::class,
            RolePermissionSeeder::class,
            ApplicationSeeder::class,
            WebhookEventSeeder::class,
            WebhookSeeder::class,
        ]);

        // Create a super admin user (global, no organization)
        $superAdmin = User::factory()->create([
            'name' => 'Super Admin',
            'email' => 'admin@authservice.com',
            'organization_id' => null, // Global user
        ]);

        // Assign global role without organization context
        $superAdmin->assignGlobalRole('Super Admin');

        // Get organizations to assign users to them
        $defaultOrg = Organization::where('slug', 'default')->first();
        $demoCorpOrg = Organization::where('slug', 'demo-corp')->first();

        // Create an organization admin for Default Organization
        $defaultAdmin = User::factory()->create([
            'name' => 'Default Admin',
            'email' => 'admin@default.com',
            'organization_id' => $defaultOrg->id,
        ]);

        // Assign organization role using organization context
        $defaultAdmin->assignOrganizationRole('Organization Owner', $defaultOrg->id);

        // Create an organization admin for Demo Corp
        $demoAdmin = User::factory()->create([
            'name' => 'Demo Admin',
            'email' => 'admin@democorp.com',
            'organization_id' => $demoCorpOrg->id,
        ]);

        $demoAdmin->assignOrganizationRole('Organization Owner', $demoCorpOrg->id);

        // Create some regular users for Default Organization
        $defaultUsers = User::factory(3)->create(['organization_id' => $defaultOrg->id]);
        foreach ($defaultUsers as $user) {
            $user->assignOrganizationRole('User', $defaultOrg->id);
        }

        // Create some regular users for Demo Corp
        $demoUsers = User::factory(2)->create(['organization_id' => $demoCorpOrg->id]);
        foreach ($demoUsers as $user) {
            $user->assignOrganizationRole('User', $demoCorpOrg->id);
        }
    }
}
