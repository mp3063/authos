<?php

namespace Database\Seeders;

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
            RolePermissionSeeder::class,
            OrganizationSeeder::class,
            ApplicationSeeder::class,
        ]);

        // Create a super admin user
        $superAdmin = User::factory()->create([
            'name' => 'Super Admin',
            'email' => 'admin@authservice.com',
        ]);
        
        $superAdmin->assignRole('Super Admin');

        // Create a demo organization admin
        $orgAdmin = User::factory()->create([
            'name' => 'Demo Admin',
            'email' => 'demo@demo-corp.com',
        ]);
        
        $orgAdmin->assignRole('Organization Admin');

        // Create some regular users
        User::factory(5)->create();
    }
}
