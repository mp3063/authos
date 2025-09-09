<?php

namespace Database\Seeders;

use App\Models\Organization;
use Illuminate\Database\Seeder;

class OrganizationSeeder extends Seeder
{
    public function run(): void
    {
        $organizations = [
            [
                'name' => 'Default Organization',
                'slug' => 'default',
                'settings' => [
                    'branding' => [
                        'logo' => null,
                        'primary_color' => '#3B82F6',
                        'secondary_color' => '#1E293B',
                    ],
                    'authentication' => [
                        'require_email_verification' => true,
                        'password_min_length' => 8,
                        'enable_social_login' => true,
                        'require_mfa' => false,
                    ],
                    'security' => [
                        'session_timeout' => 3600,
                        'max_login_attempts' => 5,
                        'lockout_duration' => 300,
                    ],
                ],
                'is_active' => true,
            ],
            [
                'name' => 'Demo Corp',
                'slug' => 'demo-corp',
                'settings' => [
                    'branding' => [
                        'logo' => null,
                        'primary_color' => '#10B981',
                        'secondary_color' => '#374151',
                    ],
                    'authentication' => [
                        'require_email_verification' => true,
                        'password_min_length' => 12,
                        'enable_social_login' => false,
                        'require_mfa' => true,
                    ],
                    'security' => [
                        'session_timeout' => 1800,
                        'max_login_attempts' => 3,
                        'lockout_duration' => 600,
                    ],
                ],
                'is_active' => true,
            ],
        ];

        foreach ($organizations as $org) {
            Organization::firstOrCreate(
                ['slug' => $org['slug']],
                $org
            );
        }
    }
}
