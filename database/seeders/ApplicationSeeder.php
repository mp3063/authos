<?php

namespace Database\Seeders;

use App\Models\Application;
use App\Models\Organization;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class ApplicationSeeder extends Seeder
{
    public function run(): void
    {
        $defaultOrg = Organization::where('slug', 'default')->first();
        $demoOrg = Organization::where('slug', 'demo-corp')->first();

        $applications = [
            [
                'organization_id' => $defaultOrg->id,
                'name' => 'Demo Web App',
                'redirect_uris' => [
                    'http://localhost:3000/callback',
                    'https://demo-app.com/callback',
                ],
                'allowed_origins' => [
                    'http://localhost:3000',
                    'https://demo-app.com',
                ],
                'allowed_grant_types' => [
                    'authorization_code',
                    'refresh_token',
                ],
                'webhook_url' => 'https://demo-app.com/webhooks/auth',
                'settings' => [
                    'token_lifetime' => 3600,
                    'refresh_token_lifetime' => 86400,
                    'require_pkce' => true,
                    'require_mfa' => false,
                ],
                'is_active' => true,
            ],
            [
                'organization_id' => $defaultOrg->id,
                'name' => 'Mobile App',
                'redirect_uris' => [
                    'com.demo.app://callback',
                ],
                'allowed_origins' => [],
                'allowed_grant_types' => [
                    'authorization_code',
                    'refresh_token',
                ],
                'webhook_url' => null,
                'settings' => [
                    'token_lifetime' => 1800,
                    'refresh_token_lifetime' => 604800,
                    'require_pkce' => true,
                    'require_mfa' => false,
                ],
                'is_active' => true,
            ],
            [
                'organization_id' => $demoOrg->id,
                'name' => 'Enterprise Dashboard',
                'redirect_uris' => [
                    'https://enterprise.demo-corp.com/auth/callback',
                ],
                'allowed_origins' => [
                    'https://enterprise.demo-corp.com',
                ],
                'allowed_grant_types' => [
                    'authorization_code',
                    'refresh_token',
                    'client_credentials',
                ],
                'webhook_url' => 'https://enterprise.demo-corp.com/webhooks/auth-service',
                'settings' => [
                    'token_lifetime' => 1800,
                    'refresh_token_lifetime' => 43200,
                    'require_pkce' => true,
                    'require_mfa' => true,
                ],
                'is_active' => true,
            ],
        ];

        foreach ($applications as $app) {
            Application::firstOrCreate(
                [
                    'organization_id' => $app['organization_id'],
                    'name' => $app['name'],
                ],
                $app
            );
        }
    }
}
