<?php

use App\Http\Middleware\EnsureOrganizationMfaIsSetUp;

return [

    /*
    |--------------------------------------------------------------------------
    | Passport Guard
    |--------------------------------------------------------------------------
    |
    | Here you may specify which authentication guard Passport will use when
    | authenticating users. This value should correspond with one of your
    | guards that is already present in your "auth" configuration file.
    |
    */

    'guard' => 'web',

    'middleware' => [
        EnsureOrganizationMfaIsSetUp::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Encryption Keys
    |--------------------------------------------------------------------------
    |
    | Passport uses encryption keys while generating secure access tokens for
    | your application. By default, the keys are stored as local files but
    | can be set via environment variables when that is more convenient.
    |
    */

    'private_key' => env('PASSPORT_PRIVATE_KEY'),

    'public_key' => env('PASSPORT_PUBLIC_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Passport Database Connection
    |--------------------------------------------------------------------------
    |
    | By default, Passport's models will utilize your application's default
    | database connection. If you wish to use a different connection you
    | may specify the configured name of the database connection here.
    |
    */

    'connection' => env('PASSPORT_CONNECTION'),

    /*
    |--------------------------------------------------------------------------
    | Token Scopes
    |--------------------------------------------------------------------------
    |
    | The scopes AuthOS registers with Passport. API login may request any of
    | them except "*".
    |
    */

    'scopes' => [
        '*' => 'Full access',
        'openid' => 'OpenID Connect access',
        'profile' => 'Access user profile information',
        'email' => 'Access user email address',
        'read' => 'Read access to your account',
        'write' => 'Write access to your account',
        'users.read' => 'Read user information',
        'users.write' => 'Write user information',
        'users.update' => 'Update user information',
        'users.delete' => 'Delete users',
        'users.manage' => 'Manage users',
        'applications.read' => 'Read application information',
        'applications.write' => 'Write application information',
        'applications.update' => 'Update applications',
        'applications.delete' => 'Delete applications',
        'applications.manage' => 'Manage applications',
        'organizations.read' => 'Read organization information',
        'organizations.write' => 'Write organization information',
        'organizations.update' => 'Update organizations',
        'organizations.manage' => 'Manage organizations',
        'sso' => 'Single Sign-On access',
        'roles.assign' => 'Assign roles to users',
        'mfa.setup' => 'Set up multi-factor authentication',
        'enterprise.audit.read' => 'Read audit exports',
        'enterprise.audit.manage' => 'Create audit exports',
        'enterprise.compliance.read' => 'Read and generate compliance reports',
        'enterprise.compliance.manage' => 'Manage compliance report schedules',
        'enterprise.branding.manage' => 'Manage organization branding',
    ],

];
