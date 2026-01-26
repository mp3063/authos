<?php

namespace App\Filament\Resources\MigrationJobResource\Pages;

use App\Filament\Resources\MigrationJobResource;
use App\Jobs\ProcessAuth0MigrationJob;
use App\Jobs\ProcessOktaMigrationJob;
use App\Models\MigrationJob;
use App\Models\Organization;
use Filament\Actions\Action;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListMigrationJobs extends ListRecords
{
    protected static string $resource = MigrationJobResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('new_migration')
                ->label('New Migration')
                ->icon('heroicon-o-arrow-up-tray')
                ->color('primary')
                ->form([
                    Section::make('Migration Source')->schema([
                        Select::make('source')
                            ->options([
                                'auth0' => 'Auth0',
                                'okta' => 'Okta',
                            ])
                            ->required()
                            ->live()
                            ->helperText('Select the identity provider to migrate from'),

                        Select::make('organization_id')
                            ->label('Target Organization')
                            ->options(Organization::pluck('name', 'id'))
                            ->required()
                            ->searchable()
                            ->helperText('Organization to import users into'),
                    ]),

                    Section::make('Auth0 Configuration')
                        ->visible(fn ($get) => $get('source') === 'auth0')
                        ->schema([
                            TextInput::make('tenant_domain')
                                ->label('Auth0 Tenant Domain')
                                ->placeholder('your-tenant.auth0.com')
                                ->required()
                                ->helperText('Your Auth0 tenant domain'),
                            TextInput::make('api_token')
                                ->label('Management API Token')
                                ->password()
                                ->required()
                                ->helperText('Auth0 Management API access token'),
                        ]),

                    Section::make('Okta Configuration')
                        ->visible(fn ($get) => $get('source') === 'okta')
                        ->schema([
                            TextInput::make('okta_domain')
                                ->label('Okta Domain')
                                ->placeholder('your-org.okta.com')
                                ->required()
                                ->helperText('Your Okta organization domain'),
                            TextInput::make('okta_api_token')
                                ->label('API Token')
                                ->password()
                                ->required()
                                ->helperText('Okta API token with read permissions'),
                        ]),

                    Section::make('Migration Options')->schema([
                        Toggle::make('migrate_users')
                            ->label('Migrate Users')
                            ->default(true),
                        Toggle::make('migrate_applications')
                            ->label('Migrate Applications')
                            ->default(true),
                        Toggle::make('migrate_roles')
                            ->label('Migrate Roles')
                            ->default(true),
                        Select::make('password_strategy')
                            ->label('Password Strategy')
                            ->options([
                                'lazy' => 'Lazy Migration (verify on login)',
                                'reset' => 'Force Password Reset',
                                'hash' => 'Import Hash (if available)',
                            ])
                            ->default('lazy')
                            ->helperText('How to handle user passwords during migration'),
                    ]),
                ])
                ->action(function (array $data) {
                    $config = [
                        'migrate_users' => $data['migrate_users'] ?? true,
                        'migrate_applications' => $data['migrate_applications'] ?? true,
                        'migrate_roles' => $data['migrate_roles'] ?? true,
                        'password_strategy' => $data['password_strategy'] ?? 'lazy',
                    ];

                    if ($data['source'] === 'auth0') {
                        $config['tenant_domain'] = $data['tenant_domain'];
                        $config['api_token'] = $data['api_token'];
                    } elseif ($data['source'] === 'okta') {
                        $config['okta_domain'] = $data['okta_domain'];
                        $config['okta_api_token'] = $data['okta_api_token'];
                    }

                    $migrationJob = MigrationJob::create([
                        'organization_id' => $data['organization_id'],
                        'source' => $data['source'],
                        'status' => 'pending',
                        'config' => $config,
                    ]);

                    // Dispatch the appropriate job
                    if ($data['source'] === 'auth0') {
                        ProcessAuth0MigrationJob::dispatch($migrationJob);
                    } elseif ($data['source'] === 'okta') {
                        ProcessOktaMigrationJob::dispatch($migrationJob);
                    }

                    Notification::make()
                        ->title('Migration Started')
                        ->body("Migration #{$migrationJob->id} has been queued for processing.")
                        ->success()
                        ->send();
                })
                ->modalHeading('Start New Migration')
                ->modalDescription('Configure and start a new user migration from an external identity provider.')
                ->modalSubmitActionLabel('Start Migration')
                ->modalWidth('2xl'),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Jobs')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'pending'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'pending')->count())
                ->badgeColor('warning'),

            'running' => Tab::make('Running')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'running'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'running')->count())
                ->badgeColor('info'),

            'completed' => Tab::make('Completed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'completed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'completed')->count())
                ->badgeColor('success'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'failed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'failed')->count())
                ->badgeColor('danger'),
        ];
    }
}
