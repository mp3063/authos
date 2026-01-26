<?php

namespace App\Filament\Resources;

use App\Filament\Resources\SSOConfigurationResource\Pages\CreateSSOConfiguration;
use App\Filament\Resources\SSOConfigurationResource\Pages\EditSSOConfiguration;
use App\Filament\Resources\SSOConfigurationResource\Pages\ListSSOConfigurations;
use App\Filament\Resources\SSOConfigurationResource\Pages\ViewSSOConfiguration;
use App\Models\SSOConfiguration;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class SSOConfigurationResource extends Resource
{
    protected static ?string $model = SSOConfiguration::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('SSO Configuration')->schema([
                TextInput::make('name')
                    ->label('Configuration Name')
                    ->required()
                    ->maxLength(255)
                    ->helperText('A descriptive name for this SSO configuration'),

                Select::make('provider')
                    ->label('Provider Type')
                    ->options([
                        'oidc' => 'OpenID Connect (OIDC)',
                        'saml' => 'SAML 2.0',
                        'saml2' => 'SAML 2.0 (Legacy)',
                    ])
                    ->required()
                    ->reactive()
                    ->live()
                    ->helperText('Select the SSO protocol to use'),

                Select::make('application_id')
                    ->label('Application')
                    ->relationship('application', 'name')
                    ->searchable()
                    ->preload()
                    ->required()
                    ->helperText('The application this SSO configuration belongs to'),

                Toggle::make('is_active')
                    ->label('Active')
                    ->default(true)
                    ->helperText('Inactive configurations will not be available for authentication'),

                TextInput::make('callback_url')
                    ->label('Callback URL')
                    ->url()
                    ->maxLength(2048)
                    ->helperText('The URL to redirect to after successful authentication')
                    ->columnSpanFull(),

                TextInput::make('logout_url')
                    ->label('Logout URL')
                    ->url()
                    ->maxLength(2048)
                    ->helperText('The URL to redirect to after logout')
                    ->columnSpanFull(),
            ])->columns(2),

            Section::make('OIDC Settings')
                ->schema([
                    KeyValue::make('configuration')
                        ->label('OIDC Configuration')
                        ->keyLabel('Setting')
                        ->valueLabel('Value')
                        ->default([
                            'client_id' => '',
                            'client_secret' => '',
                            'discovery_url' => '',
                            'authorization_endpoint' => '',
                            'token_endpoint' => '',
                            'userinfo_endpoint' => '',
                            'scopes' => 'openid profile email',
                        ])
                        ->helperText('Configure the OIDC provider settings. Common keys: client_id, client_secret, discovery_url, authorization_endpoint, token_endpoint, userinfo_endpoint, scopes.')
                        ->columnSpanFull(),
                ])
                ->visible(fn ($get) => $get('provider') === 'oidc')
                ->collapsible(),

            Section::make('SAML IdP Configuration')
                ->schema([
                    TextInput::make('configuration.idp_entity_id')
                        ->label('IdP Entity ID')
                        ->required()
                        ->maxLength(2048)
                        ->helperText('The Entity ID (Issuer) of the Identity Provider')
                        ->columnSpanFull(),

                    TextInput::make('configuration.idp_sso_url')
                        ->label('IdP SSO URL')
                        ->url()
                        ->required()
                        ->maxLength(2048)
                        ->helperText('The Single Sign-On URL of the Identity Provider'),

                    TextInput::make('configuration.idp_slo_url')
                        ->label('IdP SLO URL')
                        ->url()
                        ->maxLength(2048)
                        ->helperText('The Single Logout URL of the Identity Provider (optional)'),
                ])
                ->columns(2)
                ->visible(fn ($get) => in_array($get('provider'), ['saml', 'saml2']))
                ->collapsible(),

            Section::make('SAML Certificate Management')
                ->schema([
                    Textarea::make('configuration.x509_cert')
                        ->label('IdP Certificate (PEM)')
                        ->required()
                        ->rows(6)
                        ->helperText('Paste the IdP X.509 certificate in PEM format (including BEGIN/END CERTIFICATE lines)')
                        ->columnSpanFull(),

                    Textarea::make('configuration.sp_x509_cert')
                        ->label('SP Certificate (PEM)')
                        ->rows(6)
                        ->helperText('Optional: Paste the Service Provider X.509 certificate for signing requests')
                        ->columnSpanFull(),
                ])
                ->visible(fn ($get) => in_array($get('provider'), ['saml', 'saml2']))
                ->collapsible(),

            Section::make('SAML NameID & SP Configuration')
                ->schema([
                    Select::make('settings.name_id_format')
                        ->label('NameID Format')
                        ->options([
                            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' => 'Email Address',
                            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' => 'Persistent',
                            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' => 'Transient',
                            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified' => 'Unspecified',
                        ])
                        ->default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
                        ->helperText('The NameID format to request from the Identity Provider'),

                    TextInput::make('configuration.sp_entity_id')
                        ->label('SP Entity ID')
                        ->maxLength(2048)
                        ->helperText('The Entity ID of this Service Provider (auto-generated if left empty)'),

                    Select::make('configuration.signature_algorithm')
                        ->label('Signature Algorithm')
                        ->options([
                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'RSA-SHA256 (Recommended)',
                            'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => 'RSA-SHA1 (Legacy)',
                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => 'RSA-SHA384',
                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => 'RSA-SHA512',
                        ])
                        ->default('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
                        ->helperText('The algorithm used for signing SAML requests'),
                ])
                ->columns(2)
                ->visible(fn ($get) => in_array($get('provider'), ['saml', 'saml2']))
                ->collapsible(),

            Section::make('SAML Attribute Mapping')
                ->schema([
                    KeyValue::make('configuration.attribute_mapping')
                        ->label('Attribute Mapping')
                        ->keyLabel('Application Attribute')
                        ->valueLabel('SAML Attribute')
                        ->default([
                            'email' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                            'name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                            'first_name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
                            'last_name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
                        ])
                        ->helperText('Map SAML assertion attributes to application user fields')
                        ->columnSpanFull(),
                ])
                ->visible(fn ($get) => in_array($get('provider'), ['saml', 'saml2']))
                ->collapsible(),

            Section::make('Domain & Session')->schema([
                TagsInput::make('allowed_domains')
                    ->label('Allowed Domains')
                    ->placeholder('Add domain...')
                    ->helperText('Restrict SSO to specific email domains. Supports wildcards (e.g., *.example.com). Leave empty to allow all domains.')
                    ->columnSpanFull(),

                TextInput::make('session_lifetime')
                    ->label('Session Lifetime (minutes)')
                    ->numeric()
                    ->default(60)
                    ->minValue(1)
                    ->maxValue(43200)
                    ->helperText('Maximum session duration in minutes before re-authentication is required'),
            ])->columns(2),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')
                ->searchable()
                ->sortable()
                ->weight('bold')
                ->description(fn (SSOConfiguration $record): ?string => $record->callback_url ? \Illuminate\Support\Str::limit($record->callback_url, 50) : null),

            TextColumn::make('provider')
                ->label('Provider')
                ->badge()
                ->formatStateUsing(fn (string $state): string => strtoupper($state))
                ->color(fn (string $state): string => match ($state) {
                    'oidc' => 'info',
                    'saml', 'saml2' => 'warning',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('application.name')
                ->label('Application')
                ->badge()
                ->searchable()
                ->sortable(),

            IconColumn::make('is_active')
                ->label('Status')
                ->boolean()
                ->sortable()
                ->trueIcon('heroicon-o-check-circle')
                ->falseIcon('heroicon-o-x-circle')
                ->trueColor('success')
                ->falseColor('danger'),

            TextColumn::make('allowed_domains')
                ->label('Domains')
                ->formatStateUsing(fn ($state, SSOConfiguration $record): string => count($record->allowed_domains ?? []).' domain(s)')
                ->tooltip(fn (SSOConfiguration $record): ?string => ! empty($record->allowed_domains) ? implode(', ', $record->allowed_domains) : 'All domains allowed')
                ->badge()
                ->color('gray'),

            TextColumn::make('session_lifetime')
                ->label('Session Lifetime')
                ->suffix(' min')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('provider')
                ->label('Provider Type')
                ->options([
                    'oidc' => 'OIDC',
                    'saml' => 'SAML 2.0',
                    'saml2' => 'SAML 2.0 (Legacy)',
                ]),

            TernaryFilter::make('is_active')
                ->label('Status')
                ->boolean()
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),
                Action::make('enable')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->visible(fn (SSOConfiguration $record) => ! $record->is_active)
                    ->action(function (SSOConfiguration $record) {
                        $record->update(['is_active' => true]);

                        Notification::make()
                            ->title('SSO configuration enabled')
                            ->success()
                            ->send();
                    }),
                Action::make('disable')
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->visible(fn (SSOConfiguration $record) => $record->is_active)
                    ->requiresConfirmation()
                    ->modalHeading('Disable SSO Configuration')
                    ->modalDescription('Are you sure you want to disable this SSO configuration? Users will no longer be able to authenticate via this provider.')
                    ->action(function (SSOConfiguration $record) {
                        $record->update(['is_active' => false]);

                        Notification::make()
                            ->title('SSO configuration disabled')
                            ->success()
                            ->send();
                    }),
                DeleteAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete SSO Configuration')
                    ->modalDescription('Are you sure you want to delete this SSO configuration? This action cannot be undone.'),
            ]),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListSSOConfigurations::route('/'),
            'create' => CreateSSOConfiguration::route('/create'),
            'view' => ViewSSOConfiguration::route('/{record}'),
            'edit' => EditSSOConfiguration::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = Filament::auth()->user();

        if (! $user instanceof User) {
            return $query->whereRaw('1 = 0');
        }

        // Super admins can see all SSO configurations
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see SSO configurations from their organization's applications
        if ($user->organization_id) {
            $query->whereHas('application', function (Builder $q) use ($user) {
                $q->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->where('is_active', true)->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }
}
