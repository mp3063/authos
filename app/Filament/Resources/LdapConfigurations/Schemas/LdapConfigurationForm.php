<?php

namespace App\Filament\Resources\LdapConfigurations\Schemas;

use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Infolists\Components\TextEntry;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class LdapConfigurationForm
{
    /**
     * @throws \Throwable
     */
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Basic Information')->schema([
                    Grid::make()->schema([
                        Select::make('organization_id')
                            ->relationship('organization', 'name')
                            ->required()
                            ->searchable()
                            ->preload()
                            ->disabled(fn ($context) => $context === 'edit')
                            ->helperText('Organization cannot be changed after creation'),

                        TextInput::make('name')
                            ->required()
                            ->maxLength(255)
                            ->placeholder('My LDAP Server')
                            ->helperText('Friendly name for this configuration'),
                    ]),
                ]),

                Section::make('Connection Settings')->schema([
                    Grid::make()->schema([
                        TextInput::make('host')
                            ->required()
                            ->maxLength(255)
                            ->placeholder('ldap.example.com')
                            ->helperText('LDAP server hostname or IP address'),

                        TextInput::make('port')
                            ->numeric()
                            ->default(389)
                            ->required()
                            ->helperText('Default: 389 (LDAP), 636 (LDAPS)'),

                        Toggle::make('use_ssl')
                            ->label('Use SSL/TLS')
                            ->default(false)
                            ->helperText('Enable for secure LDAPS connections'),

                        Toggle::make('use_tls')
                            ->label('Use STARTTLS')
                            ->default(false)
                            ->helperText('Enable STARTTLS after initial connection'),
                    ]),

                    Grid::make()->schema([
                        TextInput::make('base_dn')
                            ->required()
                            ->maxLength(255)
                            ->placeholder('dc=example,dc=com')
                            ->helperText('Base Distinguished Name for LDAP searches'),
                    ]),
                ]),

                Section::make('Authentication')->schema([
                    Grid::make()->schema([
                        TextInput::make('username')
                            ->label('Bind DN')
                            ->required()
                            ->maxLength(255)
                            ->placeholder('cn=admin,dc=example,dc=com')
                            ->helperText('Distinguished Name for binding to LDAP server'),

                        TextInput::make('password')
                            ->label('Bind Password')
                            ->password()
                            ->required()
                            ->dehydrateStateUsing(fn ($state) => $state)
                            ->helperText('Password will be encrypted automatically'),
                    ]),
                ]),

                Section::make('User Synchronization')->schema([
                    Grid::make()->schema([
                        TextInput::make('user_filter')
                            ->placeholder('(objectClass=person)')
                            ->maxLength(255)
                            ->helperText('LDAP filter for finding users'),

                        TextInput::make('user_attribute')
                            ->default('uid')
                            ->required()
                            ->maxLength(255)
                            ->helperText('Attribute to use as username'),

                        Toggle::make('is_active')
                            ->label('Enable Configuration')
                            ->default(true)
                            ->helperText('Disable to prevent authentication via this LDAP server'),

                        TextEntry::make('last_sync_info')
                            ->label('Last Synchronization')
                            ->formatStateUsing(fn ($record) => $record?->last_sync_at
                                ? $record->last_sync_at->diffForHumans()
                                : 'Never synchronized')
                            ->visible(fn ($context) => $context === 'edit'),
                    ]),
                ]),

                Section::make('Attribute Mapping')
                    ->description('Map LDAP attributes to user fields. These control how LDAP data maps to local user records.')
                    ->schema([
                        KeyValue::make('sync_settings.attribute_mapping')
                            ->label('LDAP Attribute → User Field')
                            ->keyLabel('LDAP Attribute')
                            ->valueLabel('User Field')
                            ->default([
                                'mail' => 'email',
                                'displayName' => 'name',
                                'cn' => 'name_fallback',
                                'givenName' => 'first_name',
                                'sn' => 'last_name',
                                'userPrincipalName' => 'email_fallback',
                            ])
                            ->helperText('Map LDAP attributes to application user fields')
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(),

                Section::make('Group-to-Role Mapping')
                    ->description('Map LDAP groups to application roles. Users in these LDAP groups will automatically receive the corresponding role.')
                    ->schema([
                        KeyValue::make('sync_settings.group_role_mapping')
                            ->label('LDAP Group DN → Application Role')
                            ->keyLabel('LDAP Group DN')
                            ->valueLabel('Role Name')
                            ->default([])
                            ->helperText('Example: cn=admins,ou=groups,dc=example,dc=com → Organization Admin')
                            ->columnSpanFull(),
                        TextInput::make('sync_settings.group_attribute')
                            ->label('Group Membership Attribute')
                            ->default('memberOf')
                            ->helperText('LDAP attribute that contains group membership'),
                    ])
                    ->collapsible()
                    ->collapsed(),

                Section::make('Sync Schedule')
                    ->description('Configure automatic LDAP synchronization schedule.')
                    ->schema([
                        Grid::make()->schema([
                            Toggle::make('sync_settings.auto_sync_enabled')
                                ->label('Enable Automatic Sync')
                                ->default(false)
                                ->live()
                                ->helperText('When enabled, users will be synced from LDAP on a schedule'),
                            Select::make('sync_settings.sync_frequency')
                                ->label('Sync Frequency')
                                ->options([
                                    'hourly' => 'Every Hour',
                                    'every_6_hours' => 'Every 6 Hours',
                                    'every_12_hours' => 'Every 12 Hours',
                                    'daily' => 'Daily',
                                    'weekly' => 'Weekly',
                                ])
                                ->default('daily')
                                ->visible(fn ($get) => $get('sync_settings.auto_sync_enabled'))
                                ->helperText('How often to synchronize users from LDAP'),
                        ]),
                    ])
                    ->collapsible()
                    ->collapsed(),
            ]);
    }
}
