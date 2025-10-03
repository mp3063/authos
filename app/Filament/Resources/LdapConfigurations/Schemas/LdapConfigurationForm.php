<?php

namespace App\Filament\Resources\LdapConfigurations\Schemas;

use Filament\Forms\Components\Placeholder;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class LdapConfigurationForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Basic Information')->schema([
                    Grid::make(2)->schema([
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
                    Grid::make(2)->schema([
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

                    Grid::make(1)->schema([
                        TextInput::make('base_dn')
                            ->required()
                            ->maxLength(255)
                            ->placeholder('dc=example,dc=com')
                            ->helperText('Base Distinguished Name for LDAP searches'),
                    ]),
                ]),

                Section::make('Authentication')->schema([
                    Grid::make(2)->schema([
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
                    Grid::make(2)->schema([
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

                        Placeholder::make('last_sync_info')
                            ->label('Last Synchronization')
                            ->content(fn ($record) => $record?->last_sync_at
                                ? $record->last_sync_at->diffForHumans()
                                : 'Never synchronized')
                            ->visible(fn ($context) => $context === 'edit'),
                    ]),
                ]),
            ]);
    }
}
