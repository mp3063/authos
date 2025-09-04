<?php

namespace App\Filament\Resources\Invitations\Schemas;

use App\Models\Organization;
use Filament\Schemas\Schema;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\DateTimePicker;
use Filament\Schemas\Components\Section;

class InvitationForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->components([
                Section::make('Invitation Details')
                    ->description('Send an invitation to join an organization')
                    ->schema([
                        Select::make('organization_id')
                            ->label('Organization')
                            ->options(Organization::query()->pluck('name', 'id'))
                            ->required()
                            ->searchable(),

                        TextInput::make('email')
                            ->label('Email Address')
                            ->email()
                            ->required()
                            ->maxLength(255),

                        Select::make('role')
                            ->label('Role')
                            ->options([
                                'user' => 'User',
                                'Organization Member' => 'Organization Member',
                                'User Manager' => 'User Manager',
                                'Application Manager' => 'Application Manager',
                                'Organization Admin' => 'Organization Admin',
                                'Organization Owner' => 'Organization Owner',
                            ])
                            ->default('user')
                            ->required(),

                        DateTimePicker::make('expires_at')
                            ->label('Expires At')
                            ->default(now()->addDays(7))
                            ->required(),
                    ])->columns(2),

                Section::make('Invitation Status')
                    ->description('Current status of the invitation')
                    ->schema([
                        DateTimePicker::make('accepted_at')
                            ->label('Accepted At')
                            ->disabled(),

                        Select::make('accepted_by')
                            ->label('Accepted By')
                            ->relationship('acceptor', 'name')
                            ->disabled(),
                    ])
                    ->columns(2)
                    ->visibleOn('edit'),
            ]);
    }
}
