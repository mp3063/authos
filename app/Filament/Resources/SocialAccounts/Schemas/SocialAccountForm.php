<?php

namespace App\Filament\Resources\SocialAccounts\Schemas;

use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\Section;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Schema;

class SocialAccountForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->components([
                Section::make('Account Information')
                    ->schema([
                        Select::make('user_id')
                            ->label('User')
                            ->relationship('user', 'name')
                            ->searchable()
                            ->preload()
                            ->required()
                            ->columnSpanFull(),

                        Select::make('provider')
                            ->label('Provider')
                            ->options([
                                'google' => 'Google',
                                'github' => 'GitHub',
                                'facebook' => 'Facebook',
                                'twitter' => 'Twitter',
                                'linkedin' => 'LinkedIn',
                            ])
                            ->required(),

                        TextInput::make('provider_id')
                            ->label('Provider User ID')
                            ->required()
                            ->maxLength(255),

                        TextInput::make('email')
                            ->label('Provider Email')
                            ->email()
                            ->maxLength(255),

                        TextInput::make('name')
                            ->label('Provider Name')
                            ->maxLength(255),

                        TextInput::make('avatar')
                            ->label('Avatar URL')
                            ->url()
                            ->maxLength(255),
                    ])
                    ->columns(2),

                Section::make('Token Information')
                    ->schema([
                        DateTimePicker::make('token_expires_at')
                            ->label('Token Expiration')
                            ->native(false),

                        Textarea::make('provider_data')
                            ->label('Additional Provider Data (JSON)')
                            ->rows(5)
                            ->columnSpanFull(),
                    ])
                    ->columns(2),
            ]);
    }
}
