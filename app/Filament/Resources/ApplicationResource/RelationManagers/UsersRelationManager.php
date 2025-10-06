<?php

namespace App\Filament\Resources\ApplicationResource\RelationManagers;

use Filament\Forms;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class UsersRelationManager extends RelationManager
{
    protected static string $relationship = 'users';

    protected static ?string $recordTitleAttribute = 'name';

    public function form(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Forms\Components\Select::make('user_id')
                    ->label('User')
                    ->relationship('', 'name')
                    ->searchable()
                    ->preload()
                    ->required(),

                Forms\Components\KeyValue::make('metadata')
                    ->label('User Metadata')
                    ->keyLabel('Key')
                    ->valueLabel('Value')
                    ->default([])
                    ->helperText('Additional metadata for this user-application relationship'),
            ]);
    }

    public function table(Table $table): Table
    {
        return $table
            ->recordTitleAttribute('name')
            ->columns([
                Tables\Columns\TextColumn::make('name')
                    ->searchable()
                    ->sortable()
                    ->weight('bold'),

                Tables\Columns\TextColumn::make('email')
                    ->searchable()
                    ->sortable()
                    ->copyable()
                    ->copyMessage('Email copied'),

                Tables\Columns\TextColumn::make('pivot.login_count')
                    ->label('Logins')
                    ->alignCenter()
                    ->default(0)
                    ->numeric(),

                Tables\Columns\TextColumn::make('pivot.last_login_at')
                    ->label('Last Login')
                    ->dateTime()
                    ->sortable()
                    ->placeholder('Never'),

                Tables\Columns\TextColumn::make('pivot.created_at')
                    ->label('Connected')
                    ->dateTime()
                    ->sortable(),

                Tables\Columns\IconColumn::make('hasMfaEnabled')
                    ->label('MFA')
                    ->boolean()
                    ->getStateUsing(fn ($record) => $record->hasMfaEnabled()),
            ])
            ->filters([
                Tables\Filters\Filter::make('has_logged_in')
                    ->query(
                        fn (Builder $query): Builder => $query->whereNotNull('user_applications.last_login_at')
                    )
                    ->label('Has Logged In'),

                Tables\Filters\Filter::make('has_mfa')
                    ->query(
                        fn (Builder $query): Builder => $query->whereNotNull('mfa_methods')
                    )
                    ->label('MFA Enabled'),
            ])
            ->defaultSort('user_applications.created_at', 'desc');
    }
}
