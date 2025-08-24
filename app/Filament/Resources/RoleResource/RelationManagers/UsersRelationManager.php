<?php

namespace App\Filament\Resources\RoleResource\RelationManagers;

use Filament\Actions\AttachAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DetachAction;
use Filament\Actions\DetachBulkAction;
use Filament\Forms;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;

class UsersRelationManager extends RelationManager
{
    protected static string $relationship = 'users';

    protected static ?string $recordTitleAttribute = 'name';

    public function form(Schema $schema): Schema
    {
        return $schema
          ->schema([
            Forms\Components\TextInput::make('name')
              ->required()
              ->maxLength(255),
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
              ->copyable(),

            Tables\Columns\IconColumn::make('email_verified_at')
              ->label('Verified')
              ->boolean()
              ->getStateUsing(fn($record) => !is_null($record->email_verified_at)),

            Tables\Columns\IconColumn::make('mfa_enabled')
              ->label('MFA')
              ->boolean()
              ->getStateUsing(fn($record) => $record->hasMfaEnabled()),

            Tables\Columns\TextColumn::make('created_at')
              ->dateTime()
              ->sortable(),
          ])
          ->filters([
              //
          ])
          ->headerActions([
            AttachAction::make()
              ->preloadRecordSelect(),
          ])
          ->actions([
            DetachAction::make(),
          ])
          ->bulkActions([
            BulkActionGroup::make([
              DetachBulkAction::make(),
            ]),
          ]);
    }
}