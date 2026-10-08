<?php

namespace App\Filament\Resources\RoleResource\RelationManagers;

use App\Filament\Concerns\ScopesToOrganization;
use Filament\Actions\AttachAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DetachAction;
use Filament\Actions\DetachBulkAction;
use Filament\Forms;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class UsersRelationManager extends RelationManager
{
    use ScopesToOrganization;

    protected static string $relationship = 'users';

    protected static ?string $recordTitleAttribute = 'name';

    /**
     * @throws \Throwable
     */
    public function form(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Forms\Components\TextInput::make('name')
                    ->required()
                    ->maxLength(255),
            ]);
    }

    /**
     * @throws \Throwable
     */
    public function table(Table $table): Table
    {
        return $table
            ->recordTitleAttribute('name')
            ->modifyQueryUsing(fn (Builder $query): Builder => static::scopeToOrganization($query))
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
                    ->getStateUsing(fn ($record) => ! is_null($record->email_verified_at)),

                Tables\Columns\IconColumn::make('mfa_enabled')
                    ->label('MFA')
                    ->boolean()
                    ->getStateUsing(fn ($record) => $record->hasMfaEnabled()),

                Tables\Columns\TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable(),
            ])
            ->filters([

            ])
            ->headerActions([
                AttachAction::make()->visible(fn (): bool => (bool) auth()->user()?->isSuperAdmin())
                    ->preloadRecordSelect()
                    ->recordSelectOptionsQuery(fn (Builder $query) => static::scopeToOrganization($query)),
            ])
            ->recordActions([
                DetachAction::make()->visible(fn (): bool => (bool) auth()->user()?->isSuperAdmin()),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DetachBulkAction::make()->visible(fn (): bool => (bool) auth()->user()?->isSuperAdmin()),
                ]),
            ]);
    }
}
