<?php

namespace App\Filament\Resources\OrganizationResource\RelationManagers;

use Filament\Actions\BulkActionGroup;
use Filament\Actions\CreateAction;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Forms;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;

class ApplicationsRelationManager extends RelationManager
{
    protected static string $relationship = 'applications';

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

                Forms\Components\TagsInput::make('redirect_uris')
                    ->placeholder('https://example.com/callback')
                    ->helperText('Enter valid redirect URIs for OAuth flows'),

                Forms\Components\TagsInput::make('allowed_origins')
                    ->placeholder('https://example.com')
                    ->helperText('CORS allowed origins'),

                Forms\Components\Select::make('allowed_grant_types')
                    ->multiple()
                    ->options([
                        'authorization_code' => 'Authorization Code',
                        'client_credentials' => 'Client Credentials',
                        'refresh_token' => 'Refresh Token',
                        'password' => 'Password Grant',
                    ])
                    ->default(['authorization_code', 'refresh_token']),

                Forms\Components\TextInput::make('webhook_url')
                    ->url()
                    ->maxLength(255)
                    ->helperText('URL for authentication webhooks'),

                Forms\Components\Toggle::make('is_active')
                    ->default(true),
            ]);
    }

    /**
     * @throws \Throwable
     */
    public function table(Table $table): Table
    {
        return $table
            ->recordTitleAttribute('name')
            ->columns([
                Tables\Columns\TextColumn::make('name')
                    ->searchable()
                    ->sortable()
                    ->weight('bold'),

                Tables\Columns\TextColumn::make('client_id')
                    ->copyable()
                    ->copyMessage('Client ID copied')
                    ->limit(20)
                    ->tooltip(fn ($record) => $record->client_id),

                Tables\Columns\IconColumn::make('is_active')
                    ->boolean()
                    ->sortable()
                    ->label('Status'),

                Tables\Columns\TextColumn::make('users_count')
                    ->counts('users')
                    ->label('Users')
                    ->sortable()
                    ->alignCenter(),

                Tables\Columns\TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                Tables\Filters\TernaryFilter::make('is_active')
                    ->label('Status')
                    ->boolean()
                    ->trueLabel('Active only')
                    ->falseLabel('Inactive only')
                    ->native(false),
            ])
            ->headerActions([
                CreateAction::make(),
            ])
            ->recordActions([
                EditAction::make(),
                DeleteAction::make(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make(),
                ]),
            ])
            ->defaultSort('created_at', 'desc');
    }
}
