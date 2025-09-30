<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ApplicationResource\Pages\CreateApplication;
use App\Filament\Resources\ApplicationResource\Pages\EditApplication;
use App\Filament\Resources\ApplicationResource\Pages\ListApplications;
use App\Filament\Resources\ApplicationResource\Pages\ViewApplication;
use App\Filament\Resources\ApplicationResource\RelationManagers\UsersRelationManager;
use App\Models\Application;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use UnitEnum;

class ApplicationResource extends Resource
{
    protected static ?string $model = Application::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'OAuth Management';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            // Row 1: OAuth Configuration - Full Width
            Section::make('OAuth Configuration')->schema([
                TextInput::make('client_id')
                    ->label('Client ID')
                    ->copyable(copyMessage: 'Copied Client ID!', copyMessageDuration: 3000)
                    ->maxLength(255)
                    ->disabled()
                    ->dehydrated(false)
                    ->helperText('Auto-generated UUID for OAuth identification'),

                TextInput::make('client_secret')
                    ->label('Client Secret')
                    ->password()
                    ->revealable()
                    ->copyable(copyMessage: 'Copied Client Secret!', copyMessageDuration: 3000)
                    ->disabled()
                    ->dehydrated(false)
                    ->helperText('Auto-generated secure secret for OAuth flows'),

                TagsInput::make('redirect_uris')
                    ->label('Redirect URIs')
                    ->placeholder('https://example.com/callback')
                    ->required()
                    ->helperText('Valid redirect URIs for OAuth authorization flows'),

                TagsInput::make('allowed_origins')
                    ->label('Allowed Origins')
                    ->placeholder('https://example.com')
                    ->helperText('CORS allowed origins for API requests'),

                CheckboxList::make('allowed_grant_types')
                    ->label('Allowed Grant Types')
                    ->options([
                        'authorization_code' => 'Authorization Code',
                        'client_credentials' => 'Client Credentials',
                        'refresh_token' => 'Refresh Token',
                        'password' => 'Password Grant (Legacy)',
                    ])
                    ->default(['authorization_code', 'refresh_token'])
                    ->required()
                    ->columns(2)
                    ->helperText('OAuth 2.0 grant types allowed for this application'),
            ])->columnSpanFull(), // Force full width

            // Row 2: Application Details (left) and Webhook & Settings (right)
            Section::make('Application Details')->schema([
                Select::make('organization_id')
                    ->label('Organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload()
                    ->required()
                    ->createOptionForm([
                        TextInput::make('name')->required(),
                        TextInput::make('slug')->required(),
                    ]),

                TextInput::make('name')->required()->maxLength(255)->helperText('Display name for this application'),

                Toggle::make('is_active')->default(true)->helperText('Inactive applications cannot authenticate users'),
            ])->columnSpan(1),

            Section::make('Webhook & Settings')->schema([
                TextInput::make('webhook_url')
                    ->label('Webhook URL')
                    ->url()
                    ->maxLength(255)
                    ->helperText('Optional webhook endpoint for authentication events'),

                KeyValue::make('settings')->label('Application Settings')->keyLabel('Setting')->valueLabel('Value')->default([
                    'token_lifetime' => 3600,
                    'refresh_token_lifetime' => 2592000,
                    'require_pkce' => true,
                    'allowed_scopes' => ['openid', 'profile', 'email'],
                ])->helperText('Application-specific OAuth and security settings'),
            ])->columnSpan(1),
        ])->columns(2);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')->searchable()->sortable()->weight('bold'),

            TextColumn::make('organization.name')->label('Organization')->searchable()->sortable()->badge(),

            TextColumn::make('client_id')
                ->label('Client ID')
                ->copyable()
                ->copyMessage('Client ID copied')
                ->limit(20)
                ->tooltip(fn ($record) => $record->client_id),

            IconColumn::make('is_active')->boolean()->sortable()->label('Status'),

            TextColumn::make('users_count')->counts('users')->label('Users')->sortable()->alignCenter(),

            TextColumn::make('allowed_grant_types')->label('Grant Types')->badge(),

            TextColumn::make('webhook_url')
                ->label('Webhook')
                ->formatStateUsing(fn ($state) => $state ? 'Configured' : 'None')
                ->badge()
                ->color(fn ($state) => $state ? 'success' : 'gray'),

            TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('organization')->relationship('organization', 'name')->searchable()->preload(),

            TernaryFilter::make('is_active')->label('Status')->boolean()->trueLabel('Active only')->falseLabel('Inactive only')->native(false),

            Filter::make('has_webhook')->query(fn (Builder $query): Builder => $query->whereNotNull('webhook_url'))->label('Has Webhook'),

            Filter::make('authorization_code_grant')
                ->query(fn (Builder $query): Builder => $query->whereJsonContains('allowed_grant_types', 'authorization_code'))
                ->label('Authorization Code Grant'),
        ])->actions([
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),
                Action::make('regenerate_secret')
                    ->icon('heroicon-o-key')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->modalHeading('Regenerate Client Secret')
                    ->modalDescription('Are you sure you want to regenerate the client secret? This will invalidate all existing tokens.')
                    ->action(function (Application $record) {
                        $record->client_secret = Str::random(40);
                        $record->save();
                    })
                    ->successNotificationTitle('Client secret regenerated successfully'),
                Action::make('copy_credentials')
                    ->icon('heroicon-o-clipboard-document')
                    ->color('info')
                    ->modalHeading('Application Credentials')
                    ->modalContent(fn (Application $record) => view('filament.modals.application-credentials', compact('record')))
                    ->modalSubmitAction(false)
                    ->modalCancelActionLabel('Close'),
                DeleteAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Application')
                    ->modalDescription('Are you sure you want to delete this application? All associated tokens will be revoked.'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                DeleteBulkAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Applications')
                    ->modalDescription('Are you sure you want to delete these applications? All associated tokens will be revoked.'),
                BulkAction::make('activate')->icon('heroicon-o-check-circle')->color('success')->action(function ($records) {
                    $records->each(fn ($record) => $record->update(['is_active' => true]));
                })->deselectRecordsAfterCompletion()->successNotificationTitle('Applications activated successfully'),
                BulkAction::make('deactivate')->icon('heroicon-o-x-circle')->color('danger')->requiresConfirmation()->action(function ($records) {
                    $records->each(fn ($record) => $record->update(['is_active' => false]));
                })->deselectRecordsAfterCompletion()->successNotificationTitle('Applications deactivated successfully'),
            ]),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [
            UsersRelationManager::class,
        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListApplications::route('/'),
            'create' => CreateApplication::route('/create'),
            'view' => ViewApplication::route('/{record}'),
            'edit' => EditApplication::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = \Filament\Facades\Filament::auth()->user();

        // Super admins can see all applications
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see applications from their organization
        if ($user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getEloquentQuery()->count();
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return static::getEloquentQuery()->count() > 20 ? 'warning' : 'primary';
    }
}
