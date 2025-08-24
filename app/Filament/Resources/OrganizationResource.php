<?php

namespace App\Filament\Resources;

use App\Filament\Resources\OrganizationResource\Pages\CreateOrganization;
use App\Filament\Resources\OrganizationResource\Pages\EditOrganization;
use App\Filament\Resources\OrganizationResource\Pages\ListOrganizations;
use App\Filament\Resources\OrganizationResource\Pages\ViewOrganization;
use App\Filament\Resources\OrganizationResource\RelationManagers\ApplicationsRelationManager;
use App\Models\Organization;
use BackedEnum;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use UnitEnum;

class OrganizationResource extends Resource
{
    protected static ?string $model = Organization::class;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-building-office';

    protected static string|UnitEnum|null $navigationGroup = 'User Management';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
          Section::make('Organization Details')->schema([
            TextInput::make('name')
              ->required()
              ->maxLength(255)
              ->live(onBlur: true)
              ->afterStateUpdated(function (string $context, $state, $set) {
                  if ($context === 'create') {
                      $set('slug', Str::slug($state));
                  }
              }),

            TextInput::make('slug')
              ->required()
              ->maxLength(255)
              ->unique(ignoreRecord: true)
              ->alphaDash()
              ->helperText('Used for API identification and URLs'),

            Toggle::make('is_active')->default(true)->helperText('Inactive organizations cannot authenticate users'),
          ])->columns(2),

          Section::make('Security Settings')->schema([
            KeyValue::make('settings')->keyLabel('Setting')->valueLabel('Value')->default([
              'require_mfa' => false,
              'password_policy' => [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_special_chars' => false,
              ],
              'session_timeout' => 3600,
              'max_login_attempts' => 5,
              'lockout_duration' => 900,
            ])->helperText('Organization-specific security policies and configurations'),
          ]),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
          TextColumn::make('name')->searchable()->sortable()->weight('bold'),

          TextColumn::make('slug')->searchable()->sortable()->copyable()->copyMessage('Slug copied')->color('gray'),

          IconColumn::make('is_active')->boolean()->sortable()->label('Status'),

          TextColumn::make('applications_count')->counts('applications')->label('Apps')->sortable()->alignCenter(),

          TextColumn::make('settings.require_mfa')
            ->label('MFA Required')
            ->formatStateUsing(fn($state) => $state ? 'Yes' : 'No')
            ->badge()
            ->color(fn($state) => $state ? 'success' : 'gray'),

          TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

          TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ])->filters(filters: [
          TernaryFilter::make('is_active')->label('Status')->boolean()->trueLabel('Active only')
            ->falseLabel('Inactive only')->native(false),

          Filter::make('has_applications')->query(fn(Builder $query): Builder => $query->has('applications'))->label('Has Applications'),

          Filter::make('requires_mfa')
            ->query(fn(Builder $query): Builder => $query->whereJsonContains('settings->require_mfa', true))
            ->label('Requires MFA'),
        ])->recordActions([
          ViewAction::make(),
          EditAction::make(),
          DeleteAction::make()
            ->requiresConfirmation()
            ->modalDescription('Are you sure you want to delete this organization? This will also remove all associated applications and user access.'),
        ])->toolbarActions([
          BulkActionGroup::make([
            BulkAction::make('delete')
              ->label('Delete Selected')
              ->requiresConfirmation()
              ->action(fn($records) => $records->each->delete())
              ->successNotificationTitle('Organizations deleted'),

            BulkAction::make('toggle_status')
              ->label('Toggle Status')
              ->icon('heroicon-o-arrow-path')
              ->action(fn($records) => $records->each(fn($record) => $record->update(['is_active' => !$record->is_active])))
              ->requiresConfirmation()
              ->modalDescription('This will toggle the active status for selected organizations.')
              ->successNotificationTitle('Organization status updated'),
          ]),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [
          ApplicationsRelationManager::class,
        ];
    }

    public static function getPages(): array
    {
        return [
          'index' => ListOrganizations::route('/'),
          'create' => CreateOrganization::route('/create'),
          'view' => ViewOrganization::route('/{record}'),
          'edit' => EditOrganization::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getModel()::count();
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return static::getModel()::count() > 10 ? 'warning' : 'primary';
    }
}