<?php

namespace App\Filament\Resources;

use App\Filament\Resources\PermissionResource\Pages\CreatePermission;
use App\Filament\Resources\PermissionResource\Pages\EditPermission;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\PermissionResource\Pages\ViewPermission;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use UnitEnum;

class PermissionResource extends Resource
{
    protected static ?string $model = Permission::class;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-key';

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema
          ->schema([
            Section::make('Permission Information')
              ->schema([
                TextInput::make('name')
                  ->required()
                  ->unique(ignoreRecord: true)
                  ->maxLength(255)
                  ->helperText('Permission identifier (e.g., create-users, manage-applications)'),

                Select::make('guard_name')
                  ->options([
                    'web' => 'Web',
                    'api' => 'API',
                  ])
                  ->default('web')
                  ->required()
                  ->helperText('Authentication guard for this permission'),
              ])->columns(2),

            Section::make('Assignment')
              ->schema([
                Select::make('roles')
                  ->relationship('roles', 'name')
                  ->multiple()
                  ->preload()
                  ->searchable()
                  ->helperText('Roles that should have this permission'),
              ]),
          ]);
    }

    public static function table(Table $table): Table
    {
        return $table
          ->columns([
            TextColumn::make('name')
              ->searchable()
              ->sortable()
              ->weight('bold')
              ->badge()
              ->color('success'),

            TextColumn::make('guard_name')
              ->badge()
              ->color('gray')
              ->sortable(),

            TextColumn::make('category')
              ->label('Category')
              ->formatStateUsing(function ($record) {
                  $parts = explode(' ', $record->name);

                  return ucfirst($parts[1] ?? 'general');
              })
              ->badge()
              ->color('info'),

            TextColumn::make('roles_count')
              ->counts('roles')
              ->label('Roles')
              ->sortable()
              ->alignCenter(),

            TextColumn::make('users_count')
              ->counts('users')
              ->label('Direct Users')
              ->sortable()
              ->alignCenter(),

            TextColumn::make('roles.name')
              ->label('Assigned Roles')
              ->listWithLineBreaks()
              ->limitList(3)
              ->expandableLimitedList()
              ->badge()
              ->separator(','),

            TextColumn::make('created_at')
              ->dateTime()
              ->sortable()
              ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('updated_at')
              ->dateTime()
              ->sortable()
              ->toggleable(isToggledHiddenByDefault: true),
          ])
          ->filters([
            SelectFilter::make('guard_name')
              ->options([
                'web' => 'Web',
                'api' => 'API',
              ]),

            SelectFilter::make('category')
              ->options([
                'users' => 'User Management',
                'applications' => 'Application Management',
                'organizations' => 'Organization Management',
                'roles' => 'Role Management',
                'permissions' => 'Permission Management',
                'logs' => 'Log Management',
                'system' => 'System Administration',
              ])
              ->query(function (Builder $query, array $data): Builder {
                  return $query->when(
                    $data['value'],
                    fn(Builder $query, $category): Builder => $query->where('name', 'like', "%{$category}%"),
                  );
              }),

            Filter::make('has_roles')
              ->query(fn(Builder $query): Builder => $query->has('roles'))
              ->label('Assigned to Roles'),

            Filter::make('direct_user_permissions')
              ->query(fn(Builder $query): Builder => $query->has('users'))
              ->label('Direct User Permissions'),

            Filter::make('system_permissions')
              ->query(fn(Builder $query): Builder => $query->where('name', 'like', 'manage %')
                ->orWhere('name', 'like', 'create %')
                ->orWhere('name', 'like', 'delete %')
              )
              ->label('System Permissions'),
          ])
          ->actions([
            ActionGroup::make([
              ViewAction::make(),
              EditAction::make(),

              Action::make('assign_to_role')
                ->label('Assign to Role')
                ->icon('heroicon-o-plus')
                ->color('success')
                ->form([
                  Select::make('role')
                    ->relationship('roles', 'name')
                    ->required()
                    ->searchable()
                    ->preload(),
                ])
                ->action(function ($record, $data) {
                    $record->roles()->syncWithoutDetaching([$data['role']]);
                    Notification::make()
                      ->title('Permission assigned to role')
                      ->success()
                      ->send();
                }),

              DeleteAction::make()
                ->requiresConfirmation()
                ->modalDescription('Are you sure you want to delete this permission? This will remove it from all roles and users.')
                ->before(function ($record) {
                    if ($record->roles()->count() > 0 || $record->users()->count() > 0) {
                        Notification::make()
                          ->title('Warning: Permission in use')
                          ->body('This permission is assigned to roles or users.')
                          ->warning()
                          ->send();
                    }
                }),
            ]),
          ])
          ->toolbarActions([
            BulkActionGroup::make([
              DeleteBulkAction::make()
                ->requiresConfirmation()
                ->modalDescription('Are you sure you want to delete these permissions?'),

              BulkAction::make('assign_to_role')
                ->label('Assign to Role')
                ->icon('heroicon-o-user-group')
                ->color('success')
                ->form([
                  Select::make('role')
                    ->relationship('roles', 'name')
                    ->required()
                    ->searchable()
                    ->preload(),
                ])
                ->action(function ($records, $data) {
                    $role = Role::find($data['role']);
                    foreach ($records as $record) {
                        $role->permissions()->syncWithoutDetaching([$record->id]);
                    }
                    Notification::make()
                      ->title('Permissions assigned to role')
                      ->success()
                      ->send();
                }),
            ]),
          ])
          ->defaultSort('name');
    }

    public static function getPages(): array
    {
        return [
          'index' => ListPermissions::route('/'),
          'create' => CreatePermission::route('/create'),
          'view' => ViewPermission::route('/{record}'),
          'edit' => EditPermission::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getModel()::count();
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }
}