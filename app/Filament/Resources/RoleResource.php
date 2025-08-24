<?php

namespace App\Filament\Resources;

use App\Filament\Resources\RoleResource\Pages\CreateRole;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\RoleResource\Pages\ViewRole;
use App\Filament\Resources\RoleResource\RelationManagers\PermissionsRelationManager;
use App\Filament\Resources\RoleResource\RelationManagers\UsersRelationManager;
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
use Spatie\Permission\Models\Role;
use UnitEnum;

class RoleResource extends Resource
{
    protected static ?string $model = Role::class;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-user-group';

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
          Section::make('Role Information')->schema([
            TextInput::make('name')
              ->required()
              ->unique(ignoreRecord: true)
              ->maxLength(255)
              ->helperText('Unique role identifier (e.g., super-admin, user-manager)'),

            Select::make('guard_name')->options([
              'web' => 'Web',
              'api' => 'API',
            ])->default('web')->required()->helperText('Authentication guard for this role'),
          ])->columns(2),

          Section::make('Permissions')->schema([
            CheckboxList::make('permissions')
              ->relationship('permissions', 'name')
              ->columns(3)
              ->gridDirection('row')
              ->bulkToggleable()
              ->searchable()
              ->helperText('Select permissions to assign to this role'),
          ]),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
          TextColumn::make('name')->searchable()->sortable()->weight('bold')->badge()->color('primary'),

          TextColumn::make('guard_name')->badge()->color('gray')->sortable(),

          TextColumn::make('permissions_count')->counts('permissions')->label('Permissions')->sortable()->alignCenter(),

          TextColumn::make('users_count')->counts('users')->label('Users')->sortable()->alignCenter(),

          TextColumn::make('permissions.name')
            ->label('Key Permissions')
            ->listWithLineBreaks()
            ->limitList(3)
            ->expandableLimitedList()
            ->badge()
            ->separator(','),

          TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

          TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
          SelectFilter::make('guard_name')->options([
            'web' => 'Web',
            'api' => 'API',
          ]),

          Filter::make('has_users')->query(fn(Builder $query): Builder => $query->has('users'))->label('Has Users'),

          Filter::make('system_roles')->query(fn(Builder $query): Builder => $query->whereIn('name', [
            'Super Admin',
            'Organization Admin',
            'Application Admin',
          ]))->label('System Roles'),
        ])->recordActions([
          ActionGroup::make([
            ViewAction::make(),
            EditAction::make(),

            Action::make('duplicate')->label('Duplicate Role')->icon('heroicon-o-squares-plus')->color('gray')->form([
              TextInput::make('name')->required()->placeholder('New role name')->helperText('Enter name for the duplicated role'),
            ])->action(function ($record, $data) {
                $newRole = $record->replicate();
                $newRole->name = $data['name'];
                $newRole->save();
                $newRole->permissions()->sync($record->permissions);

                Notification::make()
                  ->title('Role duplicated successfully')
                  ->body("Created new role '{$data['name']}' with same permissions")
                  ->success()
                  ->send();
            }),

            DeleteAction::make()
              ->requiresConfirmation()
              ->modalDescription('Are you sure you want to delete this role? Users with this role will lose associated permissions.')
              ->before(function ($record) {
                  if ($record->users()->count() > 0) {
                      Notification::make()
                        ->title('Cannot delete role')
                        ->body('This role is assigned to users. Remove users first.')
                        ->danger()
                        ->send();

                      return false;
                  }
              }),
          ]),
        ])->bulkActions([
          BulkActionGroup::make([
            DeleteBulkAction::make()->requiresConfirmation()->modalDescription('Are you sure you want to delete these roles?'),

            BulkAction::make('assign_permission')
              ->label('Assign Permission')
              ->icon('heroicon-o-plus')
              ->color('success')
              ->schema([
                Select::make('permission')->relationship('permissions', 'name')->required()->searchable()->preload(),
              ])->action(function ($records, $data) {
                  foreach ($records as $record) {
                      $record->permissions()->syncWithoutDetaching([$data['permission']]);
                  }
                  Notification::make()->title('Permission assigned to selected roles')->success()->send();
              }),
          ]),
        ])->defaultSort('name');
    }

    public static function getRelations(): array
    {
        return [
          UsersRelationManager::class,
          PermissionsRelationManager::class,
        ];
    }

    public static function getPages(): array
    {
        return [
          'index' => ListRoles::route('/'),
          'create' => CreateRole::route('/create'),
          'view' => ViewRole::route('/{record}'),
          'edit' => EditRole::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getModel()::count();
    }
}