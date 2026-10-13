<?php

namespace App\Filament\Resources;

use App\Filament\Concerns\ScopesToOrganization;
use App\Filament\Resources\UserResource\Pages\CreateUser;
use App\Filament\Resources\UserResource\Pages\EditUser;
use App\Filament\Resources\UserResource\Pages\ListUsers;
use App\Filament\Resources\UserResource\Pages\ViewUser;
use App\Filament\Resources\UserResource\RelationManagers\ApplicationsRelationManager;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use BackedEnum;
use Closure;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\FileUpload;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\ImageColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Support\Facades\Hash;
use UnitEnum;

class UserResource extends Resource
{
    use ScopesToOrganization;

    protected static ?string $model = User::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'User Management';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('User Information')->schema([
                TextInput::make('name')->required()->maxLength(255),

                TextInput::make('email')->email()->required()->maxLength(255)->unique(ignoreRecord: true),

                TextInput::make('password')
                    ->password()
                    ->dehydrateStateUsing(fn ($state) => Hash::make($state))
                    ->dehydrated(fn ($state) => filled($state))
                    ->required(fn (string $context): bool => $context === 'create')
                    ->helperText('Leave blank to keep current password'),

                FileUpload::make('avatar')->image()->directory('avatars')->visibility('private')->helperText('Upload user profile picture'),

                DateTimePicker::make('email_verified_at')->label('Email Verified At')->helperText('Set to mark email as verified'),
            ])->columns(2),

            Section::make('Multi-Factor Authentication')->schema([
                CheckboxList::make('mfa_methods')->label('MFA Methods')->options([
                    'totp' => 'Time-based One-Time Password (TOTP)',
                    'sms' => 'SMS Verification',
                    'email' => 'Email Verification',
                    'backup_codes' => 'Backup Codes',
                ])->columns(2)->helperText('Select enabled MFA methods for this user'),

                DateTimePicker::make('two_factor_confirmed_at')
                    ->label('MFA Confirmed At')
                    ->helperText('When the user confirmed their MFA setup'),

                Textarea::make('two_factor_recovery_codes')
                    ->label('Recovery Codes')
                    ->rows(3)
                    ->formatStateUsing(fn (?User $record): string => implode("\n", $record?->mfa_backup_codes ?? []))
                    ->disabled()
                    ->dehydrated(false)
                    ->helperText('Auto-generated recovery codes (view only)'),
            ])->columns(2),

            Section::make('Profile & Settings')->schema([
                KeyValue::make('profile')
                    ->label('Profile Data')
                    ->keyLabel('Field')
                    ->valueLabel('Value')
                    ->default([])
                    ->helperText('Additional user profile information'),
            ]),

            Section::make('Roles & Permissions')->schema([
                Select::make('roles')
                    ->multiple()
                    ->searchable()
                    ->options(fn (?User $record): array => static::roleOptions($record))
                    ->afterStateHydrated(fn (Select $component, ?User $record) => $component->state(
                        $record ? app(UserRoleService::class)->assignedRoleIdsInOrganization($record, $record->organization_id)->all() : []
                    ))
                    ->disabled(fn (?User $record): bool => $record !== null && ! auth()->user()->isSuperAdmin() && auth()->user()->is($record))
                    ->rule(fn (?User $record) => function (string $attribute, mixed $value, Closure $fail) use ($record): void {
                        $denial = app(UserRoleService::class)->roleSyncDenial(
                            auth()->user(),
                            $record,
                            $record?->organization_id ?? auth()->user()->organization_id,
                            static::withRolesFromOtherOrganizations($record, $value)
                        );

                        if ($denial) {
                            $fail($denial);
                        }
                    })
                    ->saveRelationshipsUsing(fn (User $record, ?array $state) => app(UserRoleService::class)->syncRolesAs(
                        auth()->user(),
                        $record,
                        static::withRolesFromOtherOrganizations($record, $state)
                    ))
                    ->dehydrated(false)
                    ->helperText('Assign roles to this user'),

                Select::make('permissions')
                    ->visible(fn (): bool => (bool) auth()->user()?->isSuperAdmin())
                    ->relationship('permissions', 'name')
                    ->multiple()
                    ->preload()
                    ->searchable()
                    ->helperText('Direct permissions (in addition to role permissions)'),
            ])->columns(2),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            ImageColumn::make('avatar')->circular()->defaultImageUrl(url('/images/default-avatar.png')),

            TextColumn::make('name')->searchable()->sortable()->weight('bold'),

            TextColumn::make('email')->searchable()->sortable()->copyable()->copyMessage('Email copied'),

            IconColumn::make('email_verified_at')
                ->label('Verified')
                ->boolean()
                ->getStateUsing(fn ($record) => ! is_null($record->email_verified_at))
                ->sortable(),

            IconColumn::make('mfa_enabled')->label('MFA')->boolean()->getStateUsing(fn ($record) => $record->hasMfaEnabled())->sortable(),

            TextColumn::make('mfa_methods')->label('MFA Methods')->badge()->separator(',')->limit(2),

            TextColumn::make('roles.name')->label('Roles')->badge()->separator(',')->limit(2),

            TextColumn::make('applications_count')->counts('applications')->label('Apps')->sortable()->alignCenter(),

            TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            TernaryFilter::make('email_verified_at')
                ->label('Email Verified')
                ->nullable()
                ->trueLabel('Verified only')
                ->falseLabel('Unverified only')
                ->native(false),

            Filter::make('has_mfa')->query(fn (Builder $query): Builder => $query->whereNotNull('mfa_methods'))->label('MFA Enabled'),

            SelectFilter::make('roles')->relationship('roles', 'name')->multiple()->preload(),

            Filter::make('has_applications')->query(fn (Builder $query): Builder => $query->has('applications'))->label('Has Applications'),

            Filter::make('created_last_30_days')
                ->query(fn (Builder $query): Builder => $query->where('created_at', '>=', now()->subDays(30)))
                ->label('Created in Last 30 Days'),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),

                Action::make('reset_mfa')
                    ->authorize('resetCredentials')
                    ->label('Reset MFA')
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->modalDescription('This will disable MFA for the user. They will need to set it up again.')
                    ->action(function ($record) {
                        $record->update([
                            'mfa_methods' => null,
                            'two_factor_secret' => null,
                            'two_factor_recovery_codes' => null,
                            'two_factor_confirmed_at' => null,
                        ]);
                    })
                    ->after(fn () => Notification::make()->title('MFA has been reset successfully')->warning()->send())
                    ->visible(fn ($record) => $record->hasMfaEnabled()),

                Action::make('force_verify_email')
                    ->authorize('resetCredentials')
                    ->label('Verify Email')
                    ->icon('heroicon-o-check-badge')
                    ->color('success')
                    ->action(fn ($record) => $record->update(['email_verified_at' => now()]))
                    ->after(fn () => Notification::make()->title('Email verified successfully')->success()->send())
                    ->visible(fn ($record) => is_null($record->email_verified_at)),

                DeleteAction::make()->requiresConfirmation()->modalDescription('Are you sure you want to delete this user? This action cannot be undone.'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                DeleteBulkAction::make()->authorizeIndividualRecords('delete')->requiresConfirmation(),

                BulkAction::make('verify_emails')
                    ->authorizeIndividualRecords('resetCredentials')
                    ->label('Verify Emails')
                    ->icon('heroicon-o-check-badge')
                    ->color('success')
                    ->action(fn ($records) => $records->each(fn ($record) => $record->update(['email_verified_at' => now()])))
                    ->requiresConfirmation()
                    ->modalDescription('This will mark all selected users as email verified.'),

                BulkAction::make('reset_mfa')
                    ->authorizeIndividualRecords('resetCredentials')
                    ->label('Reset MFA')
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('warning')
                    ->action(fn ($records) => $records->each(fn ($record) => $record->update([
                        'mfa_methods' => null,
                        'two_factor_secret' => null,
                        'two_factor_recovery_codes' => null,
                        'two_factor_confirmed_at' => null,
                    ])))
                    ->requiresConfirmation()
                    ->modalDescription('This will disable MFA for all selected users.'),
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
            'index' => ListUsers::route('/'),
            'create' => CreateUser::route('/create'),
            'view' => ViewUser::route('/{record}'),
            'edit' => EditUser::route('/{record}/edit'),
        ];
    }

    /**
     * @return array<int, string>
     */
    private static function roleOptions(?User $record): array
    {
        $editor = auth()->user();
        $roleService = app(UserRoleService::class);

        $grantable = $editor->isSuperAdmin()
            ? Role::query()
                ->when($record !== null, fn (Builder $query) => $query->where(fn (Builder $scoped) => $scoped
                    ->whereNull('organization_id')
                    ->orWhere('organization_id', $record->organization_id)))
                ->get()
            : $roleService->manageableRoles($editor, $record?->organization_id ?? $editor->organization_id);
        $assigned = $record ? Role::whereKey($roleService->assignedRoleIdsInOrganization($record, $record->organization_id))->get() : new Collection;

        return $grantable->merge($assigned)->pluck('name', 'id')->all();
    }

    /**
     * @return SupportCollection<int, int>
     */
    private static function withRolesFromOtherOrganizations(?User $record, mixed $state): SupportCollection
    {
        $roleIds = collect($state)->map(fn ($id) => (int) $id);

        if ($record === null) {
            return $roleIds;
        }

        $roleService = app(UserRoleService::class);
        $otherOrganizationRoleIds = $roleService->assignedRoleIds($record)
            ->diff($roleService->assignedRoleIdsInOrganization($record, $record->organization_id));

        return $roleIds->merge($otherOrganizationRoleIds)->unique()->values();
    }

    public static function getEloquentQuery(): Builder
    {
        return static::scopeToOrganization(parent::getEloquentQuery());
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getEloquentQuery()->count();
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $count = static::getEloquentQuery()->count();

        return $count > 100 ? 'warning' : ($count > 50 ? 'success' : 'primary');
    }
}
