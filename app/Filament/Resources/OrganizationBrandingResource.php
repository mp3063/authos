<?php

namespace App\Filament\Resources;

use App\Filament\Resources\OrganizationBrandingResource\Pages\CreateOrganizationBranding;
use App\Filament\Resources\OrganizationBrandingResource\Pages\EditOrganizationBranding;
use App\Filament\Resources\OrganizationBrandingResource\Pages\ListOrganizationBrandings;
use App\Filament\Resources\OrganizationBrandingResource\Pages\ViewOrganizationBranding;
use App\Models\OrganizationBranding;
use App\Models\User;
use BackedEnum;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\ColorPicker;
use Filament\Forms\Components\FileUpload;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\ImageColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class OrganizationBrandingResource extends Resource
{
    protected static ?string $model = OrganizationBranding::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 3;

    protected static ?string $recordTitleAttribute = 'organization.name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            // Branding
            Section::make('Branding')->schema([
                Select::make('organization_id')
                    ->label('Organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload()
                    ->required()
                    ->disabled(fn ($context) => $context === 'edit')
                    ->helperText('Organization this branding belongs to'),

                FileUpload::make('logo_path')
                    ->label('Logo')
                    ->image()
                    ->directory('branding/logos')
                    ->maxSize(2048)
                    ->helperText('Upload an organization logo (max 2MB)'),

                FileUpload::make('login_background_path')
                    ->label('Login Background')
                    ->image()
                    ->directory('branding/backgrounds')
                    ->maxSize(5120)
                    ->helperText('Upload a login page background image (max 5MB)'),
            ])->columns(2),

            // Colors
            Section::make('Colors')->schema([
                ColorPicker::make('primary_color')
                    ->label('Primary Color')
                    ->helperText('Main brand color used for buttons, links, and accents'),

                ColorPicker::make('secondary_color')
                    ->label('Secondary Color')
                    ->helperText('Secondary brand color used for highlights and backgrounds'),
            ])->columns(2),

            // Custom CSS
            Section::make('Custom CSS')->schema([
                Textarea::make('custom_css')
                    ->label('Custom CSS')
                    ->rows(10)
                    ->helperText('Allowed CSS properties only. Scripts, @import, javascript:, expression(), and event handlers are automatically stripped for security.')
                    ->columnSpanFull(),
            ]),

            // Email Templates
            Section::make('Email Templates')->schema([
                KeyValue::make('email_templates')
                    ->label('Email Templates')
                    ->keyLabel('Template Name')
                    ->valueLabel('Template Content')
                    ->helperText('Custom email template overrides (e.g., welcome, password_reset, invitation)')
                    ->columnSpanFull(),
            ]),

            // Additional Settings
            Section::make('Additional Settings')->schema([
                KeyValue::make('settings')
                    ->label('Settings')
                    ->keyLabel('Setting Key')
                    ->valueLabel('Setting Value')
                    ->helperText('Additional branding settings (e.g., accent_color, custom_html, favicon_path)')
                    ->columnSpanFull(),
            ])->collapsible(),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('organization.name')
                ->label('Organization')
                ->searchable()
                ->sortable()
                ->weight('bold'),

            TextColumn::make('primary_color')
                ->label('Primary Color')
                ->formatStateUsing(fn (?string $state): string => $state
                    ? "\u{25CF} {$state}"
                    : 'Not set')
                ->color(fn (?string $state): ?string => $state ? $state : null)
                ->badge(),

            TextColumn::make('secondary_color')
                ->label('Secondary Color')
                ->formatStateUsing(fn (?string $state): string => $state
                    ? "\u{25CF} {$state}"
                    : 'Not set')
                ->color(fn (?string $state): ?string => $state ? $state : null)
                ->badge(),

            ImageColumn::make('logo_path')
                ->label('Logo')
                ->disk('public')
                ->circular()
                ->defaultImageUrl(fn () => null),

            TextColumn::make('created_at')
                ->label('Created')
                ->dateTime()
                ->sortable()
                ->toggleable(),

            TextColumn::make('updated_at')
                ->label('Updated')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('organization')
                ->relationship('organization', 'name')
                ->searchable()
                ->preload()
                ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),
        ])->recordActions([
            ViewAction::make(),
            EditAction::make(),
            DeleteAction::make()
                ->requiresConfirmation()
                ->modalHeading('Delete Branding')
                ->modalDescription('Are you sure you want to delete this organization branding? This action cannot be undone.'),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListOrganizationBrandings::route('/'),
            'create' => CreateOrganizationBranding::route('/create'),
            'view' => ViewOrganizationBranding::route('/{record}'),
            'edit' => EditOrganizationBranding::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = Filament::auth()->user();

        if (! $user instanceof User) {
            return $query->whereRaw('1 = 0');
        }

        // Super admins can see all branding records
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see branding from their organization
        if ($user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'info';
    }
}
