<?php

namespace App\Filament\Resources\LdapConfigurations;

use App\Filament\Resources\LdapConfigurations\Pages\CreateLdapConfiguration;
use App\Filament\Resources\LdapConfigurations\Pages\EditLdapConfiguration;
use App\Filament\Resources\LdapConfigurations\Pages\ListLdapConfigurations;
use App\Filament\Resources\LdapConfigurations\Schemas\LdapConfigurationForm;
use App\Filament\Resources\LdapConfigurations\Tables\LdapConfigurationsTable;
use App\Models\LdapConfiguration;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class LdapConfigurationResource extends Resource
{
    protected static ?string $model = LdapConfiguration::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedRectangleStack;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    protected static ?string $navigationLabel = 'LDAP Configurations';

    protected static ?string $modelLabel = 'LDAP Configuration';

    protected static ?string $pluralModelLabel = 'LDAP Configurations';

    public static function form(Schema $schema): Schema
    {
        return LdapConfigurationForm::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return LdapConfigurationsTable::configure($table);
    }

    public static function getRelations(): array
    {
        return [
            //
        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListLdapConfigurations::route('/'),
            'create' => CreateLdapConfiguration::route('/create'),
            'edit' => EditLdapConfiguration::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = \Filament\Facades\Filament::auth()->user();

        // Super admins can see all LDAP configurations
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see their organization's configurations
        if ($user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        return static::getEloquentQuery()->count();
    }
}
