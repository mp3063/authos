<?php

namespace App\Filament\Resources\CustomDomains;

use App\Filament\Concerns\ScopesToOrganization;
use App\Filament\Resources\CustomDomains\Pages\CreateCustomDomain;
use App\Filament\Resources\CustomDomains\Pages\EditCustomDomain;
use App\Filament\Resources\CustomDomains\Pages\ListCustomDomains;
use App\Filament\Resources\CustomDomains\Schemas\CustomDomainForm;
use App\Filament\Resources\CustomDomains\Tables\CustomDomainsTable;
use App\Models\CustomDomain;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class CustomDomainResource extends Resource
{
    use ScopesToOrganization;

    protected static ?string $model = CustomDomain::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'domain';

    protected static ?string $navigationLabel = 'Custom Domains';

    protected static ?string $modelLabel = 'Custom Domain';

    protected static ?string $pluralModelLabel = 'Custom Domains';

    public static function form(Schema $schema): Schema
    {
        return CustomDomainForm::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return CustomDomainsTable::configure($table);
    }

    public static function getRelations(): array
    {
        return [

        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListCustomDomains::route('/'),
            'create' => CreateCustomDomain::route('/create'),
            'edit' => EditCustomDomain::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        return static::scopeToOrganization(parent::getEloquentQuery());
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $verifiedCount = static::getEloquentQuery()->whereNotNull('verified_at')->count();
        $totalCount = static::getEloquentQuery()->count();

        if ($totalCount === 0) {
            return null;
        }

        return $verifiedCount === $totalCount ? 'success' : 'warning';
    }
}
