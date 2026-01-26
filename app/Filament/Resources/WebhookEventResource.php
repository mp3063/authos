<?php

namespace App\Filament\Resources;

use App\Filament\Resources\WebhookEventResource\Pages\ListWebhookEvents;
use App\Filament\Resources\WebhookEventResource\Pages\ViewWebhookEvent;
use App\Models\WebhookEvent;
use BackedEnum;
use Filament\Actions\ViewAction;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Grouping\Group;
use Filament\Tables\Table;
use Illuminate\Support\Str;
use UnitEnum;

class WebhookEventResource extends Resource
{
    protected static ?string $model = WebhookEvent::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Integration';

    protected static ?int $navigationSort = 2;

    protected static ?string $navigationLabel = 'Event Catalog';

    protected static ?string $modelLabel = 'Webhook Event';

    protected static ?string $pluralModelLabel = 'Webhook Events';

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit($record): bool
    {
        return false;
    }

    public static function canDelete($record): bool
    {
        return false;
    }

    /**
     * @throws \Throwable
     */
    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            // Read-only resource, no form needed
        ]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')
                ->searchable()
                ->sortable()
                ->weight('bold')
                ->copyable()
                ->copyMessage('Event name copied'),

            TextColumn::make('category')
                ->badge()
                ->searchable()
                ->sortable()
                ->formatStateUsing(fn (string $state): string => Str::title(str_replace('_', ' ', $state)))
                ->color(fn (string $state): string => match ($state) {
                    'authentication' => 'success',
                    'user' => 'info',
                    'organization' => 'warning',
                    'application' => 'primary',
                    'security' => 'danger',
                    'webhook' => 'gray',
                    'sso' => 'success',
                    'mfa' => 'warning',
                    'billing' => 'primary',
                    default => 'gray',
                }),

            TextColumn::make('description')
                ->limit(60)
                ->toggleable()
                ->tooltip(fn (?string $state): ?string => $state && strlen($state) > 60 ? $state : null),

            TextColumn::make('version')
                ->badge()
                ->color('gray'),

            IconColumn::make('is_active')
                ->label('Active')
                ->boolean()
                ->trueIcon('heroicon-o-check-circle')
                ->falseIcon('heroicon-o-x-circle')
                ->trueColor('success')
                ->falseColor('danger'),

            TextColumn::make('payload_schema')
                ->label('Schema Keys')
                ->formatStateUsing(function ($state): string {
                    if (is_array($state) && count($state) > 0) {
                        return count($state).' '.Str::plural('key', count($state));
                    }

                    return 'N/A';
                })
                ->toggleable(),
        ])->filters([
            SelectFilter::make('category')
                ->options(function () {
                    return WebhookEvent::query()
                        ->distinct()
                        ->pluck('category', 'category')
                        ->mapWithKeys(fn (string $category): array => [
                            $category => Str::title(str_replace('_', ' ', $category)),
                        ])
                        ->toArray();
                }),

            TernaryFilter::make('is_active')
                ->label('Status')
                ->boolean()
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),
        ])->recordActions([
            ViewAction::make()->modalWidth('2xl'),
        ])->groups([
            Group::make('category')
                ->label('Category')
                ->getTitleFromRecordUsing(fn (WebhookEvent $record): string => Str::title(str_replace('_', ' ', $record->category))),
        ])->defaultSort('category', 'asc')
            ->defaultGroup('category')
            ->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListWebhookEvents::route('/'),
            'view' => ViewWebhookEvent::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('is_active', true)->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'info';
    }
}
