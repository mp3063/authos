<?php

namespace App\Filament\Resources;

use App\Filament\Resources\IpBlocklistResource\Pages\CreateIpBlocklist;
use App\Filament\Resources\IpBlocklistResource\Pages\ListIpBlocklist;
use App\Models\IpBlocklist;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
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
use UnitEnum;

class IpBlocklistResource extends Resource
{
    protected static ?string $model = IpBlocklist::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Security';

    protected static ?int $navigationSort = 4;

    protected static ?string $modelLabel = 'Blocked IP';

    protected static ?string $pluralModelLabel = 'IP Blocklist';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Block IP Address')->schema([
                TextInput::make('ip_address')
                    ->required()
                    ->ip()
                    ->prefixIcon('heroicon-o-globe-alt'),

                Select::make('block_type')
                    ->options([
                        'manual' => 'Manual',
                        'automatic' => 'Automatic',
                        'permanent' => 'Permanent',
                    ])
                    ->required()
                    ->default('manual'),

                TextInput::make('reason')
                    ->required()
                    ->maxLength(255),

                Textarea::make('description')
                    ->maxLength(500)
                    ->columnSpanFull(),

                DateTimePicker::make('expires_at')
                    ->after('today')
                    ->helperText('Leave empty for permanent block'),

                Toggle::make('is_active')
                    ->default(true),
            ])->columns(2),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('ip_address')
                ->searchable()
                ->sortable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt')
                ->weight('bold'),

            TextColumn::make('block_type')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'manual' => 'info',
                    'automatic' => 'warning',
                    'permanent' => 'danger',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('reason')
                ->searchable()
                ->limit(40),

            IconColumn::make('is_active')
                ->boolean()
                ->trueIcon('heroicon-o-check-circle')
                ->falseIcon('heroicon-o-x-circle'),

            TextColumn::make('incident_count')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('blockedBy.name')
                ->label('Blocked By')
                ->placeholder('System'),

            TextColumn::make('blocked_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('expires_at')
                ->dateTime()
                ->sortable()
                ->placeholder('Never'),

            TextColumn::make('created_at')
                ->dateTime()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            TernaryFilter::make('is_active')
                ->label('Active Status')
                ->boolean()
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),

            SelectFilter::make('block_type')
                ->options([
                    'manual' => 'Manual',
                    'automatic' => 'Automatic',
                    'permanent' => 'Permanent',
                ]),

            Filter::make('expired')
                ->label('Expired')
                ->query(fn (Builder $query): Builder => $query->where('expires_at', '<', now())->where('is_active', true)),

            Filter::make('ip_address')
                ->schema([
                    TextInput::make('ip')
                        ->label('IP Address'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['ip'],
                        fn (Builder $query, $ip): Builder => $query->where('ip_address', 'like', "%$ip%"),
                    );
                }),
        ])->recordActions([
            ActionGroup::make([
                Action::make('unblock')
                    ->icon('heroicon-o-shield-check')
                    ->color('success')
                    ->requiresConfirmation()
                    ->modalHeading('Unblock IP')
                    ->modalDescription('Are you sure you want to unblock this IP address?')
                    ->visible(fn (IpBlocklist $record): bool => $record->is_active)
                    ->action(function (IpBlocklist $record) {
                        $record->update(['is_active' => false]);

                        Notification::make()
                            ->title('IP unblocked successfully')
                            ->success()
                            ->send();
                    }),

                Action::make('reblock')
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->modalHeading('Re-block IP')
                    ->modalDescription('Are you sure you want to re-block this IP address?')
                    ->visible(fn (IpBlocklist $record): bool => ! $record->is_active)
                    ->action(function (IpBlocklist $record) {
                        $record->update(['is_active' => true]);

                        Notification::make()
                            ->title('IP re-blocked successfully')
                            ->success()
                            ->send();
                    }),

                DeleteAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Blocked IP')
                    ->modalDescription('Are you sure you want to delete this blocked IP entry? This action cannot be undone.'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('bulk_unblock')
                    ->label('Unblock Selected')
                    ->icon('heroicon-o-shield-check')
                    ->color('success')
                    ->requiresConfirmation()
                    ->action(function ($records) {
                        $records->each(fn (IpBlocklist $record) => $record->update(['is_active' => false]));

                        Notification::make()
                            ->title('Selected IPs unblocked successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),

                BulkAction::make('bulk_block')
                    ->label('Block Selected')
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function ($records) {
                        $records->each(fn (IpBlocklist $record) => $record->update(['is_active' => true]));

                        Notification::make()
                            ->title('Selected IPs blocked successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),

                DeleteBulkAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Blocked IPs')
                    ->modalDescription('Are you sure you want to delete these blocked IP entries? This action cannot be undone.'),
            ]),
        ])->defaultSort('blocked_at', 'desc')->striped();
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListIpBlocklist::route('/'),
            'create' => CreateIpBlocklist::route('/create'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::active()->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $count = static::getModel()::active()->count();

        if ($count > 100) {
            return 'danger';
        }

        if ($count > 10) {
            return 'warning';
        }

        return 'primary';
    }
}
