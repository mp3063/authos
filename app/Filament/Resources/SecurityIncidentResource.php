<?php

namespace App\Filament\Resources;

use App\Filament\Resources\SecurityIncidentResource\Pages\ListSecurityIncidents;
use App\Filament\Resources\SecurityIncidentResource\Pages\ViewSecurityIncident;
use App\Models\SecurityIncident;
use App\Models\User;
use BackedEnum;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\DatePicker;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use UnitEnum;

class SecurityIncidentResource extends Resource
{
    protected static ?string $model = SecurityIncident::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Security';

    protected static ?int $navigationSort = 2;

    protected static ?string $navigationLabel = 'Security Incidents';

    protected static ?string $modelLabel = 'Security Incident';

    protected static ?string $pluralModelLabel = 'Security Incidents';

    public static function canCreate(): bool
    {
        return false;
    }

    /**
     * @throws \Throwable
     */
    public static function form(Schema $schema): Schema
    {
        return $schema->schema([// This resource is read-only, no form needed
        ]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('detected_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('type')
                ->badge()
                ->searchable()
                ->sortable(),

            TextColumn::make('severity')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'critical' => 'danger',
                    'high' => 'warning',
                    'medium' => 'info',
                    'low' => 'gray',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('status')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'open' => 'danger',
                    'investigating' => 'warning',
                    'resolved' => 'success',
                    'dismissed' => 'gray',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('ip_address')
                ->searchable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt'),

            TextColumn::make('user.name')
                ->label('User')
                ->searchable()
                ->placeholder('System'),

            TextColumn::make('endpoint')
                ->searchable()
                ->toggleable(),

            TextColumn::make('description')
                ->limit(50)
                ->toggleable(),

            TextColumn::make('action_taken')
                ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('resolved_at')
                ->dateTime()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('severity')
                ->options([
                    'critical' => 'Critical',
                    'high' => 'High',
                    'medium' => 'Medium',
                    'low' => 'Low',
                ]),

            SelectFilter::make('status')
                ->options([
                    'open' => 'Open',
                    'investigating' => 'Investigating',
                    'resolved' => 'Resolved',
                    'dismissed' => 'Dismissed',
                ]),

            SelectFilter::make('type')
                ->options([
                    'brute_force' => 'Brute Force',
                    'sql_injection' => 'SQL Injection',
                    'xss_attempt' => 'XSS Attempt',
                    'csrf_violation' => 'CSRF Violation',
                    'rate_limit_exceeded' => 'Rate Limit Exceeded',
                    'suspicious_activity' => 'Suspicious Activity',
                    'unauthorized_access' => 'Unauthorized Access',
                ]),

            Filter::make('ip_address')
                ->schema([
                    TextInput::make('ip')->label('IP Address'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['ip'],
                        fn (Builder $query, $ip): Builder => $query->where('ip_address', 'like', "%$ip%"),
                    );
                }),

            Filter::make('date_range')
                ->schema([
                    DatePicker::make('from')->label('From Date'),
                    DatePicker::make('until')->label('Until Date'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['from'],
                        fn (Builder $query, $date): Builder => $query->whereDate('detected_at', '>=', $date),
                    )->when(
                        $data['until'],
                        fn (Builder $query, $date): Builder => $query->whereDate('detected_at', '<=', $date),
                    );
                }),

            Filter::make('critical_open')
                ->query(fn (Builder $query): Builder => $query->where('severity', 'critical')->where('status', 'open'))
                ->label('Critical & Open'),
        ])->recordActions([
            ViewAction::make()->modalWidth('2xl'),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('resolve')
                    ->label('Resolve Selected')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to resolve these incidents?')
                    ->action(function (Collection $records) {
                        $records->each(function (SecurityIncident $record) {
                            $record->update([
                                'status' => 'resolved',
                                'resolved_at' => now(),
                            ]);
                        });

                        Notification::make()
                            ->title('Incidents resolved')
                            ->body("Resolved {$records->count()} incident(s).")
                            ->success()
                            ->send();
                    }),

                BulkAction::make('dismiss')
                    ->label('Dismiss Selected')
                    ->icon('heroicon-o-x-circle')
                    ->color('gray')
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to dismiss these incidents?')
                    ->action(function (Collection $records) {
                        $records->each(function (SecurityIncident $record) {
                            $record->update([
                                'status' => 'dismissed',
                                'resolved_at' => now(),
                            ]);
                        });

                        Notification::make()
                            ->title('Incidents dismissed')
                            ->body("Dismissed {$records->count()} incident(s).")
                            ->success()
                            ->send();
                    }),
            ]),
        ])->defaultSort('detected_at', 'desc')->poll('30s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListSecurityIncidents::route('/'),
            'view' => ViewSecurityIncident::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('status', 'open')
            ->whereDate('detected_at', today())
            ->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $criticalOpen = static::getModel()::where('severity', 'critical')
            ->where('status', 'open')
            ->count();

        if ($criticalOpen > 0) {
            return 'danger';
        }

        $openCount = static::getModel()::where('status', 'open')->count();

        if ($openCount > 5) {
            return 'warning';
        }

        return 'primary';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['user']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all security incidents
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see incidents from their organization
        if ($user && $user->organization_id) {
            $query->whereHas('user', function ($subQuery) use ($user) {
                $subQuery->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }
}
