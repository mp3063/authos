<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ScheduledComplianceReportResource\Pages\CreateScheduledComplianceReport;
use App\Filament\Resources\ScheduledComplianceReportResource\Pages\EditScheduledComplianceReport;
use App\Filament\Resources\ScheduledComplianceReportResource\Pages\ListScheduledComplianceReports;
use App\Jobs\GenerateComplianceReportJob;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Throwable;
use UnitEnum;

class ScheduledComplianceReportResource extends Resource
{
    protected static ?string $model = ScheduledComplianceReport::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 6;

    protected static ?string $navigationLabel = 'Scheduled Reports';

    protected static ?string $modelLabel = 'Scheduled Compliance Report';

    protected static ?string $pluralModelLabel = 'Scheduled Compliance Reports';

    public static function form(Schema $schema): Schema
    {
        /** @var User|null $currentUser */
        $currentUser = Filament::auth()->user();
        $isSuperAdmin = $currentUser && $currentUser->isSuperAdmin();

        return $schema->schema([
            Section::make('Schedule Configuration')->schema([
                Select::make('report_type')
                    ->label('Report Type')
                    ->options([
                        ComplianceReport::TYPE_SOC2 => 'SOC 2',
                        ComplianceReport::TYPE_ISO27001 => 'ISO 27001',
                        ComplianceReport::TYPE_GDPR => 'GDPR',
                    ])
                    ->required(),

                Select::make('frequency')
                    ->label('Frequency')
                    ->options([
                        ScheduledComplianceReport::FREQUENCY_DAILY => 'Daily',
                        ScheduledComplianceReport::FREQUENCY_WEEKLY => 'Weekly',
                        ScheduledComplianceReport::FREQUENCY_MONTHLY => 'Monthly',
                        ScheduledComplianceReport::FREQUENCY_QUARTERLY => 'Quarterly',
                    ])
                    ->required(),

                Select::make('organization_id')
                    ->label('Organization')
                    ->options(fn () => Organization::pluck('name', 'id')->toArray())
                    ->searchable()
                    ->required()
                    ->visible($isSuperAdmin)
                    ->default($currentUser?->organization_id)
                    ->disabled(fn (string $operation): bool => $operation === 'edit'),

                Toggle::make('is_active')
                    ->label('Active')
                    ->default(true)
                    ->helperText('Inactive schedules are skipped by the dispatcher'),

                TagsInput::make('recipients')
                    ->label('Email Recipients')
                    ->placeholder('email@example.com')
                    ->nestedRecursiveRules(['email:rfc'])
                    ->helperText('Recipients receive PDF and JSON attachments when each report completes')
                    ->columnSpanFull(),

                DateTimePicker::make('next_run_at')
                    ->label('Next Run At')
                    ->required()
                    ->seconds(false)
                    ->default(now()->addMinute())
                    ->helperText('First run time. Subsequent runs follow the frequency cadence.')
                    ->columnSpanFull(),
            ])->columns(2),
        ]);
    }

    public static function table(Table $table): Table
    {
        /** @var User|null $currentUser */
        $currentUser = Filament::auth()->user();
        $isSuperAdmin = $currentUser && $currentUser->isSuperAdmin();

        return $table->columns([
            TextColumn::make('id')->label('ID')->sortable(),

            TextColumn::make('report_type')
                ->label('Type')
                ->badge()
                ->formatStateUsing(fn (string $state): string => match ($state) {
                    ComplianceReport::TYPE_SOC2 => 'SOC 2',
                    ComplianceReport::TYPE_ISO27001 => 'ISO 27001',
                    ComplianceReport::TYPE_GDPR => 'GDPR',
                    default => $state,
                })
                ->sortable(),

            TextColumn::make('frequency')
                ->badge()
                ->formatStateUsing(fn (string $state): string => ucfirst($state))
                ->sortable(),

            TextColumn::make('organization.name')
                ->badge()
                ->searchable()
                ->visible($isSuperAdmin),

            TextColumn::make('createdBy.name')
                ->label('Created By')
                ->placeholder('—')
                ->toggleable(),

            TextColumn::make('recipients')
                ->label('Recipients')
                ->formatStateUsing(fn ($state): string => is_array($state) ? count($state).' email(s)' : '0')
                ->tooltip(fn (ScheduledComplianceReport $record): string => is_array($record->recipients)
                    ? implode(', ', $record->recipients)
                    : ''),

            IconColumn::make('is_active')
                ->label('Active')
                ->boolean()
                ->sortable(),

            TextColumn::make('next_run_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('last_run_at')
                ->dateTime()
                ->sortable()
                ->placeholder('Never'),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('report_type')
                ->options([
                    ComplianceReport::TYPE_SOC2 => 'SOC 2',
                    ComplianceReport::TYPE_ISO27001 => 'ISO 27001',
                    ComplianceReport::TYPE_GDPR => 'GDPR',
                ]),

            SelectFilter::make('frequency')
                ->options([
                    ScheduledComplianceReport::FREQUENCY_DAILY => 'Daily',
                    ScheduledComplianceReport::FREQUENCY_WEEKLY => 'Weekly',
                    ScheduledComplianceReport::FREQUENCY_MONTHLY => 'Monthly',
                    ScheduledComplianceReport::FREQUENCY_QUARTERLY => 'Quarterly',
                ]),

            TernaryFilter::make('is_active')
                ->label('Active status')
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),

            SelectFilter::make('organization_id')
                ->label('Organization')
                ->options(fn () => Organization::pluck('name', 'id')->toArray())
                ->visible($isSuperAdmin),
        ])->recordActions([
            EditAction::make(),

            Action::make('runNow')
                ->label('Run Now')
                ->icon('heroicon-o-play')
                ->color('info')
                ->requiresConfirmation()
                ->modalHeading('Run Schedule Immediately')
                ->modalDescription('Dispatch this scheduled report right now in addition to its normal cadence.')
                ->action(function (ScheduledComplianceReport $record): void {
                    try {
                        GenerateComplianceReportJob::dispatch(
                            $record->organization,
                            $record->report_type,
                            $record->recipients ?? [],
                            $record->id,
                            null,
                            null,
                            $record->created_by_user_id,
                        );

                        $record->update(['last_run_at' => now()]);

                        Notification::make()
                            ->title('Report dispatched')
                            ->body('The compliance report job has been queued.')
                            ->success()
                            ->send();
                    } catch (Throwable $e) {
                        Notification::make()
                            ->title('Dispatch failed')
                            ->body($e->getMessage())
                            ->danger()
                            ->send();
                    }
                }),

            DeleteAction::make(),
        ])->defaultSort('next_run_at', 'asc')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListScheduledComplianceReports::route('/'),
            'create' => CreateScheduledComplianceReport::route('/create'),
            'edit' => EditScheduledComplianceReport::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->where('is_active', true)->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'primary';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['organization', 'createdBy']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        if ($user && $user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }
}
