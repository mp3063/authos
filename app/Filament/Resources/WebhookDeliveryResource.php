<?php

namespace App\Filament\Resources;

use App\Enums\WebhookDeliveryStatus;
use App\Filament\Resources\WebhookDeliveryResource\Pages\ListWebhookDeliveries;
use App\Filament\Resources\WebhookDeliveryResource\Pages\ViewWebhookDelivery;
use App\Models\User;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Cache;
use UnitEnum;

class WebhookDeliveryResource extends Resource
{
    protected static ?string $model = WebhookDelivery::class;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-queue-list';

    protected static string|UnitEnum|null $navigationGroup = 'Integration';

    protected static ?int $navigationSort = 2;

    protected static ?string $label = 'Webhook Delivery';

    protected static ?string $pluralLabel = 'Webhook Deliveries';

    public static function canCreate(): bool
    {
        // Deliveries are created automatically, not manually
        return false;
    }

    public static function canEdit($record): bool
    {
        // Deliveries are read-only logs
        return false;
    }

    public static function canDelete($record): bool
    {
        // Deliveries should not be deleted
        return false;
    }

    public static function form(Schema $schema): Schema
    {
        // No form needed - read-only resource
        return $schema->schema([]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('webhook.name')
                ->label('Webhook')
                ->searchable()
                ->sortable()
                ->description(fn (WebhookDelivery $record): string => \Illuminate\Support\Str::limit($record->webhook->url ?? 'N/A', 40))
                ->url(
                    fn (WebhookDelivery $record): ?string => $record->webhook ? route('filament.admin.resources.webhooks.view', ['record' => $record->webhook]) : null
                ),

            TextColumn::make('event_type')
                ->label('Event')
                ->badge()
                ->color('info')
                ->searchable()
                ->sortable(),

            TextColumn::make('status')
                ->badge()
                ->formatStateUsing(fn (WebhookDeliveryStatus $state): string => $state->getLabel())
                ->color(fn (WebhookDeliveryStatus $state): string => $state->getColor())
                ->sortable(),

            TextColumn::make('http_status_code')
                ->label('HTTP Status')
                ->badge()
                ->color(function ($state): string {
                    if (! $state) {
                        return 'gray';
                    }
                    if ($state >= 200 && $state < 300) {
                        return 'success';
                    }
                    if ($state >= 400 && $state < 500) {
                        return 'warning';
                    }
                    if ($state >= 500) {
                        return 'danger';
                    }

                    return 'gray';
                })
                ->formatStateUsing(fn ($state): string => $state ? (string) $state : 'N/A')
                ->sortable(),

            TextColumn::make('request_duration_ms')
                ->label('Duration')
                ->formatStateUsing(fn ($state): string => $state ? $state.' ms' : 'N/A')
                ->sortable()
                ->alignCenter()
                ->color(function ($state): string {
                    if (! $state) {
                        return 'gray';
                    }
                    if ($state < 1000) {
                        return 'success';
                    }
                    if ($state < 3000) {
                        return 'warning';
                    }

                    return 'danger';
                }),

            TextColumn::make('attempt_number')
                ->label('Attempt')
                ->formatStateUsing(
                    fn (WebhookDelivery $record): string => $record->attempt_number.' / '.$record->max_attempts
                )
                ->alignCenter()
                ->color(
                    fn (WebhookDelivery $record): string => $record->attempt_number >= $record->max_attempts ? 'danger' : 'info'
                ),

            TextColumn::make('next_retry_at')
                ->label('Next Retry')
                ->dateTime()
                ->placeholder('N/A')
                ->sortable()
                ->toggleable()
                ->description(fn ($state) => $state ? $state->diffForHumans() : null),

            TextColumn::make('created_at')
                ->label('Created')
                ->dateTime()
                ->sortable()
                ->description(fn ($state) => $state->diffForHumans()),

            TextColumn::make('completed_at')
                ->label('Completed')
                ->dateTime()
                ->sortable()
                ->placeholder('Pending')
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('webhook')
                ->relationship('webhook', 'name')
                ->searchable()
                ->preload(),

            SelectFilter::make('event_type')
                ->label('Event Type')
                ->options(function () {
                    return Cache::remember('webhook_delivery_event_types', 600, function () {
                        return WebhookDelivery::query()
                            ->distinct()
                            ->pluck('event_type', 'event_type')
                            ->toArray();
                    });
                }),

            SelectFilter::make('status')
                ->options([
                    WebhookDeliveryStatus::PENDING->value => WebhookDeliveryStatus::PENDING->getLabel(),
                    WebhookDeliveryStatus::SENDING->value => WebhookDeliveryStatus::SENDING->getLabel(),
                    WebhookDeliveryStatus::SUCCESS->value => WebhookDeliveryStatus::SUCCESS->getLabel(),
                    WebhookDeliveryStatus::FAILED->value => WebhookDeliveryStatus::FAILED->getLabel(),
                    WebhookDeliveryStatus::RETRYING->value => WebhookDeliveryStatus::RETRYING->getLabel(),
                ])
                ->native(false),

            Filter::make('created_at')
                ->form([
                    \Filament\Forms\Components\DatePicker::make('created_from')
                        ->label('Created from'),
                    \Filament\Forms\Components\DatePicker::make('created_until')
                        ->label('Created until'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query
                        ->when(
                            $data['created_from'],
                            fn (Builder $query, $date): Builder => $query->whereDate('created_at', '>=', $date),
                        )
                        ->when(
                            $data['created_until'],
                            fn (Builder $query, $date): Builder => $query->whereDate('created_at', '<=', $date),
                        );
                }),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                Action::make('retry')
                    ->icon('heroicon-o-arrow-path')
                    ->color('warning')
                    ->visible(fn (WebhookDelivery $record) => $record->canRetry())
                    ->requiresConfirmation()
                    ->modalHeading('Retry Webhook Delivery')
                    ->modalDescription('Retry this failed webhook delivery?')
                    ->action(function (WebhookDelivery $record) {
                        try {
                            app(WebhookDeliveryService::class)->requeueFailedDelivery($record);

                            Notification::make()
                                ->title('Delivery queued for retry')
                                ->success()
                                ->send();
                        } catch (\Exception $e) {
                            Notification::make()
                                ->title('Error queuing retry')
                                ->body($e->getMessage())
                                ->danger()
                                ->send();
                        }
                    }),
                Action::make('view_payload')
                    ->icon('heroicon-o-code-bracket')
                    ->color('info')
                    ->modalContent(fn (WebhookDelivery $record) => view('filament.modals.webhook-payload', [
                        'payload' => $record->payload,
                    ]))
                    ->modalSubmitAction(false)
                    ->modalCancelActionLabel('Close'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('retry_failed')
                    ->icon('heroicon-o-arrow-path')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->deselectRecordsAfterCompletion()
                    ->action(function ($records) {
                        $webhookService = app(WebhookDeliveryService::class);
                        $retried = 0;

                        foreach ($records as $record) {
                            if ($record->canRetry()) {
                                $webhookService->requeueFailedDelivery($record);
                                $retried++;
                            }
                        }

                        Notification::make()
                            ->title("Retried {$retried} deliveries")
                            ->success()
                            ->send();
                    }),
            ]),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [

        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListWebhookDeliveries::route('/'),
            'view' => ViewWebhookDelivery::route('/{record}'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with('webhook');
        $user = Filament::auth()->user();

        // Ensure user is properly typed and authenticated
        if (! $user instanceof User) {
            return $query->whereRaw('1 = 0');
        }

        // Super admins can see all deliveries
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see deliveries from their organization's webhooks
        if ($user->organization_id) {
            $query->whereHas('webhook', function ($q) use ($user) {
                $q->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()
            ->where('status', WebhookDeliveryStatus::FAILED)
            ->whereDate('created_at', '>=', now()->subDay())
            ->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'danger';
    }

    public static function getNavigationLabel(): string
    {
        return 'Deliveries';
    }
}
