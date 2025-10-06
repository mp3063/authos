<?php

namespace App\Filament\Resources;

use App\Filament\Resources\WebhookResource\Pages\CreateWebhook;
use App\Filament\Resources\WebhookResource\Pages\EditWebhook;
use App\Filament\Resources\WebhookResource\Pages\ListWebhooks;
use App\Filament\Resources\WebhookResource\Pages\ViewWebhook;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookEvent;
use App\Services\WebhookService;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
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
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use UnitEnum;

class WebhookResource extends Resource
{
    protected static ?string $model = Webhook::class;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-bell-alert';

    protected static string|UnitEnum|null $navigationGroup = 'Integration';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            // Webhook Configuration
            Section::make('Webhook Configuration')->schema([
                TextInput::make('name')
                    ->label('Webhook Name')
                    ->required()
                    ->maxLength(255)
                    ->helperText('Descriptive name for this webhook'),

                TextInput::make('url')
                    ->label('Webhook URL')
                    ->url()
                    ->required()
                    ->prefixIcon('heroicon-o-link')
                    ->helperText('Must be HTTPS in production. The endpoint will receive webhook events.')
                    ->columnSpanFull(),

                Textarea::make('description')
                    ->label('Description')
                    ->maxLength(500)
                    ->rows(2)
                    ->helperText('Optional description of this webhook\'s purpose')
                    ->columnSpanFull(),

                Select::make('organization_id')
                    ->label('Organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload()
                    ->required()
                    ->disabled(fn ($context) => $context === 'edit')
                    ->helperText('Organization that owns this webhook'),

                Toggle::make('is_active')
                    ->label('Active')
                    ->default(true)
                    ->helperText('Inactive webhooks will not receive events'),
            ])->columns(2),

            // Event Subscription
            Section::make('Event Subscription')->schema([
                CheckboxList::make('events')
                    ->label('Subscribe to Events')
                    ->options(function () {
                        // Cache the grouped events for 1 hour
                        return Cache::remember('webhook_events_grouped', 3600, function () {
                            $events = WebhookEvent::active()->orderBy('category')->orderBy('name')->get();

                            $grouped = [];
                            foreach ($events->groupBy('category') as $category => $categoryEvents) {
                                $categoryLabel = Str::title(str_replace('_', ' ', $category));
                                foreach ($categoryEvents as $event) {
                                    $grouped[$categoryLabel][$event->name] = $event->name.' - '.$event->description;
                                }
                            }

                            return $grouped;
                        });
                    })
                    ->columns(2)
                    ->required()
                    ->searchable()
                    ->bulkToggleable()
                    ->helperText('Select the events this webhook should receive. At least one event is required.')
                    ->columnSpanFull(),
            ])->collapsible()->collapsed(fn ($context) => $context === 'edit'),

            // Advanced Settings
            Section::make('Advanced Settings')->schema([
                TextInput::make('secret')
                    ->label('Webhook Secret')
                    ->password()
                    ->revealable()
                    ->disabled(fn ($context) => $context === 'edit')
                    ->dehydrated(fn ($context) => $context === 'create')
                    ->helperText(fn ($context) => $context === 'create'
                        ? 'Leave empty to auto-generate. This secret is used to sign webhook payloads.'
                        : 'Secret is hidden for security. Use "Rotate Secret" action to generate a new one.'),

                TextInput::make('timeout_seconds')
                    ->label('Timeout (seconds)')
                    ->numeric()
                    ->default(30)
                    ->minValue(1)
                    ->maxValue(300)
                    ->helperText('Maximum time to wait for response'),

                KeyValue::make('headers')
                    ->label('Custom Headers')
                    ->keyLabel('Header Name')
                    ->valueLabel('Header Value')
                    ->helperText('Optional custom HTTP headers to include with requests')
                    ->columnSpanFull(),

                TagsInput::make('ip_whitelist')
                    ->label('IP Whitelist (Optional)')
                    ->placeholder('Add IP address...')
                    ->helperText('Restrict webhook to specific IPs. Leave empty to allow all.')
                    ->columnSpanFull(),
            ])->columns(2)->collapsible()->collapsed(),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')
                ->searchable()
                ->sortable()
                ->weight('bold')
                ->description(fn (Webhook $record): string => Str::limit($record->url, 50)),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->searchable()
                ->sortable()
                ->badge()
                ->toggleable(),

            TextColumn::make('events')
                ->label('Events')
                ->badge()
                ->color('info')
                ->formatStateUsing(fn ($state): string => count($state ?? []).' events')
                ->tooltip(fn (Webhook $record): string => implode(', ', array_slice($record->events ?? [], 0, 5)).(count($record->events ?? []) > 5 ? '...' : '')),

            IconColumn::make('is_active')
                ->label('Status')
                ->boolean()
                ->sortable()
                ->trueIcon('heroicon-o-check-circle')
                ->falseIcon('heroicon-o-x-circle')
                ->trueColor('success')
                ->falseColor('danger'),

            TextColumn::make('success_rate')
                ->label('Success Rate')
                ->formatStateUsing(function (Webhook $record): string {
                    $rate = $record->getSuccessRate(30);

                    return $rate > 0 ? number_format($rate, 1).'%' : 'N/A';
                })
                ->badge()
                ->color(function (Webhook $record): string {
                    $rate = $record->getSuccessRate(30);
                    if ($rate >= 90) {
                        return 'success';
                    }
                    if ($rate >= 70) {
                        return 'warning';
                    }
                    if ($rate > 0) {
                        return 'danger';
                    }

                    return 'gray';
                })
                ->sortable(false)
                ->tooltip('Success rate over last 30 days'),

            TextColumn::make('deliveries_count')
                ->counts('deliveries')
                ->label('Total Deliveries')
                ->sortable()
                ->alignCenter()
                ->toggleable(),

            TextColumn::make('last_delivered_at')
                ->label('Last Delivery')
                ->dateTime()
                ->sortable()
                ->toggleable()
                ->placeholder('Never')
                ->description(
                    fn (Webhook $record): ?string => $record->last_failed_at ? 'Last failed: '.$record->last_failed_at->diffForHumans() : null
                ),

            TextColumn::make('failure_count')
                ->label('Failures')
                ->sortable()
                ->alignCenter()
                ->badge()
                ->color(fn ($state): string => $state >= 10 ? 'danger' : ($state > 0 ? 'warning' : 'success'))
                ->toggleable(),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('organization')
                ->relationship('organization', 'name')
                ->searchable()
                ->preload()
                ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

            TernaryFilter::make('is_active')
                ->label('Status')
                ->boolean()
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),

            SelectFilter::make('event_type')
                ->label('Event Type')
                ->options(function () {
                    return Cache::remember('webhook_event_categories', 3600, function () {
                        return WebhookEvent::active()
                            ->distinct()
                            ->pluck('category', 'category')
                            ->mapWithKeys(fn ($category) => [$category => Str::title($category)])
                            ->toArray();
                    });
                })
                ->query(function (Builder $query, array $data) {
                    if (filled($data['value'])) {
                        $events = WebhookEvent::where('category', $data['value'])->pluck('name')->toArray();
                        $query->where(function ($q) use ($events) {
                            foreach ($events as $event) {
                                $q->orWhereJsonContains('events', $event);
                            }
                        });
                    }
                }),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),
                Action::make('test')
                    ->icon('heroicon-o-beaker')
                    ->color('info')
                    ->requiresConfirmation()
                    ->modalHeading('Test Webhook')
                    ->modalDescription('Send a test event to this webhook endpoint?')
                    ->action(function (Webhook $record) {
                        try {
                            $webhookService = app(WebhookService::class);
                            $delivery = $webhookService->testWebhook($record);

                            if ($delivery->isSuccessful()) {
                                Notification::make()
                                    ->title('Test webhook sent successfully!')
                                    ->success()
                                    ->send();
                            } else {
                                Notification::make()
                                    ->title('Test webhook failed')
                                    ->body($delivery->error_message ?? 'Unknown error')
                                    ->warning()
                                    ->send();
                            }
                        } catch (\Exception $e) {
                            Notification::make()
                                ->title('Error sending test webhook')
                                ->body($e->getMessage())
                                ->danger()
                                ->send();
                        }
                    }),
                Action::make('rotate_secret')
                    ->icon('heroicon-o-key')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->modalHeading('Rotate Webhook Secret')
                    ->modalDescription('Are you sure you want to rotate the webhook secret? You must update your endpoint with the new secret.')
                    ->action(function (Webhook $record) {
                        $webhookService = app(WebhookService::class);
                        $newSecret = $webhookService->rotateSecret($record);

                        Notification::make()
                            ->title('Secret rotated successfully!')
                            ->body('New secret: '.$newSecret)
                            ->success()
                            ->persistent()
                            ->send();
                    }),
                Action::make('enable')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->visible(fn (Webhook $record) => ! $record->is_active)
                    ->action(function (Webhook $record) {
                        app(WebhookService::class)->enableWebhook($record);

                        Notification::make()
                            ->title('Webhook enabled')
                            ->success()
                            ->send();
                    }),
                Action::make('disable')
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->visible(fn (Webhook $record) => $record->is_active)
                    ->requiresConfirmation()
                    ->action(function (Webhook $record) {
                        app(WebhookService::class)->disableWebhook($record);

                        Notification::make()
                            ->title('Webhook disabled')
                            ->success()
                            ->send();
                    }),
                Action::make('view_deliveries')
                    ->icon('heroicon-o-queue-list')
                    ->color('info')
                    ->url(fn (Webhook $record): string => route('filament.admin.resources.webhook-deliveries.index', [
                        'tableFilters' => ['webhook' => ['value' => $record->id]],
                    ])),
                DeleteAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Webhook')
                    ->modalDescription('Are you sure you want to delete this webhook? This action cannot be undone.'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('enable')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->action(function ($records) {
                        $webhookService = app(WebhookService::class);
                        $records->each(fn ($record) => $webhookService->enableWebhook($record));

                        Notification::make()
                            ->title('Webhooks enabled successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),
                BulkAction::make('disable')
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function ($records) {
                        $webhookService = app(WebhookService::class);
                        $records->each(fn ($record) => $webhookService->disableWebhook($record));

                        Notification::make()
                            ->title('Webhooks disabled successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),
                DeleteBulkAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Webhooks')
                    ->modalDescription('Are you sure you want to delete these webhooks? This action cannot be undone.'),
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
            'index' => ListWebhooks::route('/'),
            'create' => CreateWebhook::route('/create'),
            'view' => ViewWebhook::route('/{record}'),
            'edit' => EditWebhook::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = Filament::auth()->user();

        // Ensure user is properly typed and authenticated
        if (! $user instanceof User) {
            return $query->whereRaw('1 = 0'); // Return empty results if not authenticated properly
        }

        // Super admins can see all webhooks
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see webhooks from their organization
        if ($user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->where('is_active', true)->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }
}
