<?php

namespace App\Filament\Resources\WebhookDeliveryResource\Pages;

use App\Enums\WebhookDeliveryStatus;
use App\Filament\Resources\WebhookDeliveryResource;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewWebhookDelivery extends ViewRecord
{
    protected static string $resource = WebhookDeliveryResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('retry')
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
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Delivery Information')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('webhook.name')
                                    ->label('Webhook')
                                    ->weight(FontWeight::Bold)
                                    ->url(
                                        fn (WebhookDelivery $record): ?string => $record->webhook ? route('filament.admin.resources.webhooks.view', ['record' => $record->webhook]) : null
                                    ),
                                TextEntry::make('webhook.url')
                                    ->label('Webhook URL')
                                    ->copyable()
                                    ->url(fn ($state) => $state)
                                    ->openUrlInNewTab(),
                                TextEntry::make('event_type')
                                    ->badge()
                                    ->color('info'),
                                TextEntry::make('status')
                                    ->badge()
                                    ->formatStateUsing(fn (WebhookDeliveryStatus $state): string => $state->getLabel())
                                    ->color(fn (WebhookDeliveryStatus $state): string => $state->getColor()),
                            ]),
                    ]),

                Section::make('HTTP Response')
                    ->schema([
                        Grid::make(3)
                            ->schema([
                                TextEntry::make('http_status_code')
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
                                    ->formatStateUsing(fn ($state): string => $state ? (string) $state : 'N/A'),
                                TextEntry::make('request_duration_ms')
                                    ->label('Duration')
                                    ->suffix(' ms')
                                    ->placeholder('N/A'),
                                TextEntry::make('attempt_number')
                                    ->label('Attempt')
                                    ->formatStateUsing(
                                        fn (WebhookDelivery $record): string => $record->attempt_number.' / '.$record->max_attempts
                                    )
                                    ->badge()
                                    ->color(
                                        fn (WebhookDelivery $record): string => $record->attempt_number >= $record->max_attempts ? 'danger' : 'info'
                                    ),
                            ]),
                        TextEntry::make('error_message')
                            ->label('Error Message')
                            ->placeholder('No errors')
                            ->color('danger')
                            ->columnSpanFull()
                            ->visible(fn ($state) => filled($state)),
                    ]),

                Section::make('Request Payload')
                    ->schema([
                        TextEntry::make('payload')
                            ->label('')
                            ->formatStateUsing(fn ($state): string => json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))
                            ->copyable()
                            ->extraAttributes(['class' => 'font-mono text-sm'])
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(fn (WebhookDelivery $record) => $record->status === WebhookDeliveryStatus::SUCCESS),

                Section::make('Response Details')
                    ->schema([
                        TextEntry::make('response_body')
                            ->label('Response Body')
                            ->formatStateUsing(function ($state): string {
                                if (! $state) {
                                    return 'No response body';
                                }

                                // Try to decode as JSON
                                $decoded = json_decode($state, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    return json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                                }

                                return $state;
                            })
                            ->copyable()
                            ->extraAttributes(['class' => 'font-mono text-sm'])
                            ->placeholder('No response body')
                            ->columnSpanFull(),
                        TextEntry::make('response_headers')
                            ->label('Response Headers')
                            ->formatStateUsing(fn ($state): string => $state ? json_encode($state, JSON_PRETTY_PRINT) : 'No response headers')
                            ->copyable()
                            ->extraAttributes(['class' => 'font-mono text-sm'])
                            ->placeholder('No response headers')
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(fn (WebhookDelivery $record) => $record->status === WebhookDeliveryStatus::SUCCESS),

                Section::make('Retry Information')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('next_retry_at')
                                    ->label('Next Retry At')
                                    ->dateTime()
                                    ->placeholder('Not scheduled')
                                    ->sinceTooltip(),
                                TextEntry::make('signature')
                                    ->label('Webhook Signature')
                                    ->copyable()
                                    ->limit(50)
                                    ->placeholder('N/A'),
                            ]),
                    ])
                    ->visible(fn (WebhookDelivery $record) => $record->status === WebhookDeliveryStatus::RETRYING || $record->next_retry_at)
                    ->collapsible()
                    ->collapsed(),

                Section::make('Timestamps')
                    ->schema([
                        Grid::make(3)
                            ->schema([
                                TextEntry::make('created_at')
                                    ->dateTime()
                                    ->sinceTooltip(),
                                TextEntry::make('sent_at')
                                    ->dateTime()
                                    ->placeholder('Not sent yet')
                                    ->sinceTooltip(),
                                TextEntry::make('completed_at')
                                    ->dateTime()
                                    ->placeholder('Not completed')
                                    ->sinceTooltip(),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(),
            ]);
    }
}
