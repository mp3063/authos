<?php

namespace App\Filament\Resources\WebhookResource\Pages;

use App\Filament\Resources\WebhookResource;
use App\Models\Webhook;
use App\Services\WebhookService;
use Filament\Actions;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Split;
use Filament\Schemas\Components\TextEntry;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewWebhook extends ViewRecord
{
    protected static string $resource = WebhookResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('test')
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
            Actions\EditAction::make(),
            Actions\DeleteAction::make(),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Webhook Information')
                    ->schema([
                        Split::make([
                            Grid::make(2)
                                ->schema([
                                    TextEntry::make('name')
                                        ->weight(FontWeight::Bold),
                                    TextEntry::make('url')
                                        ->url(fn ($record) => $record->url)
                                        ->openUrlInNewTab()
                                        ->copyable()
                                        ->icon('heroicon-o-link'),
                                    TextEntry::make('organization.name')
                                        ->badge(),
                                    TextEntry::make('is_active')
                                        ->label('Status')
                                        ->badge()
                                        ->formatStateUsing(fn ($state) => $state ? 'Active' : 'Inactive')
                                        ->color(fn ($state) => $state ? 'success' : 'danger'),
                                ]),
                        ]),
                        TextEntry::make('description')
                            ->placeholder('No description provided')
                            ->columnSpanFull(),
                    ]),

                Section::make('Events')
                    ->schema([
                        TextEntry::make('events')
                            ->badge()
                            ->separator(',')
                            ->columnSpanFull(),
                    ]),

                Section::make('Statistics')
                    ->schema([
                        Grid::make(4)
                            ->schema([
                                TextEntry::make('deliveries_count')
                                    ->label('Total Deliveries')
                                    ->numeric(),
                                TextEntry::make('success_rate')
                                    ->label('Success Rate (30 days)')
                                    ->badge()
                                    ->formatStateUsing(fn (Webhook $record) => number_format($record->getSuccessRate(30), 1).'%')
                                    ->color(function (Webhook $record): string {
                                        $rate = $record->getSuccessRate(30);
                                        if ($rate >= 90) {
                                            return 'success';
                                        }
                                        if ($rate >= 70) {
                                            return 'warning';
                                        }

                                        return 'danger';
                                    }),
                                TextEntry::make('failure_count')
                                    ->label('Failure Count')
                                    ->badge()
                                    ->color(fn ($state) => $state > 0 ? 'danger' : 'success'),
                                TextEntry::make('avg_delivery_time')
                                    ->label('Avg Delivery Time')
                                    ->formatStateUsing(function (Webhook $record) {
                                        $avg = $record->getAverageDeliveryTime(30);

                                        return $avg ? number_format($avg).' ms' : 'N/A';
                                    }),
                            ]),
                    ]),

                Section::make('Advanced Settings')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('timeout_seconds')
                                    ->label('Timeout')
                                    ->suffix(' seconds'),
                                TextEntry::make('last_delivered_at')
                                    ->label('Last Delivery')
                                    ->dateTime()
                                    ->placeholder('Never'),
                                TextEntry::make('headers')
                                    ->label('Custom Headers')
                                    ->json()
                                    ->placeholder('No custom headers')
                                    ->columnSpanFull(),
                                TextEntry::make('ip_whitelist')
                                    ->label('IP Whitelist')
                                    ->badge()
                                    ->separator(',')
                                    ->placeholder('All IPs allowed')
                                    ->columnSpanFull(),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(),

                Section::make('Timestamps')
                    ->schema([
                        Grid::make(3)
                            ->schema([
                                TextEntry::make('created_at')
                                    ->dateTime(),
                                TextEntry::make('updated_at')
                                    ->dateTime(),
                                TextEntry::make('last_failed_at')
                                    ->dateTime()
                                    ->placeholder('Never failed'),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(),
            ]);
    }
}
