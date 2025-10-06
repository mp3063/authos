<?php

namespace App\Filament\Resources\WebhookResource\Widgets;

use App\Enums\WebhookDeliveryStatus;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Filament\Facades\Filament;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class WebhookStatsWidget extends BaseWidget
{
    protected function getStats(): array
    {
        $user = Filament::auth()->user();

        // Build base queries with organization scoping
        $webhookQuery = Webhook::query();
        $deliveryQuery = WebhookDelivery::query();

        if (! $user->isSuperAdmin() && $user->organization_id) {
            $webhookQuery->where('organization_id', $user->organization_id);
            $deliveryQuery->whereHas('webhook', function ($q) use ($user) {
                $q->where('organization_id', $user->organization_id);
            });
        }

        // Webhook Stats
        $totalWebhooks = (clone $webhookQuery)->count();
        $activeWebhooks = (clone $webhookQuery)->where('is_active', true)->count();
        $failingWebhooks = (clone $webhookQuery)->where('failure_count', '>', 0)->count();

        // Delivery Stats (Last 24h)
        $last24hQuery = (clone $deliveryQuery)->where('created_at', '>=', now()->subDay());
        $totalDeliveries24h = (clone $last24hQuery)->count();
        $successDeliveries24h = (clone $last24hQuery)->where('status', WebhookDeliveryStatus::SUCCESS)->count();
        $failedDeliveries24h = (clone $last24hQuery)->where('status', WebhookDeliveryStatus::FAILED)->count();

        // Calculate success rate
        $successRate = $totalDeliveries24h > 0
            ? round(($successDeliveries24h / $totalDeliveries24h) * 100, 1)
            : 0;

        // Get average delivery time for successful deliveries
        $avgDeliveryTime = (clone $last24hQuery)
            ->where('status', WebhookDeliveryStatus::SUCCESS)
            ->whereNotNull('request_duration_ms')
            ->avg('request_duration_ms');

        return [
            Stat::make('Total Webhooks', $totalWebhooks)
                ->description($activeWebhooks.' active')
                ->descriptionIcon('heroicon-m-bell-alert')
                ->color('primary')
                ->url(route('filament.admin.resources.webhooks.index')),

            Stat::make('Active Webhooks', $activeWebhooks)
                ->description('Currently enabled')
                ->descriptionIcon('heroicon-m-check-circle')
                ->color('success')
                ->chart([3, 5, 4, 6, 7, 8, 7]),

            Stat::make('Deliveries (24h)', $totalDeliveries24h)
                ->description($successDeliveries24h.' successful')
                ->descriptionIcon('heroicon-m-paper-airplane')
                ->color('info')
                ->url(route('filament.admin.resources.webhook-deliveries.index')),

            Stat::make('Success Rate (24h)', $successRate.'%')
                ->description('Delivery success rate')
                ->descriptionIcon($successRate >= 90 ? 'heroicon-m-arrow-trending-up' : 'heroicon-m-arrow-trending-down')
                ->color($successRate >= 90 ? 'success' : ($successRate >= 70 ? 'warning' : 'danger'))
                ->chart(array_fill(0, 7, $successRate)),

            Stat::make('Failed (24h)', $failedDeliveries24h)
                ->description('Failed deliveries')
                ->descriptionIcon('heroicon-m-x-circle')
                ->color($failedDeliveries24h > 0 ? 'danger' : 'success')
                ->url(route('filament.admin.resources.webhook-deliveries.index', [
                    'activeTab' => 'failed',
                ])),

            Stat::make('Avg Response Time', $avgDeliveryTime ? number_format($avgDeliveryTime).' ms' : 'N/A')
                ->description('Average delivery time')
                ->descriptionIcon('heroicon-m-clock')
                ->color($avgDeliveryTime && $avgDeliveryTime < 1000 ? 'success' : 'warning'),

            Stat::make('Failing Webhooks', $failingWebhooks)
                ->description('With failure count > 0')
                ->descriptionIcon('heroicon-m-exclamation-triangle')
                ->color($failingWebhooks > 0 ? 'danger' : 'success')
                ->url(route('filament.admin.resources.webhooks.index', [
                    'activeTab' => 'failing',
                ])),

            Stat::make('Retrying', (clone $deliveryQuery)->where('status', WebhookDeliveryStatus::RETRYING)->count())
                ->description('Pending retry')
                ->descriptionIcon('heroicon-m-arrow-path')
                ->color('warning')
                ->url(route('filament.admin.resources.webhook-deliveries.index', [
                    'activeTab' => 'retrying',
                ])),
        ];
    }
}
