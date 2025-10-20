<?php

namespace App\Filament\Resources\WebhookDeliveryResource\Pages;

use App\Enums\WebhookDeliveryStatus;
use App\Filament\Resources\WebhookDeliveryResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListWebhookDeliveries extends ListRecords
{
    protected static string $resource = WebhookDeliveryResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Deliveries')
                ->badge(fn () => $this->getCachedBadgeCount()),

            'success' => Tab::make('Success')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', WebhookDeliveryStatus::SUCCESS))
                ->badge(fn () => $this->getCachedBadgeCount(WebhookDeliveryStatus::SUCCESS))
                ->badgeColor('success'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', WebhookDeliveryStatus::FAILED))
                ->badge(fn () => $this->getCachedBadgeCount(WebhookDeliveryStatus::FAILED))
                ->badgeColor('danger'),

            'retrying' => Tab::make('Retrying')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', WebhookDeliveryStatus::RETRYING))
                ->badge(fn () => $this->getCachedBadgeCount(WebhookDeliveryStatus::RETRYING))
                ->badgeColor('warning'),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereIn('status', [
                    WebhookDeliveryStatus::PENDING,
                    WebhookDeliveryStatus::SENDING,
                ]))
                ->badge(fn () => $this->getCachedBadgeCount([
                    WebhookDeliveryStatus::PENDING,
                    WebhookDeliveryStatus::SENDING,
                ]))
                ->badgeColor('info'),

            'last_24h' => Tab::make('Last 24 Hours')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('created_at', '>=', now()->subDay()))
                ->badge(fn () => $this->getCachedBadgeCount(last24h: true))
                ->badgeColor('gray'),
        ];
    }

    /**
     * Get cached badge count for tabs
     */
    protected function getCachedBadgeCount(
        WebhookDeliveryStatus|array|null $status = null,
        bool $last24h = false
    ): int {
        try {
            $query = static::getResource()::getEloquentQuery();

            if (is_array($status)) {
                $query->whereIn('status', $status);
            } elseif ($status !== null) {
                $query->where('status', $status);
            }

            if ($last24h) {
                $query->where('created_at', '>=', now()->subDay());
            }

            return $query->count();
        } catch (\Exception $e) {
            // Return 0 if there's any error calculating the count
            return 0;
        }
    }
}
