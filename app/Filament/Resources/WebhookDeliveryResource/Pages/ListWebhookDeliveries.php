<?php

namespace App\Filament\Resources\WebhookDeliveryResource\Pages;

use App\Enums\WebhookDeliveryStatus;
use App\Filament\Resources\WebhookDeliveryResource;
use App\Models\WebhookDelivery;
use Filament\Facades\Filament;
use Filament\Resources\Components\Tab;
use Filament\Resources\Pages\ListRecords;
use Illuminate\Database\Eloquent\Builder;

class ListWebhookDeliveries extends ListRecords
{
    protected static string $resource = WebhookDeliveryResource::class;

    public function getTabs(): array
    {
        $user = Filament::auth()->user();
        $query = WebhookDelivery::query();

        // Apply organization scoping via webhook relationship
        if (! $user->isSuperAdmin() && $user->organization_id) {
            $query->whereHas('webhook', function ($q) use ($user) {
                $q->where('organization_id', $user->organization_id);
            });
        }

        return [
            'all' => Tab::make('All Deliveries')
                ->badge((clone $query)->count()),

            'success' => Tab::make('Success')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('status', WebhookDeliveryStatus::SUCCESS))
                ->badge((clone $query)->where('status', WebhookDeliveryStatus::SUCCESS)->count())
                ->badgeColor('success'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('status', WebhookDeliveryStatus::FAILED))
                ->badge((clone $query)->where('status', WebhookDeliveryStatus::FAILED)->count())
                ->badgeColor('danger'),

            'retrying' => Tab::make('Retrying')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('status', WebhookDeliveryStatus::RETRYING))
                ->badge((clone $query)->where('status', WebhookDeliveryStatus::RETRYING)->count())
                ->badgeColor('warning'),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $q) => $q->whereIn('status', [
                    WebhookDeliveryStatus::PENDING,
                    WebhookDeliveryStatus::SENDING,
                ]))
                ->badge((clone $query)->whereIn('status', [
                    WebhookDeliveryStatus::PENDING,
                    WebhookDeliveryStatus::SENDING,
                ])->count())
                ->badgeColor('info'),

            'last_24h' => Tab::make('Last 24 Hours')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('created_at', '>=', now()->subDay()))
                ->badge((clone $query)->where('created_at', '>=', now()->subDay())->count())
                ->badgeColor('gray'),
        ];
    }
}
