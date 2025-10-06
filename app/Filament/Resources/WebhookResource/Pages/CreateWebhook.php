<?php

namespace App\Filament\Resources\WebhookResource\Pages;

use App\Filament\Resources\WebhookResource;
use App\Models\Webhook;
use App\Services\WebhookService;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\CreateRecord;
use Illuminate\Database\Eloquent\Model;

class CreateWebhook extends CreateRecord
{
    protected static string $resource = WebhookResource::class;

    protected string $generatedSecret = '';

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        // Generate secret if not provided
        if (empty($data['secret'])) {
            $data['secret'] = app(\App\Services\WebhookSignatureService::class)->generateSecret();

            // Store the generated secret to show in notification
            $this->generatedSecret = $data['secret'];
        }

        return $data;
    }

    protected function handleRecordCreation(array $data): Model
    {
        // Use the WebhookService to create the webhook properly
        $organization = \App\Models\Organization::find($data['organization_id']);

        return app(WebhookService::class)->createWebhook($organization, $data);
    }

    protected function getCreatedNotification(): ?Notification
    {
        $notification = Notification::make()
            ->success()
            ->title('Webhook created successfully!')
            ->persistent();

        if (! empty($this->generatedSecret)) {
            $notification->body('**Important:** Save your webhook secret now. You won\'t be able to see it again: `'.$this->generatedSecret.'`');
        }

        return $notification;
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('view', ['record' => $this->getRecord()]);
    }
}
