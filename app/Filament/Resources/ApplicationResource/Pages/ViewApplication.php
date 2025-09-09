<?php

namespace App\Filament\Resources\ApplicationResource\Pages;

use App\Filament\Resources\ApplicationResource;
use Filament\Actions;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;

class ViewApplication extends ViewRecord
{
    protected static string $resource = ApplicationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\EditAction::make(),

            Action::make('copy_credentials')
                ->label('Copy Credentials')
                ->icon('heroicon-o-clipboard-document')
                ->color('gray')
                ->action(function () {
                    Notification::make()
                        ->title('Credentials copied to clipboard')
                        ->body('Client ID and Secret have been copied')
                        ->success()
                        ->send();
                })
                ->modalContent(fn ($record) => view('filament.modals.application-credentials', [
                    'clientId' => $record->client_id,
                    'clientSecret' => $record->client_secret,
                ])),

            Action::make('regenerate_secret')
                ->label('Regenerate Secret')
                ->icon('heroicon-o-arrow-path')
                ->color('warning')
                ->requiresConfirmation()
                ->modalDescription('This will generate a new client secret. The old secret will stop working immediately.')
                ->action(fn ($record) => $record->regenerateSecret())
                ->after(fn () => Notification::make()
                    ->title('Client secret regenerated successfully')
                    ->warning()
                    ->send()
                ),
        ];
    }

    /* Infolist method temporarily disabled */
}
