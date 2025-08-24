<?php

namespace App\Filament\Resources\UserResource\Pages;

use App\Filament\Resources\UserResource;
use Filament\Actions;
use Filament\Resources\Pages\ViewRecord;

class ViewUser extends ViewRecord
{
    protected static string $resource = UserResource::class;

    protected function getHeaderActions(): array
    {
        return [
          Actions\EditAction::make(),

          Actions\Action::make('reset_mfa')
            ->label('Reset MFA')
            ->icon('heroicon-o-shield-exclamation')
            ->color('warning')
            ->requiresConfirmation()
            ->modalDescription('This will disable MFA for the user. They will need to set it up again.')
            ->action(function ($record) {
                $record->update([
                  'mfa_methods' => null,
                  'two_factor_secret' => null,
                  'two_factor_recovery_codes' => null,
                  'two_factor_confirmed_at' => null,
                ]);
            })
            ->after(fn() => \Filament\Notifications\Notification::make()
              ->title('MFA has been reset successfully')
              ->warning()
              ->send()
            )
            ->visible(fn($record) => $record->hasMfaEnabled()),
        ];
    }

    /* Infolist method temporarily disabled */
}