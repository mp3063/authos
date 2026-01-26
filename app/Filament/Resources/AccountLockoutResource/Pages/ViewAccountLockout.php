<?php

namespace App\Filament\Resources\AccountLockoutResource\Pages;

use App\Filament\Resources\AccountLockoutResource;
use App\Models\AccountLockout;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewAccountLockout extends ViewRecord
{
    protected static string $resource = AccountLockoutResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('unlock')
                ->icon('heroicon-o-lock-open')
                ->color('success')
                ->visible(fn (AccountLockout $record) => $record->isActive())
                ->requiresConfirmation()
                ->modalHeading('Unlock Account')
                ->modalDescription('Are you sure you want to unlock this account lockout?')
                ->action(function (AccountLockout $record) {
                    $record->update([
                        'unlocked_at' => now(),
                        'unlock_method' => 'admin_manual',
                    ]);

                    Notification::make()
                        ->title('Account unlocked successfully')
                        ->success()
                        ->send();

                    $this->refreshFormData([
                        'unlocked_at',
                        'unlock_method',
                    ]);
                }),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Lockout Details')
                ->schema([
                    TextEntry::make('locked_at')
                        ->label('Locked At')
                        ->dateTime()
                        ->sinceTooltip(),

                    TextEntry::make('unlock_at')
                        ->label('Expires At')
                        ->dateTime()
                        ->placeholder('No expiry')
                        ->sinceTooltip(),

                    TextEntry::make('unlocked_at')
                        ->label('Unlocked At')
                        ->dateTime()
                        ->placeholder('Still locked')
                        ->sinceTooltip(),

                    TextEntry::make('unlock_method')
                        ->label('Unlock Method')
                        ->badge()
                        ->placeholder('N/A'),

                    TextEntry::make('attempt_count')
                        ->label('Attempt Count')
                        ->badge()
                        ->color('danger'),

                    TextEntry::make('reason')
                        ->label('Reason')
                        ->placeholder('No reason provided')
                        ->columnSpanFull(),
                ])
                ->columns(2),

            Section::make('User & Network')
                ->schema([
                    TextEntry::make('email')
                        ->label('Email')
                        ->copyable()
                        ->icon('heroicon-o-envelope'),

                    TextEntry::make('user.name')
                        ->label('User')
                        ->placeholder('N/A')
                        ->url(fn ($record) => $record->user ? route('filament.admin.resources.users.view', $record->user) : null),

                    TextEntry::make('ip_address')
                        ->label('IP Address')
                        ->copyable()
                        ->icon('heroicon-o-globe-alt'),
                ])
                ->columns(3),

            Section::make('Metadata')
                ->headerActions([
                    Actions\Action::make('copyJson')
                        ->label('Copy JSON')
                        ->icon('heroicon-o-clipboard')
                        ->color('gray')
                        ->size('sm')
                        ->url('javascript:void(0)')
                        ->extraAttributes([
                            'onclick' => 'copyJsonContent(); event.preventDefault(); return false;',
                        ]),
                ])
                ->schema([
                    ViewEntry::make('metadata')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->metadata;
                            if (! $state) {
                                return ['json' => 'None'];
                            }

                            if (is_string($state)) {
                                $decoded = json_decode($state, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    $formatted = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

                                    return ['json' => trim($formatted)];
                                }
                            }

                            if (is_array($state)) {
                                $formatted = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

                                return ['json' => trim($formatted)];
                            }

                            return ['json' => $state];
                        }),
                ])
                ->collapsible()
                ->columnSpanFull(),
        ]);
    }
}
