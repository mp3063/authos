<?php

namespace App\Filament\Resources\SSOSessionResource\Pages;

use App\Filament\Resources\SSOSessionResource;
use App\Models\SSOSession;
use App\Models\User;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewSSOSession extends ViewRecord
{
    protected static string $resource = SSOSessionResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('terminate')
                ->label('Terminate Session')
                ->icon('heroicon-o-x-circle')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('Terminate Session')
                ->modalDescription('Are you sure you want to terminate this SSO session? The user will be logged out of this application.')
                ->modalSubmitActionLabel('Terminate')
                ->visible(fn () => $this->record->isActive())
                ->action(function () {
                    /** @var User $authUser */
                    $authUser = Filament::auth()->user();

                    /** @var SSOSession $record */
                    $record = $this->record;
                    $record->logout($authUser);

                    Notification::make()
                        ->title('Session terminated')
                        ->body('The SSO session has been terminated successfully.')
                        ->success()
                        ->send();

                    $this->redirect(SSOSessionResource::getUrl('index'));
                }),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Session Details')
                ->schema([
                    TextEntry::make('user.name')
                        ->label('User'),

                    TextEntry::make('user.email')
                        ->label('Email'),

                    TextEntry::make('application.name')
                        ->label('Application')
                        ->badge(),

                    TextEntry::make('is_active')
                        ->label('Status')
                        ->badge()
                        ->formatStateUsing(fn () => $this->record->isActive() ? 'Active' : 'Inactive')
                        ->color(fn () => $this->record->isActive() ? 'success' : 'gray'),

                    TextEntry::make('external_session_id')
                        ->label('External Session ID')
                        ->placeholder('N/A')
                        ->copyable(),

                    TextEntry::make('created_at')
                        ->label('Created At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

                    TextEntry::make('expires_at')
                        ->label('Expires At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

                    TextEntry::make('last_activity_at')
                        ->label('Last Activity')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

                    TextEntry::make('logged_out_at')
                        ->label('Logged Out At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Still active'),

                    TextEntry::make('loggedOutBy.name')
                        ->label('Logged Out By')
                        ->placeholder('N/A'),
                ])
                ->columns(2)
                ->columnSpanFull(),

            Section::make('Device Information')
                ->schema([
                    TextEntry::make('ip_address')
                        ->label('IP Address')
                        ->copyable()
                        ->icon('heroicon-o-globe-alt'),

                    TextEntry::make('user_agent')
                        ->label('User Agent')
                        ->columnSpanFull()
                        ->tooltip(fn ($record) => $record->user_agent),

                    TextEntry::make('device_info')
                        ->label('Device')
                        ->formatStateUsing(function () {
                            $info = $this->record->getDeviceInfo();

                            return ucfirst($info['device']);
                        })
                        ->placeholder('Unknown'),

                    TextEntry::make('browser_info')
                        ->label('Browser')
                        ->formatStateUsing(function () {
                            $info = $this->record->getDeviceInfo();

                            return ucfirst($info['browser']);
                        })
                        ->placeholder('Unknown'),

                    TextEntry::make('platform_info')
                        ->label('Platform')
                        ->formatStateUsing(function () {
                            $info = $this->record->getDeviceInfo();

                            return ucfirst($info['platform']);
                        })
                        ->placeholder('Unknown'),
                ])
                ->columns(3)
                ->collapsible()
                ->columnSpanFull(),

            Section::make('Location Information')
                ->schema([
                    TextEntry::make('location_country')
                        ->label('Country')
                        ->formatStateUsing(function () {
                            $info = $this->record->getLocationInfo();

                            return $info['country'];
                        })
                        ->placeholder('Unknown'),

                    TextEntry::make('location_city')
                        ->label('City')
                        ->formatStateUsing(function () {
                            $info = $this->record->getLocationInfo();

                            return $info['city'];
                        })
                        ->placeholder('Unknown'),

                    TextEntry::make('location_region')
                        ->label('Region')
                        ->formatStateUsing(function () {
                            $info = $this->record->getLocationInfo();

                            return $info['region'];
                        })
                        ->placeholder('Unknown'),

                    TextEntry::make('location_timezone')
                        ->label('Timezone')
                        ->formatStateUsing(function () {
                            $info = $this->record->getLocationInfo();

                            return $info['timezone'];
                        })
                        ->placeholder('Unknown'),
                ])
                ->columns(2)
                ->collapsible()
                ->columnSpanFull(),

            Section::make('Metadata')
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
                ->collapsed()
                ->columnSpanFull(),
        ]);
    }
}
