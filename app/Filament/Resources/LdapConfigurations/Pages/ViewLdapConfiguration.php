<?php

namespace App\Filament\Resources\LdapConfigurations\Pages;

use App\Filament\Resources\LdapConfigurations\LdapConfigurationResource;
use App\Jobs\SyncLdapUsersJob;
use App\Services\LdapAuthService;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewLdapConfiguration extends ViewRecord
{
    protected static string $resource = LdapConfigurationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('test_connection')
                ->label('Test Connection')
                ->icon('heroicon-o-signal')
                ->color('info')
                ->action(function () {
                    try {
                        $result = app(LdapAuthService::class)->testConnection($this->record);

                        Notification::make()
                            ->success()
                            ->title('Connection Successful')
                            ->body("Found {$result['user_count']} users")
                            ->send();
                    } catch (\Exception $e) {
                        Notification::make()
                            ->danger()
                            ->title('Connection Failed')
                            ->body($e->getMessage())
                            ->send();
                    }
                })
                ->requiresConfirmation()
                ->modalHeading('Test LDAP Connection')
                ->modalDescription('This will attempt to connect to the LDAP server with the configured credentials.')
                ->modalSubmitActionLabel('Test Now'),

            Action::make('sync_now')
                ->label('Sync Now')
                ->icon('heroicon-o-arrow-path')
                ->color('success')
                ->visible(fn (): bool => $this->record->is_active)
                ->action(function () {
                    $this->record->update(['sync_status' => 'pending']);
                    SyncLdapUsersJob::dispatch($this->record);

                    Notification::make()
                        ->success()
                        ->title('Sync Started')
                        ->body('User synchronization has been queued')
                        ->send();

                    $this->redirect(LdapConfigurationResource::getUrl('view', ['record' => $this->record]));
                })
                ->requiresConfirmation()
                ->modalHeading('Synchronize Users')
                ->modalDescription('This will sync users from the LDAP server to your organization.')
                ->modalSubmitActionLabel('Start Sync'),

            EditAction::make(),

            DeleteAction::make(),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Basic Information')
                ->schema([
                    TextEntry::make('name')
                        ->label('Configuration Name')
                        ->weight('bold'),

                    TextEntry::make('organization.name')
                        ->label('Organization')
                        ->badge()
                        ->placeholder('N/A'),

                    TextEntry::make('connection_info')
                        ->label('Connection')
                        ->state(fn ($record): string => $record->host.':'.$record->port)
                        ->icon('heroicon-o-server')
                        ->copyable()
                        ->copyMessage('Connection info copied'),

                    TextEntry::make('base_dn')
                        ->label('Base DN')
                        ->copyable()
                        ->copyMessage('Base DN copied'),

                    TextEntry::make('username')
                        ->label('Bind Username')
                        ->copyable(),

                    TextEntry::make('user_filter')
                        ->label('User Filter')
                        ->placeholder('(objectClass=person)'),

                    TextEntry::make('user_attribute')
                        ->label('User Attribute')
                        ->placeholder('Not set'),

                    TextEntry::make('ssl_tls')
                        ->label('Encryption')
                        ->state(function ($record): string {
                            if ($record->use_ssl) {
                                return 'SSL';
                            }
                            if ($record->use_tls) {
                                return 'TLS';
                            }

                            return 'None';
                        })
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'SSL', 'TLS' => 'success',
                            default => 'warning',
                        }),

                    TextEntry::make('is_active')
                        ->label('Status')
                        ->formatStateUsing(fn (bool $state): string => $state ? 'Enabled' : 'Disabled')
                        ->badge()
                        ->color(fn (bool $state): string => $state ? 'success' : 'danger'),
                ])
                ->columns(3),

            Section::make('Sync Status')
                ->schema([
                    TextEntry::make('sync_status')
                        ->label('Status')
                        ->badge()
                        ->color(fn (?string $state): string => match ($state) {
                            'pending' => 'warning',
                            'processing' => 'info',
                            'completed' => 'success',
                            'failed' => 'danger',
                            default => 'gray',
                        })
                        ->icon(fn (?string $state): ?string => match ($state) {
                            'pending' => 'heroicon-o-clock',
                            'processing' => 'heroicon-o-arrow-path',
                            'completed' => 'heroicon-o-check-circle',
                            'failed' => 'heroicon-o-x-circle',
                            default => null,
                        })
                        ->placeholder('Never synced'),

                    TextEntry::make('last_sync_at')
                        ->label('Last Sync')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Never'),

                    TextEntry::make('created_at')
                        ->label('Created At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

                    TextEntry::make('updated_at')
                        ->label('Last Updated')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),
                ])
                ->columns(3),

            Section::make('Last Sync Result')
                ->schema([
                    ViewEntry::make('last_sync_result')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->last_sync_result;
                            if (! $state) {
                                return ['json' => 'No sync results available'];
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

            Section::make('Error Log')
                ->schema([
                    ViewEntry::make('last_sync_error')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->last_sync_error;
                            if (! $state) {
                                return ['json' => 'No errors'];
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
                ->visible(fn ($record) => ! empty($record->last_sync_error))
                ->columnSpanFull(),
        ]);
    }
}
