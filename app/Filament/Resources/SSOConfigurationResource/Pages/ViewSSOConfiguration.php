<?php

namespace App\Filament\Resources\SSOConfigurationResource\Pages;

use App\Filament\Resources\SSOConfigurationResource;
use App\Models\SSOConfiguration;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewSSOConfiguration extends ViewRecord
{
    protected static string $resource = SSOConfigurationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('enable')
                ->authorize('update')
                ->icon('heroicon-o-check-circle')
                ->color('success')
                ->visible(fn (SSOConfiguration $record) => ! $record->is_active)
                ->action(function (SSOConfiguration $record) {
                    $record->update(['is_active' => true]);

                    Notification::make()
                        ->title('SSO configuration enabled')
                        ->success()
                        ->send();

                    $this->refreshFormData(['is_active']);
                }),
            Actions\Action::make('disable')
                ->authorize('update')
                ->icon('heroicon-o-x-circle')
                ->color('danger')
                ->visible(fn (SSOConfiguration $record) => $record->is_active)
                ->requiresConfirmation()
                ->modalHeading('Disable SSO Configuration')
                ->modalDescription('Are you sure you want to disable this SSO configuration? Users will no longer be able to authenticate via this provider.')
                ->action(function (SSOConfiguration $record) {
                    $record->update(['is_active' => false]);

                    Notification::make()
                        ->title('SSO configuration disabled')
                        ->success()
                        ->send();

                    $this->refreshFormData(['is_active']);
                }),
            Actions\EditAction::make(),
            Actions\DeleteAction::make(),
        ];
    }

    private static function redactSecrets(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        $redacted = [];

        foreach ($value as $key => $item) {
            $redacted[$key] = is_string($key) && preg_match('/(password|secret|private_key|api_key)$/i', $key)
                ? '********'
                : self::redactSecrets($item);
        }

        return $redacted;
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('SSO Configuration')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('name')
                                    ->weight(FontWeight::Bold),
                                TextEntry::make('provider')
                                    ->badge()
                                    ->formatStateUsing(fn (string $state): string => strtoupper($state))
                                    ->color(fn (string $state): string => match ($state) {
                                        'oidc' => 'info',
                                        'saml' => 'warning',
                                        default => 'gray',
                                    }),
                                TextEntry::make('application.name')
                                    ->label('Application')
                                    ->badge(),
                                TextEntry::make('is_active')
                                    ->label('Status')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'Active' : 'Inactive')
                                    ->color(fn ($state) => $state ? 'success' : 'danger'),
                                TextEntry::make('callback_url')
                                    ->label('Callback URL')
                                    ->url(fn ($record) => $record->callback_url)
                                    ->openUrlInNewTab()
                                    ->copyable()
                                    ->icon('heroicon-o-link')
                                    ->placeholder('Not configured')
                                    ->columnSpanFull(),
                                TextEntry::make('logout_url')
                                    ->label('Logout URL')
                                    ->url(fn ($record) => $record->logout_url)
                                    ->openUrlInNewTab()
                                    ->copyable()
                                    ->icon('heroicon-o-link')
                                    ->placeholder('Not configured')
                                    ->columnSpanFull(),
                            ]),
                    ]),

                Section::make('Provider Configuration')
                    ->schema([
                        TextEntry::make('configuration')
                            ->label(fn (SSOConfiguration $record): string => strtoupper($record->provider).' Settings')
                            ->state(fn (SSOConfiguration $record): string => empty($record->configuration) ? 'No configuration set' : json_encode(self::redactSecrets($record->configuration), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))
                            ->markdown()
                            ->columnSpanFull(),
                    ])
                    ->collapsible(),

                Section::make('Domain & Session')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('allowed_domains')
                                    ->label('Allowed Domains')
                                    ->badge()
                                    ->separator(',')
                                    ->placeholder('All domains allowed')
                                    ->columnSpanFull(),
                                TextEntry::make('session_lifetime')
                                    ->label('Session Lifetime')
                                    ->suffix(' minutes')
                                    ->placeholder('Default (60 minutes)'),
                            ]),
                    ]),

                Section::make('Timestamps')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('created_at')
                                    ->dateTime(),
                                TextEntry::make('updated_at')
                                    ->dateTime(),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(),
            ]);
    }
}
