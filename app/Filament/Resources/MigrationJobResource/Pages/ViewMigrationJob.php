<?php

namespace App\Filament\Resources\MigrationJobResource\Pages;

use App\Filament\Resources\MigrationJobResource;
use App\Models\MigrationJob;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewMigrationJob extends ViewRecord
{
    protected static string $resource = MigrationJobResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('retry')
                ->label('Retry')
                ->icon('heroicon-o-arrow-path')
                ->color('warning')
                ->visible(fn (): bool => $this->record->status === 'failed')
                ->requiresConfirmation()
                ->modalHeading('Retry Migration')
                ->modalDescription('Are you sure you want to retry this failed migration? The status will be reset to pending.')
                ->action(function () {
                    $this->record->update([
                        'status' => 'pending',
                        'error_log' => null,
                    ]);

                    Notification::make()
                        ->title('Migration queued for retry')
                        ->body("Migration #{$this->record->id} has been reset to pending.")
                        ->success()
                        ->send();

                    $this->redirect(MigrationJobResource::getUrl('view', ['record' => $this->record]));
                }),

            Action::make('rollback')
                ->label('Rollback')
                ->icon('heroicon-o-arrow-uturn-left')
                ->color('danger')
                ->visible(fn (): bool => $this->record->status === 'completed')
                ->requiresConfirmation()
                ->modalHeading('Rollback Migration')
                ->modalDescription('Are you sure you want to rollback this migration? This will delete all migrated data and cannot be undone.')
                ->action(function () {
                    $this->record->rollback();

                    Notification::make()
                        ->title('Migration rolled back')
                        ->body("Migration #{$this->record->id} has been rolled back successfully.")
                        ->success()
                        ->send();

                    $this->redirect(MigrationJobResource::getUrl('view', ['record' => $this->record]));
                }),

            DeleteAction::make(),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Migration Details')
                ->schema([
                    TextEntry::make('id')
                        ->label('Migration ID'),

                    TextEntry::make('source')
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'auth0' => 'info',
                            'okta' => 'warning',
                            'custom' => 'gray',
                            default => 'gray',
                        }),

                    TextEntry::make('status')
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'pending' => 'warning',
                            'running' => 'info',
                            'completed' => 'success',
                            'failed' => 'danger',
                            'rolled_back' => 'gray',
                            default => 'gray',
                        }),

                    TextEntry::make('organization.name')
                        ->label('Organization')
                        ->badge()
                        ->placeholder('N/A'),

                    TextEntry::make('total_items')
                        ->label('Total Items')
                        ->placeholder('0'),

                    TextEntry::make('summary')
                        ->label('Summary')
                        ->state(fn (MigrationJob $record): string => $record->getSummary())
                        ->columnSpanFull(),
                ])
                ->columns(3),

            Section::make('Timing')
                ->schema([
                    TextEntry::make('started_at')
                        ->label('Started At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Not started'),

                    TextEntry::make('completed_at')
                        ->label('Completed At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Not completed'),

                    TextEntry::make('duration')
                        ->label('Duration')
                        ->state(function (MigrationJob $record): string {
                            if (! $record->started_at) {
                                return 'N/A';
                            }
                            $end = $record->completed_at ?? now();
                            $seconds = $record->started_at->diffInSeconds($end);

                            if ($seconds < 60) {
                                return "{$seconds}s";
                            }

                            $minutes = floor($seconds / 60);
                            $remainingSeconds = $seconds % 60;

                            return "{$minutes}m {$remainingSeconds}s";
                        }),

                    TextEntry::make('created_at')
                        ->label('Created At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

                    TextEntry::make('updated_at')
                        ->label('Last Updated')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),
                ])
                ->columns(3),

            Section::make('Migration Statistics')
                ->schema([
                    ViewEntry::make('stats')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->stats;
                            if (! $state) {
                                return ['json' => 'No statistics available'];
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

            Section::make('Configuration')
                ->schema([
                    ViewEntry::make('config')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->config;
                            if (! $state) {
                                return ['json' => 'No configuration data'];
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

            Section::make('Error Log')
                ->schema([
                    ViewEntry::make('error_log')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->error_log;
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
                ->visible(fn ($record) => ! empty($record->error_log))
                ->columnSpanFull(),
        ]);
    }
}
