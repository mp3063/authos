<?php

namespace App\Filament\Resources\BulkImportJobResource\Pages;

use App\Filament\Resources\BulkImportJobResource;
use App\Models\BulkImportJob;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewBulkImportJob extends ViewRecord
{
    protected static string $resource = BulkImportJobResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('retry')
                ->label('Retry')
                ->icon('heroicon-o-arrow-path')
                ->color('info')
                ->requiresConfirmation()
                ->modalHeading('Retry Job')
                ->modalDescription('Are you sure you want to retry this failed job? The status will be reset to pending.')
                ->visible(fn (BulkImportJob $record) => $record->hasFailed())
                ->action(function (BulkImportJob $record) {
                    $record->update([
                        'status' => BulkImportJob::STATUS_PENDING,
                        'processed_records' => 0,
                        'successful_records' => 0,
                        'failed_records' => 0,
                        'errors' => null,
                        'started_at' => null,
                        'completed_at' => null,
                        'processing_time' => null,
                    ]);

                    Notification::make()
                        ->title('Job queued for retry')
                        ->body("Job #{$record->id} has been reset to pending.")
                        ->success()
                        ->send();

                    $this->refreshFormData([
                        'status',
                        'processed_records',
                        'successful_records',
                        'failed_records',
                        'started_at',
                        'completed_at',
                    ]);
                }),

            Actions\Action::make('cancel')
                ->label('Cancel')
                ->icon('heroicon-o-x-circle')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('Cancel Job')
                ->modalDescription('Are you sure you want to cancel this job? This action cannot be undone.')
                ->visible(fn (BulkImportJob $record) => $record->isInProgress())
                ->action(function (BulkImportJob $record) {
                    $record->markAsCancelled();

                    Notification::make()
                        ->title('Job cancelled')
                        ->body("Job #{$record->id} has been cancelled.")
                        ->success()
                        ->send();

                    $this->refreshFormData([
                        'status',
                        'completed_at',
                    ]);
                }),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Job Overview')
                ->schema([
                    TextEntry::make('id')
                        ->label('Job ID'),

                    TextEntry::make('type')
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'import' => 'primary',
                            'export' => 'success',
                            'users' => 'info',
                            default => 'gray',
                        })
                        ->formatStateUsing(fn (string $state): string => ucfirst($state)),

                    TextEntry::make('status')
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'pending' => 'warning',
                            'processing' => 'info',
                            'completed' => 'success',
                            'completed_with_errors' => 'warning',
                            'failed' => 'danger',
                            'cancelled' => 'gray',
                            default => 'gray',
                        })
                        ->formatStateUsing(fn (string $state): string => ucwords(str_replace('_', ' ', $state))),

                    TextEntry::make('organization.name')
                        ->label('Organization')
                        ->badge(),

                    TextEntry::make('createdBy.name')
                        ->label('Created By')
                        ->placeholder('N/A'),

                    TextEntry::make('createdBy.email')
                        ->label('Creator Email')
                        ->placeholder('N/A'),
                ])
                ->columns(3),

            Section::make('Progress')
                ->schema([
                    TextEntry::make('progress_percentage')
                        ->label('Progress')
                        ->state(fn (BulkImportJob $record): string => $record->getProgressPercentage() . '%')
                        ->badge()
                        ->color(fn (BulkImportJob $record): string => match (true) {
                            $record->getProgressPercentage() >= 100 => 'success',
                            $record->getProgressPercentage() >= 50 => 'info',
                            $record->getProgressPercentage() > 0 => 'warning',
                            default => 'gray',
                        })
                        ->size(TextEntry\TextEntrySize::Large),

                    TextEntry::make('total_records')
                        ->label('Total Records')
                        ->numeric(),

                    TextEntry::make('processed_records')
                        ->label('Processed Records')
                        ->numeric(),

                    TextEntry::make('successful_records')
                        ->label('Successful Records')
                        ->numeric()
                        ->color('success'),

                    TextEntry::make('failed_records')
                        ->label('Failed Records')
                        ->numeric()
                        ->color('danger'),

                    TextEntry::make('valid_records')
                        ->label('Valid Records')
                        ->numeric()
                        ->color('success'),

                    TextEntry::make('invalid_records')
                        ->label('Invalid Records')
                        ->numeric()
                        ->color('danger'),
                ])
                ->columns(4),

            Section::make('File Information')
                ->schema([
                    TextEntry::make('file_format')
                        ->label('File Format')
                        ->badge()
                        ->formatStateUsing(fn (?string $state): string => $state ? strtoupper($state) : 'N/A')
                        ->color('info'),

                    TextEntry::make('formatted_file_size')
                        ->label('File Size')
                        ->state(fn (BulkImportJob $record): string => $record->formatted_file_size),

                    TextEntry::make('file_path')
                        ->label('File Path')
                        ->placeholder('No file')
                        ->limit(60)
                        ->tooltip(fn ($record) => $record->file_path),

                    TextEntry::make('error_file_path')
                        ->label('Error File Path')
                        ->placeholder('No error file')
                        ->limit(60)
                        ->tooltip(fn ($record) => $record->error_file_path),

                    TextEntry::make('format')
                        ->label('Export Format')
                        ->placeholder('N/A')
                        ->badge()
                        ->formatStateUsing(fn (?string $state): string => $state ? strtoupper($state) : 'N/A'),

                    TextEntry::make('export_type')
                        ->label('Export Type')
                        ->placeholder('N/A')
                        ->formatStateUsing(fn (?string $state): string => $state ? ucfirst($state) : 'N/A'),
                ])
                ->columns(3),

            Section::make('Timing')
                ->schema([
                    TextEntry::make('created_at')
                        ->label('Created At')
                        ->dateTime()
                        ->sinceTooltip(),

                    TextEntry::make('started_at')
                        ->label('Started At')
                        ->dateTime()
                        ->placeholder('Not started')
                        ->sinceTooltip(),

                    TextEntry::make('completed_at')
                        ->label('Completed At')
                        ->dateTime()
                        ->placeholder('Not completed')
                        ->sinceTooltip(),

                    TextEntry::make('processing_time')
                        ->label('Processing Time')
                        ->formatStateUsing(fn (?int $state): string => $state ? "{$state} seconds" : 'N/A'),
                ])
                ->columns(4),

            Section::make('Validation Errors')
                ->schema([
                    ViewEntry::make('errors')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->errors;
                            if (! $state || (is_array($state) && empty($state))) {
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
                ->collapsed(fn (BulkImportJob $record): bool => empty($record->errors))
                ->columnSpanFull(),

            Section::make('Validation Report')
                ->schema([
                    ViewEntry::make('validation_report')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->validation_report;
                            if (! $state || (is_array($state) && empty($state))) {
                                return ['json' => 'No validation report'];
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
                ->collapsed(fn (BulkImportJob $record): bool => empty($record->validation_report))
                ->columnSpanFull(),

            Section::make('Options')
                ->schema([
                    ViewEntry::make('options')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->options;
                            if (! $state || (is_array($state) && empty($state))) {
                                return ['json' => 'No options configured'];
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
