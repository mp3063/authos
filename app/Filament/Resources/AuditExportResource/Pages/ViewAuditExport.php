<?php

namespace App\Filament\Resources\AuditExportResource\Pages;

use App\Filament\Resources\AuditExportResource;
use App\Models\AuditExport;
use Filament\Actions\Action;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewAuditExport extends ViewRecord
{
    protected static string $resource = AuditExportResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('download')
                ->label('Download Export')
                ->icon('heroicon-o-arrow-down-tray')
                ->color('success')
                ->url(fn (AuditExport $record): ?string => $record->download_url)
                ->openUrlInNewTab()
                ->visible(fn (AuditExport $record): bool => $record->isCompleted() && ! empty($record->file_path)),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Export Details')
                ->schema([
                    TextEntry::make('id')
                        ->label('Export ID'),

                    TextEntry::make('type')
                        ->label('Export Type')
                        ->formatStateUsing(fn ($state) => ucwords(str_replace('_', ' ', $state)))
                        ->badge(),

                    TextEntry::make('status')
                        ->badge()
                        ->color(fn (string $state): string => match ($state) {
                            'pending' => 'warning',
                            'processing' => 'info',
                            'completed' => 'success',
                            'failed' => 'danger',
                            default => 'gray',
                        }),

                    TextEntry::make('organization.name')
                        ->label('Organization')
                        ->badge(),

                    TextEntry::make('user.name')
                        ->label('Requested By')
                        ->placeholder('System'),

                    TextEntry::make('user.email')
                        ->label('Requester Email')
                        ->placeholder('N/A'),

                    TextEntry::make('records_count')
                        ->label('Records Exported')
                        ->numeric()
                        ->placeholder('N/A'),

                    TextEntry::make('started_at')
                        ->label('Started At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Not started'),

                    TextEntry::make('completed_at')
                        ->label('Completed At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Not completed'),

                    TextEntry::make('created_at')
                        ->label('Created At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),
                ])
                ->columns(2)
                ->columnSpanFull(),

            Section::make('Filters Applied')
                ->schema([
                    ViewEntry::make('filters')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->filters;
                            if (! $state) {
                                return ['json' => 'No filters applied'];
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

            Section::make('Error Information')
                ->schema([
                    TextEntry::make('error_message')
                        ->label('Error Message')
                        ->columnSpanFull()
                        ->placeholder('No errors'),
                ])
                ->collapsible()
                ->collapsed()
                ->visible(fn ($record) => $record->hasFailed() || ! empty($record->error_message))
                ->columnSpanFull(),

            Section::make('Download')
                ->schema([
                    TextEntry::make('file_path')
                        ->label('File Path')
                        ->placeholder('No file available'),

                    TextEntry::make('download_url')
                        ->label('Download Link')
                        ->url(fn ($record) => $record->download_url)
                        ->openUrlInNewTab()
                        ->placeholder('Not available')
                        ->visible(fn ($record) => $record->isCompleted() && ! empty($record->file_path)),
                ])
                ->collapsible()
                ->visible(fn ($record) => $record->isCompleted() && ! empty($record->file_path))
                ->columnSpanFull(),
        ]);
    }
}
