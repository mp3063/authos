<?php

namespace App\Filament\Resources\SecurityIncidentResource\Pages;

use App\Filament\Resources\SecurityIncidentResource;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewSecurityIncident extends ViewRecord
{
    protected static string $resource = SecurityIncidentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            // Read-only resource, no header actions needed
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            TextEntry::make('type')
                ->label('Incident Type')
                ->formatStateUsing(fn ($state) => ucwords(str_replace('_', ' ', $state)))
                ->badge(),

            TextEntry::make('severity')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'critical' => 'danger',
                    'high' => 'warning',
                    'medium' => 'info',
                    'low' => 'gray',
                    default => 'gray',
                }),

            TextEntry::make('status')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'open' => 'danger',
                    'investigating' => 'warning',
                    'resolved' => 'success',
                    'dismissed' => 'gray',
                    default => 'gray',
                }),

            TextEntry::make('detected_at')
                ->label('Detected At')
                ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A')),

            TextEntry::make('ip_address')
                ->label('IP Address')
                ->copyable()
                ->icon('heroicon-o-globe-alt'),

            TextEntry::make('user_agent')
                ->label('User Agent')
                ->limit(100)
                ->tooltip(fn ($record) => $record->user_agent),

            TextEntry::make('user.name')
                ->label('User')
                ->placeholder('System'),

            TextEntry::make('user.email')
                ->label('Email')
                ->placeholder('N/A'),

            TextEntry::make('endpoint')
                ->label('Endpoint')
                ->placeholder('N/A'),

            TextEntry::make('description')
                ->label('Description')
                ->columnSpanFull(),

            Section::make('Resolution')
                ->schema([
                    TextEntry::make('resolved_at')
                        ->label('Resolved At')
                        ->formatStateUsing(fn ($state) => $state?->format('M j, Y \a\t g:i A'))
                        ->placeholder('Not resolved'),

                    TextEntry::make('resolution_notes')
                        ->label('Resolution Notes')
                        ->placeholder('None'),

                    TextEntry::make('action_taken')
                        ->label('Action Taken')
                        ->placeholder('None'),
                ])
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
                ->columnSpanFull(),
        ]);
    }
}
