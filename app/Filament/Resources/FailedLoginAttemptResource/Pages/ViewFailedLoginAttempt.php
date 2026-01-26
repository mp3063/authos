<?php

namespace App\Filament\Resources\FailedLoginAttemptResource\Pages;

use App\Filament\Resources\FailedLoginAttemptResource;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewFailedLoginAttempt extends ViewRecord
{
    protected static string $resource = FailedLoginAttemptResource::class;

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Attempt Details')
                ->schema([
                    TextEntry::make('attempted_at')
                        ->label('Time')
                        ->formatStateUsing(fn ($state) => $state->format('M j, Y \a\t g:i:s A')),

                    TextEntry::make('email')
                        ->label('Email')
                        ->copyable(),

                    TextEntry::make('attempt_type')
                        ->label('Attempt Type')
                        ->badge()
                        ->color(fn ($state) => match ($state) {
                            'login' => 'primary',
                            'mfa' => 'warning',
                            'api' => 'info',
                            default => 'gray',
                        }),

                    TextEntry::make('failure_reason')
                        ->label('Failure Reason')
                        ->formatStateUsing(fn ($state) => ucwords(str_replace('_', ' ', $state))),
                ]),

            Section::make('Network Information')
                ->schema([
                    TextEntry::make('ip_address')
                        ->label('IP Address')
                        ->copyable()
                        ->icon('heroicon-o-globe-alt'),

                    TextEntry::make('user_agent')
                        ->label('User Agent')
                        ->limit(100)
                        ->tooltip(fn ($record) => $record->user_agent),
                ]),

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
