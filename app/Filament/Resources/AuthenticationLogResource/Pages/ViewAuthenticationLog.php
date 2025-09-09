<?php

namespace App\Filament\Resources\AuthenticationLogResource\Pages;

use App\Filament\Resources\AuthenticationLogResource;
use Filament\Schemas\Components\Section;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Support\Components\HtmlString;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Schema;

class ViewAuthenticationLog extends ViewRecord
{
    protected static string $resource = AuthenticationLogResource::class;

    protected function getHeaderActions(): array
    {
        return [
            // Add any header actions here if needed
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            TextEntry::make('event')
                ->label('Event Type')
                ->formatStateUsing(fn ($state) => ucwords(str_replace('_', ' ', $state)))
                ->badge()
                ->color(fn($record) => $record->getEventBadgeColor()),
            
            TextEntry::make('created_at')
                ->label('Timestamp')
                ->formatStateUsing(fn ($state) => $state->format('M j, Y \a\t g:i A')),
            
            TextEntry::make('ip_address')
                ->label('IP Address')
                ->copyable()
                ->icon('heroicon-o-globe-alt'),
            
            TextEntry::make('user_agent')
                ->label('User Agent')
                ->limit(100)
                ->tooltip(fn($record) => $record->user_agent),
            
            TextEntry::make('user.name')
                ->label('User')
                ->placeholder('System'),
            
            TextEntry::make('user.email')
                ->label('Email')
                ->placeholder('N/A'),
            
            TextEntry::make('application.name')
                ->label('Application')
                ->placeholder('N/A')
                ->badge(),
            
            TextEntry::make('user.organization.name')
                ->label('Organization')
                ->placeholder('N/A'),
            
            Section::make('Event Details')
                ->headerActions([
                    \Filament\Actions\Action::make('copyJson')
                        ->label('Copy JSON')
                        ->icon('heroicon-o-clipboard')
                        ->color('gray')
                        ->size('sm')
                        ->url('javascript:void(0)')
                        ->extraAttributes([
                            'onclick' => 'copyJsonContent(); event.preventDefault(); return false;'
                        ]),
                ])
                ->schema([
                    ViewEntry::make('details')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->details;
                            if (!$state) return ['json' => 'None'];
                            
                            // If it's already a string (JSON), decode it first
                            if (is_string($state)) {
                                $decoded = json_decode($state, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    $formatted = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                                    return ['json' => trim($formatted)];
                                }
                            }
                            
                            // If it's already an array, encode it
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