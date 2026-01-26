<?php

namespace App\Filament\Resources\WebhookEventResource\Pages;

use App\Filament\Resources\WebhookEventResource;
use Filament\Infolists\Components\IconEntry;
use Filament\Infolists\Components\TextEntry;
use Filament\Infolists\Components\ViewEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Illuminate\Support\Str;

class ViewWebhookEvent extends ViewRecord
{
    protected static string $resource = WebhookEventResource::class;

    protected function getHeaderActions(): array
    {
        return [
            // Read-only resource, no header actions needed
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Event Details')
                ->schema([
                    TextEntry::make('name')
                        ->label('Event Name')
                        ->copyable()
                        ->weight('bold'),

                    TextEntry::make('category')
                        ->badge()
                        ->formatStateUsing(fn (string $state): string => Str::title(str_replace('_', ' ', $state)))
                        ->color(fn (string $state): string => match ($state) {
                            'authentication' => 'success',
                            'user' => 'info',
                            'organization' => 'warning',
                            'application' => 'primary',
                            'security' => 'danger',
                            'webhook' => 'gray',
                            'sso' => 'success',
                            'mfa' => 'warning',
                            'billing' => 'primary',
                            default => 'gray',
                        }),

                    TextEntry::make('version')
                        ->badge()
                        ->color('gray'),

                    IconEntry::make('is_active')
                        ->label('Active')
                        ->boolean()
                        ->trueIcon('heroicon-o-check-circle')
                        ->falseIcon('heroicon-o-x-circle')
                        ->trueColor('success')
                        ->falseColor('danger'),

                    TextEntry::make('description')
                        ->label('Description')
                        ->columnSpanFull(),

                    TextEntry::make('created_at')
                        ->label('Created')
                        ->dateTime(),

                    TextEntry::make('updated_at')
                        ->label('Last Updated')
                        ->dateTime(),
                ])
                ->columns(2),

            Section::make('Payload Schema')
                ->schema([
                    ViewEntry::make('payload_schema')
                        ->label('')
                        ->view('components.json-display-simple')
                        ->viewData(function ($record) {
                            $state = $record->payload_schema;
                            if (! $state) {
                                return ['json' => 'No schema defined'];
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
