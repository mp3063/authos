<?php

namespace App\Filament\Resources\OrganizationBrandingResource\Pages;

use App\Filament\Resources\OrganizationBrandingResource;
use Filament\Actions;
use Filament\Infolists\Components\ImageEntry;
use Filament\Infolists\Components\KeyValueEntry;
use Filament\Infolists\Components\TextEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewOrganizationBranding extends ViewRecord
{
    protected static string $resource = OrganizationBrandingResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\EditAction::make(),
            Actions\DeleteAction::make(),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Organization')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('organization.name')
                                    ->label('Organization')
                                    ->weight(FontWeight::Bold)
                                    ->badge(),
                                TextEntry::make('id')
                                    ->label('Branding ID'),
                            ]),
                    ]),

                Section::make('Branding Assets')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                ImageEntry::make('logo_path')
                                    ->label('Logo')
                                    ->disk('public')
                                    ->height(100)
                                    ->placeholder('No logo uploaded'),

                                ImageEntry::make('login_background_path')
                                    ->label('Login Background')
                                    ->disk('public')
                                    ->height(150)
                                    ->placeholder('No background uploaded'),
                            ]),
                    ]),

                Section::make('Colors')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('primary_color')
                                    ->label('Primary Color')
                                    ->badge()
                                    ->formatStateUsing(fn (?string $state): string => $state
                                        ? "\u{25CF} {$state}"
                                        : 'Not set')
                                    ->color(fn (?string $state): ?string => $state ? $state : null),

                                TextEntry::make('secondary_color')
                                    ->label('Secondary Color')
                                    ->badge()
                                    ->formatStateUsing(fn (?string $state): string => $state
                                        ? "\u{25CF} {$state}"
                                        : 'Not set')
                                    ->color(fn (?string $state): ?string => $state ? $state : null),
                            ]),
                    ]),

                Section::make('Custom CSS')
                    ->schema([
                        TextEntry::make('custom_css')
                            ->label('Custom CSS')
                            ->markdown()
                            ->placeholder('No custom CSS defined')
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(),

                Section::make('Email Templates')
                    ->schema([
                        KeyValueEntry::make('email_templates')
                            ->label('Email Templates')
                            ->placeholder('No email templates configured')
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(),

                Section::make('Additional Settings')
                    ->schema([
                        KeyValueEntry::make('settings')
                            ->label('Settings')
                            ->placeholder('No additional settings configured')
                            ->columnSpanFull(),
                    ])
                    ->collapsible()
                    ->collapsed(),

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
