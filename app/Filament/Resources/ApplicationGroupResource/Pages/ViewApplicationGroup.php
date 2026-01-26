<?php

namespace App\Filament\Resources\ApplicationGroupResource\Pages;

use App\Filament\Resources\ApplicationGroupResource;
use App\Models\ApplicationGroup;
use Filament\Actions;
use Filament\Infolists\Components\RepeatableEntry;
use Filament\Infolists\Components\TextEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewApplicationGroup extends ViewRecord
{
    protected static string $resource = ApplicationGroupResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\EditAction::make(),
            Actions\DeleteAction::make()
                ->hidden(fn (ApplicationGroup $record): bool => $record->hasChildren()),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Group Information')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('name')
                                    ->weight(FontWeight::Bold),
                                TextEntry::make('organization.name')
                                    ->label('Organization')
                                    ->badge(),
                                TextEntry::make('parent.name')
                                    ->label('Parent Group')
                                    ->placeholder('Root Group'),
                                TextEntry::make('is_active')
                                    ->label('Status')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'Active' : 'Inactive')
                                    ->color(fn ($state) => $state ? 'success' : 'danger'),
                            ]),
                        TextEntry::make('full_path')
                            ->label('Hierarchy Path')
                            ->getStateUsing(fn (ApplicationGroup $record): string => $record->getFullPath())
                            ->icon('heroicon-o-arrows-right-left')
                            ->columnSpanFull(),
                        TextEntry::make('description')
                            ->placeholder('No description provided')
                            ->columnSpanFull(),
                    ]),

                Section::make('Applications')
                    ->schema([
                        RepeatableEntry::make('applications')
                            ->schema([
                                TextEntry::make('name')
                                    ->weight(FontWeight::Bold),
                            ])
                            ->placeholder('No applications assigned')
                            ->columnSpanFull(),
                    ]),

                Section::make('Child Groups')
                    ->schema([
                        RepeatableEntry::make('children')
                            ->schema([
                                TextEntry::make('name')
                                    ->weight(FontWeight::Bold),
                                TextEntry::make('is_active')
                                    ->label('Status')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'Active' : 'Inactive')
                                    ->color(fn ($state) => $state ? 'success' : 'danger'),
                            ])
                            ->placeholder('No child groups')
                            ->columns(2)
                            ->columnSpanFull(),
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
