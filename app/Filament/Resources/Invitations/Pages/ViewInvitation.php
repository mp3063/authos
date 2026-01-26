<?php

namespace App\Filament\Resources\Invitations\Pages;

use App\Filament\Resources\Invitations\InvitationResource;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class ViewInvitation extends ViewRecord
{
    protected static string $resource = InvitationResource::class;

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
                Section::make('Invitation Details')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('email')
                                    ->icon('heroicon-o-envelope')
                                    ->copyable(),
                                TextEntry::make('organization.name')
                                    ->label('Organization')
                                    ->badge(),
                                TextEntry::make('role')
                                    ->badge()
                                    ->color('info'),
                                TextEntry::make('status')
                                    ->badge()
                                    ->color(fn (string $state): string => match ($state) {
                                        'pending' => 'warning',
                                        'accepted' => 'success',
                                        'declined' => 'danger',
                                        'cancelled' => 'gray',
                                        default => 'gray',
                                    }),
                                TextEntry::make('inviter.name')
                                    ->label('Invited By')
                                    ->placeholder('System'),
                                TextEntry::make('expires_at')
                                    ->dateTime()
                                    ->label('Expires At'),
                            ]),
                    ]),

                Section::make('Response Details')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('acceptedBy.name')
                                    ->label('Accepted By')
                                    ->placeholder('Not accepted'),
                                TextEntry::make('accepted_at')
                                    ->dateTime()
                                    ->placeholder('Not accepted'),
                                TextEntry::make('declined_at')
                                    ->dateTime()
                                    ->placeholder('Not declined'),
                                TextEntry::make('decline_reason')
                                    ->placeholder('N/A'),
                                TextEntry::make('cancelledBy.name')
                                    ->label('Cancelled By')
                                    ->placeholder('Not cancelled'),
                                TextEntry::make('cancelled_at')
                                    ->dateTime()
                                    ->placeholder('Not cancelled'),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(fn ($record) => $record->status === 'pending'),

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
