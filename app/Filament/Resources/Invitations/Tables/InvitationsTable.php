<?php

namespace App\Filament\Resources\Invitations\Tables;

use App\Services\InvitationService;
use Filament\Actions\Action;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class InvitationsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('email')
                    ->label('Email')
                    ->searchable()
                    ->sortable(),

                TextColumn::make('organization.name')
                    ->label('Organization')
                    ->searchable()
                    ->sortable(),

                TextColumn::make('role')
                    ->label('Role')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'Organization Owner' => 'danger',
                        'Organization Admin' => 'warning',
                        'User Manager', 'Application Manager' => 'info',
                        default => 'gray',
                    }),

                TextColumn::make('inviter.name')
                    ->label('Invited By')
                    ->searchable(),

                TextColumn::make('status')
                    ->label('Status')
                    ->state(fn ($record) => $record->isPending() ? 'Pending' : ($record->isExpired() ? 'Expired' : 'Accepted'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'Pending' => 'warning',
                        'Expired' => 'danger',
                        'Accepted' => 'success',
                    }),

                TextColumn::make('expires_at')
                    ->label('Expires')
                    ->dateTime()
                    ->sortable(),

                TextColumn::make('accepted_at')
                    ->label('Accepted At')
                    ->dateTime()
                    ->placeholder('Not accepted')
                    ->sortable(),

                TextColumn::make('created_at')
                    ->label('Sent At')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('status')
                    ->options([
                        'pending' => 'Pending',
                        'expired' => 'Expired',
                        'accepted' => 'Accepted',
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        if (! $data['value']) {
                            return $query;
                        }

                        return match ($data['value']) {
                            'pending' => $query->pending(),
                            'expired' => $query->expired(),
                            'accepted' => $query->accepted(),
                            default => $query,
                        };
                    }),

                SelectFilter::make('organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload(),
            ])
            ->recordActions([
                Action::make('resend')
                    ->label('Resend')
                    ->icon('heroicon-o-arrow-path')
                    ->color('warning')
                    ->visible(fn ($record) => $record->isPending())
                    ->action(function ($record) {
                        $invitationService = app(InvitationService::class);
                        $invitationService->resendInvitation($record->id, auth()->user());

                        \Filament\Notifications\Notification::make()
                            ->title('Invitation Resent')
                            ->success()
                            ->send();
                    }),

                EditAction::make(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make(),
                ]),
            ])
            ->defaultSort('created_at', 'desc');
    }
}
