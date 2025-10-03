<?php

namespace App\Filament\Resources\SocialAccounts\Tables;

use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\ImageColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class SocialAccountsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                ImageColumn::make('avatar')
                    ->label('Avatar')
                    ->circular()
                    ->defaultImageUrl(fn ($record) => 'https://ui-avatars.com/api/?name='.urlencode($record->name ?? 'User')),

                TextColumn::make('user.name')
                    ->label('User')
                    ->searchable()
                    ->sortable()
                    ->url(fn ($record) => route('filament.admin.resources.users.edit', ['record' => $record->user_id])),

                TextColumn::make('provider')
                    ->label('Provider')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'google' => 'danger',
                        'github' => 'gray',
                        'facebook' => 'info',
                        'twitter' => 'primary',
                        'linkedin' => 'success',
                        default => 'warning',
                    })
                    ->formatStateUsing(fn (string $state): string => match ($state) {
                        'google' => 'Google',
                        'github' => 'GitHub',
                        'facebook' => 'Facebook',
                        'twitter' => 'Twitter',
                        'linkedin' => 'LinkedIn',
                        default => ucfirst($state),
                    })
                    ->searchable()
                    ->sortable(),

                TextColumn::make('email')
                    ->label('Provider Email')
                    ->searchable()
                    ->toggleable(),

                TextColumn::make('name')
                    ->label('Provider Name')
                    ->searchable()
                    ->toggleable(),

                IconColumn::make('token_expired')
                    ->label('Token Status')
                    ->boolean()
                    ->trueIcon('heroicon-o-x-circle')
                    ->falseIcon('heroicon-o-check-circle')
                    ->trueColor('danger')
                    ->falseColor('success')
                    ->getStateUsing(fn ($record) => $record->isTokenExpired()),

                TextColumn::make('created_at')
                    ->label('Connected At')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(),

                TextColumn::make('updated_at')
                    ->label('Updated At')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('provider')
                    ->options([
                        'google' => 'Google',
                        'github' => 'GitHub',
                        'facebook' => 'Facebook',
                        'twitter' => 'Twitter',
                        'linkedin' => 'LinkedIn',
                    ]),
            ])
            ->recordActions([
                ViewAction::make(),
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
