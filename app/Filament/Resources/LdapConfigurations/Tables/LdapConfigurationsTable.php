<?php

namespace App\Filament\Resources\LdapConfigurations\Tables;

use App\Jobs\SyncLdapUsersJob;
use App\Services\LdapAuthService;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class LdapConfigurationsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('organization.name')
                    ->label('Organization')
                    ->searchable()
                    ->sortable()
                    ->weight('medium'),

                TextColumn::make('name')
                    ->searchable()
                    ->sortable()
                    ->weight('bold'),

                TextColumn::make('connection_info')
                    ->label('Connection')
                    ->getStateUsing(fn ($record) => $record->host.':'.$record->port)
                    ->icon('heroicon-o-server')
                    ->copyable()
                    ->copyMessage('Connection info copied'),

                IconColumn::make('use_ssl')
                    ->label('SSL')
                    ->boolean()
                    ->sortable(),

                IconColumn::make('is_active')
                    ->label('Enabled')
                    ->boolean()
                    ->sortable(),

                TextColumn::make('last_sync_at')
                    ->label('Last Sync')
                    ->dateTime()
                    ->since()
                    ->sortable()
                    ->placeholder('Never'),

                TextColumn::make('sync_status')
                    ->label('Sync Status')
                    ->badge()
                    ->color(fn (?string $state): string => match ($state) {
                        'pending' => 'warning',
                        'processing' => 'info',
                        'completed' => 'success',
                        'failed' => 'danger',
                        default => 'gray',
                    })
                    ->icon(fn (?string $state): ?string => match ($state) {
                        'pending' => 'heroicon-o-clock',
                        'processing' => 'heroicon-o-arrow-path',
                        'completed' => 'heroicon-o-check-circle',
                        'failed' => 'heroicon-o-x-circle',
                        default => null,
                    })
                    ->placeholder('Never synced')
                    ->sortable(),

                TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('updated_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload()
                    ->multiple(),

                TernaryFilter::make('is_active')
                    ->label('Status')
                    ->placeholder('All configurations')
                    ->trueLabel('Enabled only')
                    ->falseLabel('Disabled only')
                    ->native(false),

                TernaryFilter::make('use_ssl')
                    ->label('SSL Enabled')
                    ->placeholder('All')
                    ->trueLabel('SSL enabled')
                    ->falseLabel('No SSL')
                    ->native(false),

                TernaryFilter::make('has_synced')
                    ->label('Synchronization')
                    ->placeholder('All')
                    ->trueLabel('Has been synced')
                    ->falseLabel('Never synced')
                    ->queries(
                        true: fn (Builder $query) => $query->whereNotNull('last_sync_at'),
                        false: fn (Builder $query) => $query->whereNull('last_sync_at'),
                    ),
            ])
            ->recordActions([
                ActionGroup::make([
                    ViewAction::make(),

                    EditAction::make(),

                    Action::make('test_connection')
                        ->label('Test Connection')
                        ->icon('heroicon-o-signal')
                        ->color('info')
                        ->action(function ($record) {
                            try {
                                $result = app(LdapAuthService::class)->testConnection($record);

                                Notification::make()
                                    ->success()
                                    ->title('Connection Successful')
                                    ->body("Found {$result['user_count']} users")
                                    ->send();
                            } catch (\Exception $e) {
                                Notification::make()
                                    ->danger()
                                    ->title('Connection Failed')
                                    ->body($e->getMessage())
                                    ->send();
                            }
                        })
                        ->requiresConfirmation()
                        ->modalHeading('Test LDAP Connection')
                        ->modalDescription('This will attempt to connect to the LDAP server with the configured credentials.')
                        ->modalSubmitActionLabel('Test Now'),

                    Action::make('sync_users')
                        ->label('Sync Users')
                        ->icon('heroicon-o-arrow-path')
                        ->color('success')
                        ->action(function ($record) {
                            $record->update(['sync_status' => 'pending']);
                            SyncLdapUsersJob::dispatch($record);

                            Notification::make()
                                ->success()
                                ->title('Sync Started')
                                ->body('User synchronization has been queued')
                                ->send();
                        })
                        ->requiresConfirmation()
                        ->modalHeading('Synchronize Users')
                        ->modalDescription('This will sync users from the LDAP server to your organization.')
                        ->modalSubmitActionLabel('Start Sync')
                        ->visible(fn ($record) => $record->is_active),

                    DeleteAction::make()
                        ->requiresConfirmation()
                        ->modalDescription('Are you sure you want to delete this LDAP configuration? Users authenticated via this server will need to be manually managed.'),
                ]),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make()
                        ->requiresConfirmation(),
                ]),
            ])
            ->defaultSort('created_at', 'desc');
    }
}
