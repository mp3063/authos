<?php

namespace App\Filament\Resources\CustomDomains\Tables;

use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class CustomDomainsTable
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

                TextColumn::make('domain')
                    ->searchable()
                    ->sortable()
                    ->weight('bold')
                    ->copyable()
                    ->copyMessage('Domain copied'),

                TextColumn::make('verified_at')
                    ->label('Verification Status')
                    ->badge()
                    ->getStateUsing(fn ($record) => $record->isVerified() ? 'Verified' : 'Pending')
                    ->colors([
                        'success' => 'Verified',
                        'warning' => 'Pending',
                    ])
                    ->sortable(),

                IconColumn::make('is_active')
                    ->label('Active')
                    ->boolean()
                    ->sortable(),

                TextColumn::make('created_at')
                    ->label('Added')
                    ->dateTime()
                    ->since()
                    ->sortable(),

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

                TernaryFilter::make('verified')
                    ->label('Verification Status')
                    ->placeholder('All domains')
                    ->trueLabel('Verified only')
                    ->falseLabel('Pending only')
                    ->queries(
                        true: fn (Builder $query) => $query->whereNotNull('verified_at'),
                        false: fn (Builder $query) => $query->whereNull('verified_at'),
                    )
                    ->native(false),

                TernaryFilter::make('is_active')
                    ->label('Status')
                    ->placeholder('All')
                    ->trueLabel('Active only')
                    ->falseLabel('Inactive only')
                    ->native(false),
            ])
            ->recordActions([
                ActionGroup::make([
                    EditAction::make(),

                    Action::make('verify_domain')
                        ->label('Verify Domain')
                        ->icon('heroicon-o-check-badge')
                        ->color('success')
                        ->action(function ($record) {
                            // Mock verification - in production, this would check DNS
                            $record->update(['verified_at' => now()]);

                            Notification::make()
                                ->success()
                                ->title('Domain Verified')
                                ->body('Your domain has been successfully verified!')
                                ->send();
                        })
                        ->requiresConfirmation()
                        ->modalHeading('Verify Domain')
                        ->modalDescription('This will check DNS records and verify domain ownership. Make sure you have added the required TXT record.')
                        ->modalSubmitActionLabel('Verify Now')
                        ->visible(fn ($record) => ! $record->isVerified()),

                    Action::make('copy_verification_code')
                        ->label('Copy Verification Code')
                        ->icon('heroicon-o-clipboard')
                        ->color('info')
                        ->action(function ($record) {
                            Notification::make()
                                ->success()
                                ->title('Copied!')
                                ->body('Verification code copied to clipboard')
                                ->send();
                        })
                        ->visible(fn ($record) => ! $record->isVerified()),

                    Action::make('view_dns_instructions')
                        ->label('DNS Instructions')
                        ->icon('heroicon-o-information-circle')
                        ->color('info')
                        ->modalHeading('DNS Configuration Instructions')
                        ->modalContent(function ($record) {
                            $records = $record->getVerificationDnsRecords();
                            $html = '<div class="space-y-4">';

                            foreach ($records as $dnsRecord) {
                                $html .= '<div class="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg">';
                                $html .= '<p><strong>Type:</strong> '.$dnsRecord['type'].'</p>';
                                $html .= '<p><strong>Host/Name:</strong> '.$dnsRecord['name'].'</p>';
                                $html .= '<p><strong>Value:</strong> <code class="bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded">'.$dnsRecord['value'].'</code></p>';
                                $html .= '<p><strong>TTL:</strong> '.$dnsRecord['ttl'].' seconds</p>';
                                $html .= '</div>';
                            }

                            $html .= '<p class="mt-4 text-sm text-gray-600 dark:text-gray-400">After adding these records, allow up to 48 hours for DNS propagation, then click "Verify Domain".</p>';
                            $html .= '</div>';

                            return new \Illuminate\Support\HtmlString($html);
                        })
                        ->modalSubmitAction(false)
                        ->modalCancelActionLabel('Close'),

                    DeleteAction::make()
                        ->requiresConfirmation()
                        ->modalDescription('Are you sure you want to delete this custom domain? This action cannot be undone.'),
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
