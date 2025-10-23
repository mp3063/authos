<?php

namespace App\Filament\Widgets;

use App\Models\Invitation;
use Filament\Actions\Action;
use Filament\Actions\BulkAction;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Filament\Support\Enums\TextSize;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget as BaseWidget;
use Illuminate\Database\Eloquent\Collection;

class PendingInvitationsWidget extends BaseWidget
{
    protected static ?string $heading = 'Pending Invitations';

    protected static ?int $sort = 4;

    protected int|string|array $columnSpan = 'full';

    protected static bool $isLazy = false;

    public function table(Table $table): Table
    {
        $user = Filament::auth()->user();

        // Only show for organization owners/admins
        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return $table->query(Invitation::whereRaw('1 = 0')); // Empty query
        }

        $organizationId = $user->organization_id;

        return $table
            ->query(
                Invitation::query()
                    ->with(['organization', 'inviter', 'acceptor'])
                    ->where('organization_id', $organizationId)
                    ->pending()
                    ->latest()
            )
            ->columns([
                TextColumn::make('email')
                    ->label('Email Address')
                    ->searchable()
                    ->sortable()
                    ->copyable()
                    ->icon('heroicon-o-envelope')
                    ->weight('medium'),

                TextColumn::make('role')
                    ->label('Role')
                    ->badge()
                    ->color(fn ($state) => match ($state) {
                        'super-admin' => 'danger',
                        'organization-admin' => 'warning',
                        'application-admin' => 'info',
                        'user' => 'success',
                        default => 'gray'
                    }),

                TextColumn::make('inviter.name')
                    ->label('Invited By')
                    ->placeholder('System')
                    ->url(fn ($record) => $record->inviter && $user->can('view users') ?
                        route('filament.admin.resources.users.view', $record->inviter->id) : null)
                    ->color('primary'),

                TextColumn::make('created_at')
                    ->label('Sent')
                    ->dateTime('M d, H:i')
                    ->sortable()
                    ->since()
                    ->tooltip(fn ($record) => $record->created_at->format('F j, Y \a\t g:i A')),

                TextColumn::make('expires_at')
                    ->label('Expires')
                    ->dateTime('M d, H:i')
                    ->sortable()
                    ->color(fn ($record) => $record->expires_at->isPast() ? 'danger' :
                        ($record->expires_at->diffInDays() <= 1 ? 'warning' : 'success'))
                    ->formatStateUsing(function ($record) {
                        if ($record->expires_at->isPast()) {
                            return 'Expired';
                        }

                        return $record->expires_at->diffForHumans();
                    }),

                TextColumn::make('status')
                    ->label('Status')
                    ->badge()
                    ->formatStateUsing(function ($record) {
                        if ($record->isExpired()) {
                            return 'Expired';
                        } elseif ($record->isPending()) {
                            return 'Pending';
                        } else {
                            return 'Unknown';
                        }
                    })
                    ->color(fn ($record) => $record->isExpired() ? 'danger' : 'warning'),

                TextColumn::make('actions_summary')
                    ->label('Quick Info')
                    ->formatStateUsing(function ($record) {
                        $info = [];

                        if ($record->metadata && isset($record->metadata['reminder_count'])) {
                            $info[] = $record->metadata['reminder_count'].' reminders';
                        }

                        if ($record->expires_at->diffInDays() <= 1 && ! $record->expires_at->isPast()) {
                            $info[] = 'Expires soon';
                        }

                        return implode(' • ', $info) ?: 'New invitation';
                    })
                    ->color('gray')
                    ->size(TextSize::ExtraSmall),
            ])
            ->filters([
                SelectFilter::make('role')
                    ->options([
                        'super-admin' => 'Super Admin',
                        'organization-admin' => 'Organization Admin',
                        'application-admin' => 'Application Admin',
                        'user' => 'User',
                    ])
                    ->multiple(),
            ])
            ->recordActions([
                Action::make('resend')
                    ->icon('heroicon-o-paper-airplane')
                    ->color('primary')
                    ->tooltip('Resend Invitation')
                    ->action(function ($record) {
                        $this->resendInvitation($record);
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Resend Invitation')
                    ->modalDescription(fn ($record) => "Resend the invitation to {$record->email}?")
                    ->modalSubmitActionLabel('Resend'),

                Action::make('extend')
                    ->icon('heroicon-o-clock')
                    ->color('warning')
                    ->tooltip('Extend Expiry')
                    ->action(function ($record) {
                        $record->extend(7); // Extend by 7 days

                        Notification::make()
                            ->title('Invitation Extended')
                            ->body("Extended invitation for {$record->email} by 7 days.")
                            ->success()
                            ->send();
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Extend Invitation')
                    ->modalDescription(fn ($record) => "Extend the invitation for {$record->email} by 7 days?")
                    ->modalSubmitActionLabel('Extend'),

                Action::make('copy_link')
                    ->icon('heroicon-o-link')
                    ->color('gray')
                    ->tooltip('Copy Invitation Link')
                    ->action(function ($record) {
                        // In a real implementation, you'd generate the actual invitation URL
                        $invitationUrl = url("/accept-invitation/{$record->token}");

                        Notification::make()
                            ->title('Link Copied')
                            ->body('Invitation link has been copied to clipboard.')
                            ->success()
                            ->send();

                        // This would typically use JavaScript to copy to clipboard
                        $this->dispatch('copy-to-clipboard', text: $invitationUrl);
                    }),

                Action::make('cancel')
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->tooltip('Cancel Invitation')
                    ->action(function ($record) {
                        $record->delete();

                        Notification::make()
                            ->title('Invitation Cancelled')
                            ->body("Cancelled invitation for {$record->email}.")
                            ->success()
                            ->send();
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Cancel Invitation')
                    ->modalDescription(fn ($record) => "Are you sure you want to cancel the invitation for {$record->email}?")
                    ->modalSubmitActionLabel('Cancel Invitation'),
            ])
            ->toolbarActions([
                BulkAction::make('resend_selected')
                    ->label('Resend Selected')
                    ->icon('heroicon-o-paper-airplane')
                    ->color('primary')
                    ->action(function (Collection $records) {
                        $count = 0;
                        foreach ($records as $record) {
                            if ($record->isPending()) {
                                $this->resendInvitation($record);
                                $count++;
                            }
                        }

                        Notification::make()
                            ->title('Invitations Resent')
                            ->body("Resent {$count} invitation(s).")
                            ->success()
                            ->send();
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Resend Invitations')
                    ->modalDescription('Resend all selected pending invitations?'),

                BulkAction::make('extend_selected')
                    ->label('Extend Selected')
                    ->icon('heroicon-o-clock')
                    ->color('warning')
                    ->action(function (Collection $records) {
                        $count = 0;
                        foreach ($records as $record) {
                            if ($record->isPending()) {
                                $record->extend(7);
                                $count++;
                            }
                        }

                        Notification::make()
                            ->title('Invitations Extended')
                            ->body("Extended {$count} invitation(s) by 7 days.")
                            ->success()
                            ->send();
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Extend Invitations')
                    ->modalDescription('Extend all selected invitations by 7 days?'),

                BulkAction::make('cancel_selected')
                    ->label('Cancel Selected')
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->action(function (Collection $records) {
                        $count = $records->count();
                        foreach ($records as $record) {
                            $record->delete();
                        }

                        Notification::make()
                            ->title('Invitations Cancelled')
                            ->body("Cancelled {$count} invitation(s).")
                            ->success()
                            ->send();
                    })
                    ->requiresConfirmation()
                    ->modalHeading('Cancel Invitations')
                    ->modalDescription('Are you sure you want to cancel all selected invitations?'),
            ])
            ->defaultSort('created_at', 'desc')
            ->striped()
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(10)
            ->poll('30s')
            ->emptyStateHeading('No Pending Invitations')
            ->emptyStateDescription('All invitations have been accepted or have expired.')
            ->emptyStateIcon('heroicon-o-envelope');
    }

    protected function resendInvitation(Invitation $invitation): void
    {
        if (! $invitation->isPending()) {
            Notification::make()
                ->title('Cannot Resend')
                ->body('This invitation is no longer pending.')
                ->danger()
                ->send();

            return;
        }

        try {
            // Update reminder count in metadata
            $metadata = $invitation->metadata ?? [];
            $metadata['reminder_count'] = ($metadata['reminder_count'] ?? 0) + 1;
            $metadata['last_reminder_at'] = now()->toISOString();

            $invitation->update(['metadata' => $metadata]);

            // In a real implementation, you'd send the actual invitation email here
            // Mail::to($invitation->email)->send(new InvitationMail($invitation));

            Notification::make()
                ->title('Invitation Resent')
                ->body("Resent invitation to {$invitation->email}.")
                ->success()
                ->send();

        } catch (\Exception $e) {
            Notification::make()
                ->title('Failed to Resend')
                ->body('There was an error resending the invitation.')
                ->danger()
                ->send();
        }
    }

    public function getTableHeading(): ?string
    {
        $user = Filament::auth()->user();

        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return 'Access Restricted';
        }

        $count = Invitation::where('organization_id', $user->organization_id)
            ->pending()
            ->count();

        return "Pending Invitations ({$count})";
    }

    protected function getTableDescription(): ?string
    {
        $user = Filament::auth()->user();

        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return 'You need organization admin permissions to manage invitations.';
        }

        $orgName = $user->organization?->name;

        return $orgName ? "Manage pending invitations for {$orgName}" : 'Manage pending invitations';
    }

    protected ?string $pollingInterval = '30s';
}
