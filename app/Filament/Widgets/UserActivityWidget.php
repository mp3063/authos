<?php

namespace App\Filament\Widgets;

use App\Models\AuthenticationLog;
use App\Models\User;
use Filament\Facades\Filament;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget as BaseWidget;
use Filament\Tables\Actions\Action;
use Filament\Tables\Filters\SelectFilter;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Cache;

class UserActivityWidget extends BaseWidget
{
    protected static ?string $heading = 'Recent User Activity';

    protected static ?int $sort = 2;

    protected int|string|array $columnSpan = 'full';

    protected static bool $isLazy = false;

    public function table(Table $table): Table
    {
        $user = Filament::auth()->user();
        
        // Only show for organization owners/admins
        if (!$user->isOrganizationOwner() && !$user->isOrganizationAdmin()) {
            return $table->query(AuthenticationLog::whereRaw('1 = 0')); // Empty query
        }

        $organizationId = $user->organization_id;

        return $table
            ->query(
                AuthenticationLog::query()
                    ->with(['user', 'application'])
                    ->whereHas('application', function ($query) use ($organizationId) {
                        $query->where('organization_id', $organizationId);
                    })
                    ->orWhereHas('user', function ($query) use ($organizationId) {
                        $query->where('organization_id', $organizationId);
                    })
                    ->latest()
                    ->limit(50)
            )
            ->columns([
                TextColumn::make('created_at')
                    ->label('Time')
                    ->dateTime('M d, H:i:s')
                    ->sortable()
                    ->size(TextColumn\TextColumnSize::ExtraSmall),

                TextColumn::make('event')
                    ->badge()
                    ->color(fn($record) => $record->getEventBadgeColor())
                    ->icon(fn($record) => $record->getEventIcon())
                    ->size(TextColumn\TextColumnSize::Small),

                TextColumn::make('user.name')
                    ->label('User')
                    ->placeholder('System')
                    ->limit(25)
                    ->tooltip(fn($record) => $record->user?->email)
                    ->url(fn($record) => $record->user && $user->can('view users') ? 
                        route('filament.admin.resources.users.view', $record->user->id) : null)
                    ->color('primary')
                    ->weight('medium'),

                TextColumn::make('application.name')
                    ->label('Application')
                    ->placeholder('N/A')
                    ->badge()
                    ->color('gray')
                    ->limit(20)
                    ->url(fn($record) => $record->application && $user->can('view applications') ? 
                        route('filament.admin.resources.applications.view', $record->application->id) : null),

                TextColumn::make('ip_address')
                    ->label('IP Address')
                    ->copyable()
                    ->icon('heroicon-o-globe-alt')
                    ->color('gray')
                    ->size(TextColumn\TextColumnSize::Small),

                TextColumn::make('location')
                    ->label('Location')
                    ->formatStateUsing(function ($record) {
                        // Simple location formatting based on IP or user agent
                        if ($record->metadata && isset($record->metadata['location'])) {
                            return $record->metadata['location'];
                        }
                        return 'Unknown';
                    })
                    ->icon('heroicon-o-map-pin')
                    ->color('gray')
                    ->size(TextColumn\TextColumnSize::Small),

                TextColumn::make('user_agent')
                    ->label('Device')
                    ->formatStateUsing(function ($state) {
                        if (!$state) {
                            return 'Unknown';
                        }

                        // Enhanced user agent parsing
                        if (str_contains($state, 'Mobile') || str_contains($state, 'Android') || str_contains($state, 'iPhone')) {
                            return 'Mobile';
                        } elseif (str_contains($state, 'iPad') || str_contains($state, 'Tablet')) {
                            return 'Tablet';
                        } elseif (str_contains($state, 'Chrome')) {
                            return 'Chrome';
                        } elseif (str_contains($state, 'Firefox')) {
                            return 'Firefox';
                        } elseif (str_contains($state, 'Safari')) {
                            return 'Safari';
                        } elseif (str_contains($state, 'Edge')) {
                            return 'Edge';
                        } else {
                            return 'Desktop';
                        }
                    })
                    ->badge()
                    ->color(fn($state) => match(true) {
                        str_contains($state, 'Mobile') => 'info',
                        str_contains($state, 'Tablet') => 'warning',
                        default => 'gray'
                    }),

                TextColumn::make('risk_score')
                    ->label('Risk')
                    ->formatStateUsing(function ($record) {
                        return $this->calculateRiskScore($record);
                    })
                    ->badge()
                    ->color(fn($state) => match($state) {
                        'Low' => 'success',
                        'Medium' => 'warning',
                        'High' => 'danger',
                        default => 'gray'
                    }),
            ])
            ->filters([
                SelectFilter::make('event')
                    ->options([
                        'login' => 'Login',
                        'logout' => 'Logout',
                        'failed_login' => 'Failed Login',
                        'failed_mfa' => 'Failed MFA',
                        'password_reset' => 'Password Reset',
                        'suspicious_activity' => 'Suspicious Activity',
                    ])
                    ->multiple(),
                
                SelectFilter::make('application_id')
                    ->label('Application')
                    ->relationship('application', 'name')
                    ->searchable()
                    ->preload(),

                SelectFilter::make('user_id')
                    ->label('User')
                    ->relationship('user', 'name')
                    ->searchable()
                    ->preload(),
            ])
            ->actions([
                Action::make('view_details')
                    ->icon('heroicon-o-eye')
                    ->color('gray')
                    ->tooltip('View Details')
                    ->modalHeading(fn($record) => 'Activity Details - ' . ucfirst($record->event))
                    ->modalContent(fn($record) => view('filament.widgets.modals.activity-details', ['record' => $record]))
                    ->modalSubmitAction(false)
                    ->modalCancelAction(false),
            ])
            ->defaultSort('created_at', 'desc')
            ->striped()
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(25)
            ->poll('30s');
    }

    protected function calculateRiskScore($record): string
    {
        $score = 0;
        
        // Event-based scoring
        switch ($record->event) {
            case 'failed_login':
            case 'failed_mfa':
                $score += 50;
                break;
            case 'suspicious_activity':
                $score += 80;
                break;
            case 'password_reset':
                $score += 30;
                break;
            case 'login':
                // Check for unusual patterns
                if ($this->isUnusualLogin($record)) {
                    $score += 40;
                }
                break;
        }
        
        // Time-based scoring (late night/early morning)
        $hour = (int) $record->created_at->format('H');
        if ($hour < 6 || $hour > 22) {
            $score += 20;
        }
        
        // IP-based scoring (simple check for known patterns)
        if ($this->isSuspiciousIP($record->ip_address)) {
            $score += 30;
        }
        
        if ($score >= 70) {
            return 'High';
        } elseif ($score >= 40) {
            return 'Medium';
        } else {
            return 'Low';
        }
    }

    protected function isUnusualLogin($record): bool
    {
        if (!$record->user_id) {
            return false;
        }

        // Check if this is the user's first login from this IP in the last 30 days
        $previousLogins = AuthenticationLog::where('user_id', $record->user_id)
            ->where('ip_address', $record->ip_address)
            ->where('event', 'login')
            ->where('created_at', '>=', now()->subDays(30))
            ->where('id', '!=', $record->id)
            ->count();

        return $previousLogins === 0;
    }

    protected function isSuspiciousIP($ip): bool
    {
        // Simple checks for obviously suspicious patterns
        // In production, you'd integrate with threat intelligence feeds
        $suspiciousPatterns = [
            '10.0.0.', // Private ranges might be suspicious in some contexts
            '192.168.', // Local network
            // Add more patterns as needed
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (str_starts_with($ip, $pattern)) {
                return false; // Actually, private IPs are usually safe
            }
        }

        return false; // Default to not suspicious without proper threat intel
    }

    protected function getTableRecordsPerPageSelectOptions(): array
    {
        return [10, 25, 50, 100];
    }
}