<?php

namespace App\Filament\Widgets;

use App\Filament\Concerns\ScopesToOrganization;
use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\User;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Support\Enums\TextSize;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget as BaseWidget;
use Illuminate\Database\Eloquent\Builder;

class UserActivityWidget extends BaseWidget
{
    use ScopesToOrganization;

    protected static ?string $heading = 'Recent User Activity';

    protected static ?int $sort = 2;

    protected int|string|array $columnSpan = 'full';

    protected static bool $isLazy = false;

    public function table(Table $table): Table
    {
        $user = Filament::auth()->user();

        return $table
            ->query(
                $this->scopedLogs()
                    ->with(['user', 'application'])
                    ->latest()
                    ->limit(50)
            )
            ->columns($this->tableColumns($user))
            ->filters($this->tableFilters())
            ->recordActions($this->tableRecordActions())
            ->defaultSort('created_at', 'desc')
            ->striped()
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(25)
            ->poll('30s');
    }

    public static function canView(): bool
    {
        return Filament::auth()->user()?->hasOrganizationPermission('users.read') === true;
    }

    private function scopedLogs(): Builder
    {
        $query = AuthenticationLog::query();

        if (static::canChooseOrganization()) {
            return $query;
        }

        $organizationId = Filament::auth()->user()?->organization_id;

        if ($organizationId === null) {
            return $query->whereRaw('1 = 0');
        }

        return $query->where(function (Builder $scoped) use ($organizationId) {
            $scoped->whereHas('application', fn (Builder $related) => $related->where('organization_id', $organizationId))
                ->orWhereHas('user', fn (Builder $related) => $related->where('organization_id', $organizationId));
        });
    }

    private function tableColumns(User $user): array
    {
        return [
            TextColumn::make('created_at')
                ->label('Time')
                ->dateTime('M d, H:i:s')
                ->sortable()
                ->size(TextSize::ExtraSmall),

            TextColumn::make('event')
                ->badge()
                ->color(fn ($record) => $record->getEventBadgeColor())
                ->icon(fn ($record) => $record->getEventIcon())
                ->size(TextSize::Small),

            TextColumn::make('user.name')
                ->label('User')
                ->placeholder('System')
                ->limit(25)
                ->tooltip(fn ($record) => $record->user?->email)
                ->url(fn ($record) => $record->user && $user->can('viewAny', User::class) ?
                    route('filament.admin.resources.users.view', $record->user->id) : null)
                ->color('primary')
                ->weight('medium'),

            TextColumn::make('application.name')
                ->label('Application')
                ->placeholder('N/A')
                ->badge()
                ->color('gray')
                ->limit(20)
                ->url(fn ($record) => $record->application && $user->can('viewAny', Application::class) ?
                    route('filament.admin.resources.applications.view', $record->application->id) : null),

            TextColumn::make('ip_address')
                ->label('IP Address')
                ->copyable()
                ->icon('heroicon-o-globe-alt')
                ->color('gray')
                ->size(TextSize::Small),

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
                ->size(TextSize::Small),

            TextColumn::make('user_agent')
                ->label('Device')
                ->formatStateUsing(fn ($state) => $this->deviceLabel($state))
                ->badge()
                ->color(fn ($state) => match (true) {
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
                ->color(fn ($state) => match ($state) {
                    'Low' => 'success',
                    'Medium' => 'warning',
                    'High' => 'danger',
                    default => 'gray'
                }),
        ];
    }

    private function deviceLabel(mixed $state): string
    {
        if (! $state) {
            return 'Unknown';
        }

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
    }

    private function tableFilters(): array
    {
        return [
            SelectFilter::make('event')
                ->options([
                    'login_success' => 'Login',
                    'logout' => 'Logout',
                    'login_failed' => 'Failed Login',
                    'failed_mfa' => 'Failed MFA',
                    'password_reset' => 'Password Reset',
                    'suspicious_activity' => 'Suspicious Activity',
                ])
                ->multiple(),

            SelectFilter::make('application_id')
                ->label('Application')
                ->relationship('application', 'name', fn (Builder $query) => static::scopeToOrganization($query))
                ->searchable()
                ->preload(),

            SelectFilter::make('user_id')
                ->label('User')
                ->relationship('user', 'name', fn (Builder $query) => static::scopeToOrganization($query))
                ->searchable()
                ->preload(),
        ];
    }

    private function tableRecordActions(): array
    {
        return [
            Action::make('view_details')
                ->icon('heroicon-o-eye')
                ->color('gray')
                ->tooltip('View Details')
                ->modalHeading(fn ($record) => 'Activity Details - '.ucfirst($record->event))
                ->modalContent(fn ($record) => view('filament.widgets.modals.activity-details', ['record' => $record]))
                ->modalSubmitAction(false)
                ->modalCancelAction(false),
        ];
    }

    protected function calculateRiskScore($record): string
    {
        $score = 0;

        // Event-based scoring
        switch ($record->event) {
            case 'login_failed':
            case 'failed_mfa':
                $score += 50;
                break;
            case 'suspicious_activity':
                $score += 80;
                break;
            case 'password_reset':
                $score += 30;
                break;
            case 'login_success':
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
        if (! $record->user_id) {
            return false;
        }

        // Check if this is the user's first login from this IP in the last 30 days
        $previousLogins = AuthenticationLog::where('user_id', $record->user_id)
            ->where('ip_address', $record->ip_address)
            ->where('event', 'login_success')
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
