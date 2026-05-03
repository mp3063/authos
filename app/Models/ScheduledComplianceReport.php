<?php

namespace App\Models;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use InvalidArgumentException;

class ScheduledComplianceReport extends Model
{
    use HasFactory;

    public const FREQUENCY_DAILY = 'daily';

    public const FREQUENCY_WEEKLY = 'weekly';

    public const FREQUENCY_MONTHLY = 'monthly';

    public const FREQUENCY_QUARTERLY = 'quarterly';

    public const FREQUENCIES = [
        self::FREQUENCY_DAILY,
        self::FREQUENCY_WEEKLY,
        self::FREQUENCY_MONTHLY,
        self::FREQUENCY_QUARTERLY,
    ];

    protected $fillable = [
        'organization_id',
        'created_by_user_id',
        'report_type',
        'frequency',
        'recipients',
        'next_run_at',
        'last_run_at',
        'is_active',
    ];

    protected function casts(): array
    {
        return [
            'recipients' => 'array',
            'next_run_at' => 'datetime',
            'last_run_at' => 'datetime',
            'is_active' => 'boolean',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function createdBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by_user_id');
    }

    public function reports(): HasMany
    {
        return $this->hasMany(ComplianceReport::class, 'scheduled_report_id');
    }

    public function computeNextRunAt(?CarbonInterface $from = null): Carbon
    {
        $base = $from ? Carbon::instance($from) : Carbon::now();

        return match ($this->frequency) {
            self::FREQUENCY_DAILY => $base->copy()->addDay(),
            self::FREQUENCY_WEEKLY => $base->copy()->addWeek(),
            self::FREQUENCY_MONTHLY => $base->copy()->addMonth(),
            self::FREQUENCY_QUARTERLY => $base->copy()->addMonths(3),
            default => throw new InvalidArgumentException("Unknown frequency: {$this->frequency}"),
        };
    }

    public function scopeDue(Builder $query): Builder
    {
        return $query->where('is_active', true)->where('next_run_at', '<=', now());
    }

    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }
}
