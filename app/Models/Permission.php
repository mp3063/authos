<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Spatie\Permission\Models\Permission as SpatiePermission;

class Permission extends SpatiePermission
{
    /**
     * Define the relationship to Organization
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
