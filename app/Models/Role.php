<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Spatie\Permission\Models\Role as SpatieRole;

class Role extends SpatieRole
{
    /**
     * Define the relationship to Organization
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
