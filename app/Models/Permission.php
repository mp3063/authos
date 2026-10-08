<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Spatie\Permission\Models\Permission as SpatiePermission;

class Permission extends SpatiePermission
{
    public const POLICY_ABILITY_NAMES = [
        'viewAny', 'view', 'create', 'update', 'delete', 'deleteAny',
        'restore', 'restoreAny', 'forceDelete', 'forceDeleteAny',
        'replicate', 'reorder', 'attach', 'attachAny', 'detach', 'detachAny',
        'associate', 'associateAny', 'dissociate', 'dissociateAny',
    ];

    /**
     * Define the relationship to Organization
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
