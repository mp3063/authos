<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

class UserApplication extends Pivot
{
    protected $table = 'user_applications';
    
    protected $fillable = [
        'user_id',
        'application_id',
        'permissions',
        'metadata',
        'last_login_at',
        'login_count',
        'granted_at',
        'granted_by',
    ];

    protected $casts = [
        'permissions' => 'array',
        'metadata' => 'array',
        'last_login_at' => 'datetime',
        'granted_at' => 'datetime',
    ];
}
