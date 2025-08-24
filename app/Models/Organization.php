<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Organization extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'settings',
        'is_active',
    ];

    protected $casts = [
        'settings' => 'array',
        'is_active' => 'boolean',
    ];

    public function applications(): HasMany
    {
        return $this->hasMany(Application::class);
    }

    public function users()
    {
        return $this->hasManyThrough(User::class, Application::class, 'organization_id', 'id', 'id', 'id')
            ->join('user_applications', 'users.id', '=', 'user_applications.user_id')
            ->where('user_applications.application_id', '=', 'applications.id');
    }
}
