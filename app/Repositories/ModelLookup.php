<?php

namespace App\Repositories;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

class ModelLookup
{
    public function __construct(private Model $model) {}

    public function findBy(string $field, mixed $value): Collection
    {
        return $this->model->newQuery()->where($field, $value)->get();
    }

    public function findFirstBy(string $field, mixed $value): ?Model
    {
        return $this->model->newQuery()->where($field, $value)->first();
    }

    public function exists(int $id): bool
    {
        return $this->model->newQuery()->where('id', $id)->exists();
    }
}
