<?php

namespace App\Repositories\Contracts;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

/**
 * Base repository interface
 */
interface BaseRepositoryInterface
{
    /**
     * Find model by ID
     */
    public function find(int $id): ?Model;

    /**
     * Find model by ID or fail
     */
    public function findOrFail(int $id): Model;

    /**
     * Get all models
     */
    public function all(): Collection;

    /**
     * Get paginated results
     */
    public function paginate(array $filters = [], int $perPage = 15): LengthAwarePaginator;

    /**
     * Create new model
     */
    public function create(array $data): Model;

    /**
     * Update model
     */
    public function update(Model $model, array $data): Model;

    /**
     * Delete model
     */
    public function delete(Model $model): bool;

    /**
     * Find models by criteria
     */
    public function findBy(string $field, mixed $value): Collection;

    /**
     * Find first model by criteria
     */
    public function findFirstBy(string $field, mixed $value): ?Model;

    /**
     * Count models
     */
    public function count(array $filters = []): int;

    /**
     * Check if model exists
     */
    public function exists(int $id): bool;
}
