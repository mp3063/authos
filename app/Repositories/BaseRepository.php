<?php

namespace App\Repositories;

use App\Repositories\Contracts\BaseRepositoryInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

/**
 * Base repository implementation
 */
abstract class BaseRepository implements BaseRepositoryInterface
{
    protected Model $model;

    public function __construct(Model $model)
    {
        $this->model = $model;
    }

    /**
     * Get the model instance
     */
    public function getModel(): Model
    {
        return $this->model;
    }

    /**
     * Get a fresh query builder instance
     */
    protected function query(): Builder
    {
        return $this->model->newQuery();
    }

    /**
     * Find model by ID
     */
    public function find(int $id): ?Model
    {
        return $this->query()->find($id);
    }

    /**
     * Find model by ID or fail
     */
    public function findOrFail(int $id): Model
    {
        return $this->query()->findOrFail($id);
    }

    /**
     * Get all models
     */
    public function all(): Collection
    {
        return $this->query()->get();
    }

    /**
     * Get paginated results
     */
    public function paginate(array $filters = [], int $perPage = 15): LengthAwarePaginator
    {
        $query = $this->query();

        $this->applyFilters($query, $filters);

        return $query->paginate($perPage);
    }

    /**
     * Create new model
     */
    public function create(array $data): Model
    {
        return $this->query()->create($data);
    }

    /**
     * Update model
     */
    public function update(Model $model, array $data): Model
    {
        $model->update($data);

        return $model->fresh();
    }

    /**
     * Delete model
     */
    public function delete(Model $model): bool
    {
        return $model->delete();
    }

    /**
     * Find models by criteria
     */
    public function findBy(string $field, $value): Collection
    {
        return $this->query()->where($field, $value)->get();
    }

    /**
     * Find first model by criteria
     */
    public function findFirstBy(string $field, $value): ?Model
    {
        return $this->query()->where($field, $value)->first();
    }

    /**
     * Count models
     */
    public function count(array $filters = []): int
    {
        $query = $this->query();

        $this->applyFilters($query, $filters);

        return $query->count();
    }

    /**
     * Check if model exists
     */
    public function exists(int $id): bool
    {
        return $this->query()->where('id', $id)->exists();
    }

    /**
     * Apply filters to query builder
     */
    protected function applyFilters(Builder $query, array $filters): void
    {
        foreach ($filters as $field => $value) {
            if ($value !== null && $value !== '') {
                $this->applyFilter($query, $field, $value);
            }
        }
    }

    /**
     * Apply individual filter
     */
    protected function applyFilter(Builder $query, string $field, $value): void
    {
        // Default implementation - can be overridden in child classes
        if (is_array($value)) {
            $query->whereIn($field, $value);
        } else {
            $query->where($field, $value);
        }
    }

    /**
     * Apply search to query
     */
    protected function applySearch(Builder $query, string $search, array $fields): void
    {
        if (empty($search) || empty($fields)) {
            return;
        }

        $query->where(function ($q) use ($search, $fields) {
            foreach ($fields as $field) {
                $q->orWhere($field, 'ILIKE', "%{$search}%");
            }
        });
    }

    /**
     * Apply sorting to query
     */
    protected function applySorting(Builder $query, string $sort = 'id', string $order = 'asc'): void
    {
        $allowedSortFields = $this->getAllowedSortFields();

        if (in_array($sort, $allowedSortFields)) {
            $query->orderBy($sort, $order === 'desc' ? 'desc' : 'asc');
        } else {
            $query->orderBy('id', 'asc');
        }
    }

    /**
     * Get allowed sort fields - override in child classes
     */
    protected function getAllowedSortFields(): array
    {
        return ['id', 'created_at', 'updated_at'];
    }
}
