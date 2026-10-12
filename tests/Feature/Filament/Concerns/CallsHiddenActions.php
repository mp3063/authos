<?php

namespace Tests\Feature\Filament\Concerns;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Livewire\Features\SupportTesting\Testable;

trait CallsHiddenActions
{
    /**
     * @param  array<string, mixed>  $data
     */
    protected function forceTableAction(Testable $component, string $name, Model $record, array $data = []): Testable
    {
        $component->call('mountTableAction', $name, $record->getKey());

        foreach ($data as $key => $value) {
            $component->set("mountedActions.0.data.{$key}", $value);
        }

        return $component->call('callMountedTableAction');
    }

    protected function forceTableBulkAction(Testable $component, string $name, array $records): Testable
    {
        return $component
            ->set('selectedTableRecords', array_map(fn (Model $record) => (string) $record->getKey(), $records))
            ->call('mountAction', $name, [], ['table' => true, 'bulk' => true])
            ->call('callMountedAction');
    }

    protected function forcePageAction(Testable $component, string $name): Testable
    {
        return $component
            ->call('mountAction', $name)
            ->call('callMountedAction');
    }

    /**
     * @param  list<string>  $permissions
     */
    protected function createUserWithCustomPermissions(Organization $organization, array $permissions): User
    {
        $user = $this->createUser(['organization_id' => $organization->id], 'User', 'web');
        CustomRole::factory()->forOrganization($organization)->create(['permissions' => $permissions])->assignToUser($user);

        return $user;
    }
}
