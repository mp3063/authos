<?php

namespace Tests\Feature\Filament\Concerns;

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

    protected function forcePageAction(Testable $component, string $name): Testable
    {
        return $component
            ->call('mountAction', $name)
            ->call('callMountedAction');
    }
}
