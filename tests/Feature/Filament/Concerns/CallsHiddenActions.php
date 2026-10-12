<?php

namespace Tests\Feature\Filament\Concerns;

use Illuminate\Database\Eloquent\Model;
use Livewire\Features\SupportTesting\Testable;

trait CallsHiddenActions
{
    protected function forceTableAction(Testable $component, string $name, Model $record): Testable
    {
        return $component
            ->call('mountTableAction', $name, $record->getKey())
            ->call('callMountedTableAction');
    }

    protected function forcePageAction(Testable $component, string $name): Testable
    {
        return $component
            ->call('mountAction', $name)
            ->call('callMountedAction');
    }
}
