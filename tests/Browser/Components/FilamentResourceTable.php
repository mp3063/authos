<?php

namespace Tests\Browser\Components;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Component as BaseComponent;

class FilamentResourceTable extends BaseComponent
{
    /**
     * Get the root selector for the component.
     */
    public function selector(): string
    {
        return '.fi-ta-table, [data-filament-table]';
    }

    /**
     * Assert that the browser page contains the component.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertVisible($this->selector());
    }

    /**
     * Get the element shortcuts for the component.
     */
    public function elements(): array
    {
        return [
            '@search' => 'input[type="search"]',
            '@row' => 'tbody tr',
            '@firstRow' => 'tbody tr:first-child',
            '@viewAction' => 'button[title="View"], a[title="View"]',
            '@editAction' => 'button[title="Edit"], a[title="Edit"]',
            '@deleteAction' => 'button[title="Delete"]',
            '@bulkActions' => '[data-bulk-actions]',
            '@pagination' => '.fi-ta-pagination',
            '@emptyState' => '.fi-ta-empty-state',
        ];
    }

    /**
     * Search for a record.
     */
    public function search(Browser $browser, string $query): void
    {
        $browser->type('@search', $query)
            ->pause(500);
    }

    /**
     * Click on a row action.
     */
    public function clickRowAction(Browser $browser, string $action, int $rowIndex = 1): void
    {
        $browser->click("tbody tr:nth-child({$rowIndex}) button[title=\"{$action}\"]")
            ->pause(300);
    }

    /**
     * Get row count.
     */
    public function getRowCount(Browser $browser): int
    {
        return count($browser->elements('@row'));
    }

    /**
     * Assert table has records.
     */
    public function assertHasRecords(Browser $browser): void
    {
        $browser->assertMissing('@emptyState');
    }

    /**
     * Assert table is empty.
     */
    public function assertEmpty(Browser $browser): void
    {
        $browser->assertVisible('@emptyState');
    }
}
