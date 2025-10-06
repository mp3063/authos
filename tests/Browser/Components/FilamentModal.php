<?php

namespace Tests\Browser\Components;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Component as BaseComponent;

class FilamentModal extends BaseComponent
{
    /**
     * Get the root selector for the component.
     */
    public function selector(): string
    {
        return '.fi-modal, [role="dialog"]';
    }

    /**
     * Assert that the browser page contains the component.
     */
    public function assert(Browser $browser): void
    {
        $browser->waitFor($this->selector(), 3)
            ->assertVisible($this->selector());
    }

    /**
     * Get the element shortcuts for the component.
     */
    public function elements(): array
    {
        return [
            '@title' => '.fi-modal-heading, [data-modal-title]',
            '@content' => '.fi-modal-content',
            '@closeButton' => '.fi-modal-close, button[aria-label="Close"]',
            '@submitButton' => 'button[type="submit"]',
            '@cancelButton' => 'button:contains("Cancel")',
            '@errorMessage' => '.fi-fo-field-wrp-error-message',
        ];
    }

    /**
     * Fill in a form field.
     */
    public function fillField(Browser $browser, string $name, string $value): void
    {
        $browser->type("input[name=\"{$name}\"]", $value);
    }

    /**
     * Select a value.
     */
    public function select(Browser $browser, string $name, string $value): void
    {
        $browser->select("select[name=\"{$name}\"]", $value);
    }

    /**
     * Submit the modal form.
     */
    public function submit(Browser $browser): void
    {
        $browser->click('@submitButton')
            ->pause(500);
    }

    /**
     * Close the modal.
     */
    public function close(Browser $browser): void
    {
        $browser->click('@closeButton')
            ->pause(300);
    }

    /**
     * Cancel the modal.
     */
    public function cancel(Browser $browser): void
    {
        $browser->click('@cancelButton')
            ->pause(300);
    }
}
