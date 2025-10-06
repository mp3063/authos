<?php

namespace Tests\Browser\Components;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Component as BaseComponent;

class FilamentNotification extends BaseComponent
{
    /**
     * Get the root selector for the component.
     */
    public function selector(): string
    {
        return '.fi-no-notification, [data-notification]';
    }

    /**
     * Assert that the browser page contains the component.
     */
    public function assert(Browser $browser): void
    {
        $browser->waitFor($this->selector(), 3);
    }

    /**
     * Get the element shortcuts for the component.
     */
    public function elements(): array
    {
        return [
            '@title' => '.fi-no-title',
            '@body' => '.fi-no-body',
            '@closeButton' => '.fi-no-close-btn',
            '@success' => '.fi-no-notification[data-type="success"]',
            '@error' => '.fi-no-notification[data-type="danger"]',
            '@warning' => '.fi-no-notification[data-type="warning"]',
            '@info' => '.fi-no-notification[data-type="info"]',
        ];
    }

    /**
     * Assert notification is visible.
     */
    public function assertVisible(Browser $browser, ?string $type = null): void
    {
        if ($type) {
            $browser->assertVisible("@{$type}");
        } else {
            $browser->assertVisible($this->selector());
        }
    }

    /**
     * Assert notification contains text.
     */
    public function assertContains(Browser $browser, string $text): void
    {
        $browser->assertSeeIn($this->selector(), $text);
    }

    /**
     * Close the notification.
     */
    public function close(Browser $browser): void
    {
        $browser->click('@closeButton')
            ->pause(200);
    }
}
