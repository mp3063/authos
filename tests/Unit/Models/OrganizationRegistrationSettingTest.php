<?php

namespace Tests\Unit\Models;

use App\Models\Organization;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class OrganizationRegistrationSettingTest extends TestCase
{
    /**
     * @return array<string, array{array<string, mixed>, bool}>
     */
    public static function settings(): array
    {
        return [
            'missing' => [[], true],
            'true' => [['allow_registration' => true], true],
            'string true' => [['allow_registration' => 'true'], true],
            'false' => [['allow_registration' => false], false],
            'string false' => [['allow_registration' => 'false'], false],
            'string zero' => [['allow_registration' => '0'], false],
        ];
    }

    #[Test]
    #[DataProvider('settings')]
    public function it_reads_the_allow_registration_setting_as_a_boolean(array $settings, bool $allowed): void
    {
        $organization = new Organization(['settings' => $settings]);

        $this->assertSame($allowed, $organization->allowsRegistration());
    }
}
