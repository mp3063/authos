<?php

namespace Tests\Integration\Security;

use App\Models\Organization;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\Migration\Importers\OrganizationImporter;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class PlanFollowUpFixesTest extends IntegrationTestCase
{
    #[Test]
    public function it_gives_imported_auth0_organizations_a_unique_slug(): void
    {
        $dto = fn (string $id, string $name) => new Auth0OrganizationDTO($id, $name, 'Acme Corp', [], []);

        $result = (new OrganizationImporter)->import([
            $dto('org_1', 'Acme Corp'),
            $dto('org_2', 'acme-corp'),
        ]);

        $this->assertSame(2, $result->getSuccessCount());
        $this->assertSame(
            ['acme-corp', 'acme-corp-2'],
            Organization::orderBy('id')->pluck('slug')->all()
        );
    }
}
