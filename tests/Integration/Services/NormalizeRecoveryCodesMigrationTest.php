<?php

namespace Tests\Integration\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class NormalizeRecoveryCodesMigrationTest extends IntegrationTestCase
{
    #[Test]
    public function it_decodes_double_encoded_recovery_codes_once_and_leaves_others_untouched(): void
    {
        $doubleEncoded = User::factory()->create();
        $singleEncoded = User::factory()->create(['two_factor_recovery_codes' => ['EFGH5678']]);
        DB::table('users')->where('id', $doubleEncoded->id)
            ->update(['two_factor_recovery_codes' => json_encode(json_encode(['ABCD1234']))]);

        (require database_path('migrations/2026_10_07_163350_normalize_double_encoded_recovery_codes.php'))->up();

        $this->assertSame(['ABCD1234'], $doubleEncoded->fresh()->two_factor_recovery_codes);
        $this->assertSame(['EFGH5678'], $singleEncoded->fresh()->two_factor_recovery_codes);
    }
}
