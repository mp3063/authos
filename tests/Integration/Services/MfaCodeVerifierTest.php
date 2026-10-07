<?php

namespace Tests\Integration\Services;

use App\Services\Auth\MfaCodeVerifier;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class MfaCodeVerifierTest extends IntegrationTestCase
{
    #[Test]
    public function it_consumes_a_recovery_code_stored_as_a_json_string(): void
    {
        $user = $this->createUser();
        $user->update(['two_factor_recovery_codes' => json_encode(['ABCD1234', 'EFGH5678'])]);

        $verified = app(MfaCodeVerifier::class)->verifyAndConsumeRecoveryCode($user->fresh(), 'abcd1234');

        $this->assertTrue($verified);
        $this->assertSame(['EFGH5678'], $user->fresh()->mfa_backup_codes);
    }

    #[Test]
    public function it_rejects_an_unknown_recovery_code(): void
    {
        $user = $this->createUser();
        $user->update(['two_factor_recovery_codes' => ['ABCD1234']]);

        $verified = app(MfaCodeVerifier::class)->verifyAndConsumeRecoveryCode($user->fresh(), 'ZZZZ9999');

        $this->assertFalse($verified);
        $this->assertSame(['ABCD1234'], $user->fresh()->mfa_backup_codes);
    }
}
