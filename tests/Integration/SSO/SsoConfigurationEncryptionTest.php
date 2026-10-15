<?php

namespace Tests\Integration\SSO;

use App\Models\SSOConfiguration;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoConfigurationEncryptionTest extends IntegrationTestCase
{
    #[Test]
    public function it_stores_the_sso_configuration_encrypted(): void
    {
        $config = SSOConfiguration::factory()->oidc()->create([
            'configuration' => ['client_id' => 'cid', 'client_secret' => 's3cr3t'],
        ]);

        $raw = DB::table('sso_configurations')->where('id', $config->id)->value('configuration');

        $this->assertStringNotContainsString('s3cr3t', $raw);
        $this->assertNull(json_decode($raw, true));
        $this->assertSame('s3cr3t', $config->fresh()->configuration['client_secret']);
    }

    #[Test]
    public function it_still_updates_saml_certificates_on_an_encrypted_configuration(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'api');
        $application = $this->createOAuthApplication(['organization_id' => $owner->organization_id]);
        $config = SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'configuration' => ['x509_cert' => 'old-cert', 'entity_id' => 'https://idp.example.com'],
        ]);

        $this->actingAsApiUserWithToken($owner, ['sso'])
            ->postJson("/api/v1/sso/saml/certificates/{$config->id}", ['x509_cert' => 'new-cert'])
            ->assertOk();

        $this->actingAsApiUserWithToken($owner, ['sso'])
            ->postJson("/api/v1/sso/saml/certificates/{$config->id}", ['x509_cert' => 'sp-cert', 'cert_type' => 'sp'])
            ->assertOk();

        $configuration = $config->fresh()->configuration;
        $this->assertSame('new-cert', $configuration['x509_cert']);
        $this->assertSame('sp-cert', $configuration['sp_x509_cert']);
        $this->assertSame('https://idp.example.com', $configuration['entity_id']);
        $this->assertStringNotContainsString('new-cert', DB::table('sso_configurations')->where('id', $config->id)->value('configuration'));
    }

    #[Test]
    public function it_encrypts_existing_plain_json_rows_on_migrate_and_restores_them_on_rollback(): void
    {
        $config = SSOConfiguration::factory()->create(['configuration' => null]);
        $plain = json_encode(['client_id' => 'cid', 'client_secret' => 's3cr3t']);
        DB::table('sso_configurations')->where('id', $config->id)->update(['configuration' => $plain]);
        $nullConfig = SSOConfiguration::factory()->create(['configuration' => null]);

        $migration = $this->migration();
        $migration->up();

        $raw = DB::table('sso_configurations')->where('id', $config->id)->value('configuration');
        $this->assertStringNotContainsString('s3cr3t', $raw);
        $this->assertSame($plain, Crypt::decryptString($raw));
        $this->assertSame('s3cr3t', $config->fresh()->configuration['client_secret']);
        $this->assertNull($nullConfig->fresh()->configuration);

        $migration->up();
        $this->assertSame('s3cr3t', $config->fresh()->configuration['client_secret']);

        $migration->down();
        $this->assertSame($plain, DB::table('sso_configurations')->where('id', $config->id)->value('configuration'));
        $this->assertNull(DB::table('sso_configurations')->where('id', $nullConfig->id)->value('configuration'));

        $migration->up();
    }

    private function migration(): Migration
    {
        return require database_path('migrations/2026_10_14_000001_encrypt_sso_configurations_configuration.php');
    }
}
