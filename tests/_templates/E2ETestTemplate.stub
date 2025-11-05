<?php

namespace Tests\Integration\{Category};

use Tests\Integration\IntegrationTestCase;

/**
 * Template for End-to-End Integration Tests
 *
 * E2E tests verify complete user flows by making real HTTP requests
 * and verifying both responses and side effects.
 *
 * Key principles:
 * 1. Test complete flows (multiple HTTP requests in sequence)
 * 2. Verify HTTP responses (status, headers, JSON structure)
 * 3. Verify side effects (database, logs, events, notifications)
 * 4. Use descriptive test names that describe business scenarios
 * 5. Follow Arrange-Act-Assert pattern
 *
 * @group integration
 * @group e2e
 * @group {category}
 */
class ExampleFlowTest extends IntegrationTestCase
{
    /**
     * Test a complete flow with multiple steps
     *
     * @test
     */
    public function complete_flow_with_descriptive_name()
    {
        // ============================================================
        // ARRANGE: Set up test data
        // ============================================================
        $user = $this->createUser([
            'email' => 'test@example.com',
        ]);

        $organization = $this->createOrganization([
            'name' => 'Test Organization',
        ]);

        $application = $this->createApplication([
            'name' => 'Test App',
            'organization_id' => $organization->id,
        ]);

        // ============================================================
        // ACT 1: First HTTP request
        // ============================================================
        $firstResponse = $this->actingAs($user)
            ->postJson('/api/v1/endpoint', [
                'key' => 'value',
            ]);

        // ============================================================
        // ASSERT 1: Verify first response
        // ============================================================
        $firstResponse->assertOk();
        $firstResponse->assertJsonStructure([
            'data' => [
                'id',
                'attribute',
            ],
        ]);

        // Extract data for next step
        $resourceId = $firstResponse->json('data.id');

        // ============================================================
        // ACT 2: Second HTTP request (using data from first)
        // ============================================================
        $secondResponse = $this->actingAs($user)
            ->getJson("/api/v1/endpoint/{$resourceId}");

        // ============================================================
        // ASSERT 2: Verify second response
        // ============================================================
        $secondResponse->assertOk();

        // ============================================================
        // ASSERT 3: Verify side effects
        // ============================================================

        // Database state
        $this->assertDatabaseHas('table_name', [
            'user_id' => $user->id,
            'status' => 'active',
        ]);

        // Authentication logs
        $this->assertAuthenticationLogged([
            'user_id' => $user->id,
            'event_type' => 'action_performed',
        ]);

        // Notifications
        $this->assertNotificationSentTo($user, \App\Notifications\SomeNotification::class);

        // Webhook deliveries
        $this->assertWebhookDeliveryCreated([
            'event_type' => 'resource.created',
        ]);
    }

    /**
     * Test error handling in the flow
     *
     * @test
     */
    public function flow_handles_error_scenario_correctly()
    {
        // ARRANGE: Set up scenario that will cause error
        $user = $this->createUser();

        // ACT: Perform action that should fail
        $response = $this->actingAs($user)
            ->postJson('/api/v1/endpoint', [
                'invalid' => 'data',
            ]);

        // ASSERT: Verify error response
        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['field_name']);

        // ASSERT: Verify no side effects occurred
        $this->assertDatabaseMissing('table_name', [
            'user_id' => $user->id,
        ]);
    }

    /**
     * Test authorization requirements
     *
     * @test
     */
    public function flow_requires_authentication()
    {
        // ACT: Attempt action without authentication
        $response = $this->postJson('/api/v1/endpoint', [
            'key' => 'value',
        ]);

        // ASSERT: Verify authentication required
        $response->assertUnauthorized();
    }

    /**
     * Test authorization requirements for specific role
     *
     * @test
     */
    public function flow_requires_specific_permission()
    {
        // ARRANGE: Create user without required permission
        $user = $this->createUser([], 'User');

        // ACT: Attempt action
        $response = $this->actingAs($user)
            ->postJson('/api/v1/endpoint', [
                'key' => 'value',
            ]);

        // ASSERT: Verify permission denied
        $response->assertForbidden();
    }

    /**
     * Test organization boundary enforcement
     *
     * @test
     */
    public function flow_enforces_organization_boundaries()
    {
        // ARRANGE: Create two organizations
        $org1 = $this->createOrganization();
        $org2 = $this->createOrganization();

        $userOrg1 = $this->createUser(['organization_id' => $org1->id]);
        $resourceOrg2 = $this->createApplication(['organization_id' => $org2->id]);

        // ACT: User from Org1 tries to access Org2 resource
        $response = $this->actingAs($userOrg1)
            ->getJson("/api/v1/applications/{$resourceOrg2->id}");

        // ASSERT: Returns 404 (not 403!) to prevent information leakage
        $response->assertNotFound();

        // Alternative: Use helper method
        $this->assertOrganizationBoundaryEnforced(
            $userOrg1,
            "/api/v1/applications/{$resourceOrg2->id}"
        );
    }
}
