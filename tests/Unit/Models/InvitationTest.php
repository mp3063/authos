<?php

namespace Tests\Unit\Models;

use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Carbon\Carbon;

class InvitationTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $inviter;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
        $this->inviter = User::factory()->forOrganization($this->organization)->create();
    }

    public function test_invitation_belongs_to_organization(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->assertInstanceOf(Organization::class, $invitation->organization);
        $this->assertEquals($this->organization->id, $invitation->organization->id);
    }

    public function test_invitation_belongs_to_inviter(): void
    {
        $invitation = Invitation::factory()
            ->fromInviter($this->inviter)
            ->create();

        $this->assertInstanceOf(User::class, $invitation->inviter);
        $this->assertEquals($this->inviter->id, $invitation->inviter->id);
    }

    public function test_invitation_can_belong_to_accepted_by_user(): void
    {
        $acceptedBy = User::factory()->create();
        $invitation = Invitation::factory()
            ->accepted()
            ->create(['accepted_by' => $acceptedBy->id]);

        $this->assertInstanceOf(User::class, $invitation->acceptedBy);
        $this->assertEquals($acceptedBy->id, $invitation->acceptedBy->id);
    }

    public function test_is_expired_scope_filters_expired_invitations(): void
    {
        // Create expired invitation
        $expiredInvitation = Invitation::factory()
            ->expired()
            ->create();

        // Create active invitation
        $activeInvitation = Invitation::factory()
            ->expiresIn(7)
            ->create();

        $expiredInvitations = Invitation::isExpired()->get();

        $this->assertCount(1, $expiredInvitations);
        $this->assertEquals($expiredInvitation->id, $expiredInvitations->first()->id);
    }

    public function test_is_pending_scope_filters_pending_invitations(): void
    {
        // Create pending invitation
        $pendingInvitation = Invitation::factory()
            ->create(['status' => 'pending']);

        // Create accepted invitation
        $acceptedInvitation = Invitation::factory()
            ->accepted()
            ->create();

        $pendingInvitations = Invitation::isPending()->get();

        $this->assertCount(1, $pendingInvitations);
        $this->assertEquals($pendingInvitation->id, $pendingInvitations->first()->id);
    }

    public function test_for_organization_scope_filters_by_organization(): void
    {
        $otherOrganization = Organization::factory()->create();

        // Create invitation for our organization
        $ourInvitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->create();

        // Create invitation for other organization
        $otherInvitation = Invitation::factory()
            ->forOrganization($otherOrganization)
            ->create();

        $organizationInvitations = Invitation::forOrganization($this->organization->id)->get();

        $this->assertCount(1, $organizationInvitations);
        $this->assertEquals($ourInvitation->id, $organizationInvitations->first()->id);
    }

    public function test_is_expired_method_correctly_identifies_expired_invitations(): void
    {
        $expiredInvitation = Invitation::factory()
            ->create(['expires_at' => Carbon::now()->subDay()]);

        $activeInvitation = Invitation::factory()
            ->create(['expires_at' => Carbon::now()->addDays(7)]);

        $this->assertTrue($expiredInvitation->isExpired());
        $this->assertFalse($activeInvitation->isExpired());
    }

    public function test_is_pending_method_correctly_identifies_pending_invitations(): void
    {
        $pendingInvitation = Invitation::factory()
            ->create(['status' => 'pending']);

        $acceptedInvitation = Invitation::factory()
            ->create(['status' => 'accepted']);

        $this->assertTrue($pendingInvitation->isPending());
        $this->assertFalse($acceptedInvitation->isPending());
    }

    public function test_is_accepted_method_correctly_identifies_accepted_invitations(): void
    {
        $acceptedInvitation = Invitation::factory()
            ->accepted()
            ->create();

        $pendingInvitation = Invitation::factory()
            ->create(['status' => 'pending']);

        $this->assertTrue($acceptedInvitation->isAccepted());
        $this->assertFalse($pendingInvitation->isAccepted());
    }

    public function test_can_be_accepted_returns_true_for_valid_invitations(): void
    {
        $validInvitation = Invitation::factory()
            ->create([
                'status' => 'pending',
                'expires_at' => Carbon::now()->addDays(7)
            ]);

        $this->assertTrue($validInvitation->canBeAccepted());
    }

    public function test_can_be_accepted_returns_false_for_expired_invitations(): void
    {
        $expiredInvitation = Invitation::factory()
            ->create([
                'status' => 'pending',
                'expires_at' => Carbon::now()->subDay()
            ]);

        $this->assertFalse($expiredInvitation->canBeAccepted());
    }

    public function test_can_be_accepted_returns_false_for_already_accepted_invitations(): void
    {
        $acceptedInvitation = Invitation::factory()
            ->accepted()
            ->create(['expires_at' => Carbon::now()->addDays(7)]);

        $this->assertFalse($acceptedInvitation->canBeAccepted());
    }

    public function test_can_be_accepted_returns_false_for_cancelled_invitations(): void
    {
        $cancelledInvitation = Invitation::factory()
            ->create([
                'status' => 'cancelled',
                'expires_at' => Carbon::now()->addDays(7)
            ]);

        $this->assertFalse($cancelledInvitation->canBeAccepted());
    }

    public function test_mark_as_accepted_updates_invitation_status(): void
    {
        $invitation = Invitation::factory()
            ->create(['status' => 'pending']);

        $acceptedBy = User::factory()->create();

        $invitation->markAsAccepted($acceptedBy->id);

        $this->assertEquals('accepted', $invitation->status);
        $this->assertEquals($acceptedBy->id, $invitation->accepted_by);
        $this->assertNotNull($invitation->accepted_at);
    }

    public function test_mark_as_declined_updates_invitation_status(): void
    {
        $invitation = Invitation::factory()
            ->create(['status' => 'pending']);

        $reason = 'Not interested';
        $invitation->markAsDeclined($reason);

        $this->assertEquals('declined', $invitation->status);
        $this->assertEquals($reason, $invitation->decline_reason);
        $this->assertNotNull($invitation->declined_at);
    }

    public function test_mark_as_cancelled_updates_invitation_status(): void
    {
        $invitation = Invitation::factory()
            ->create(['status' => 'pending']);

        $cancelledBy = $this->inviter->id;
        $invitation->markAsCancelled($cancelledBy);

        $this->assertEquals('cancelled', $invitation->status);
        $this->assertEquals($cancelledBy, $invitation->cancelled_by);
        $this->assertNotNull($invitation->cancelled_at);
    }

    public function test_regenerate_token_creates_new_token_and_extends_expiry(): void
    {
        $invitation = Invitation::factory()
            ->create(['expires_at' => Carbon::now()->addDay()]);

        $originalToken = $invitation->token;
        $originalExpiry = $invitation->expires_at;

        $invitation->regenerateToken();

        $this->assertNotEquals($originalToken, $invitation->token);
        $this->assertTrue($invitation->expires_at->gt($originalExpiry));
        $this->assertEquals(32, strlen($invitation->token)); // Standard token length
    }

    public function test_get_invitation_url_returns_formatted_url(): void
    {
        $invitation = Invitation::factory()->create();

        $url = $invitation->getInvitationUrl();

        $this->assertStringContainsString('accept', $url);
        $this->assertStringContainsString($invitation->token, $url);
        $this->assertStringStartsWith('http', $url);
    }

    public function test_days_until_expiry_calculates_correctly(): void
    {
        $invitation = Invitation::factory()
            ->create(['expires_at' => Carbon::now()->addDays(5)]);

        $this->assertEquals(5, $invitation->daysUntilExpiry());
    }

    public function test_days_until_expiry_returns_negative_for_expired(): void
    {
        $invitation = Invitation::factory()
            ->create(['expires_at' => Carbon::now()->subDays(2)]);

        $this->assertEquals(-2, $invitation->daysUntilExpiry());
    }

    public function test_metadata_is_cast_to_array(): void
    {
        $metadata = ['source' => 'admin_panel', 'custom_field' => 'value'];
        
        $invitation = Invitation::factory()
            ->create(['metadata' => $metadata]);

        $this->assertIsArray($invitation->metadata);
        $this->assertEquals($metadata, $invitation->metadata);
    }

    public function test_invitation_has_correct_fillable_attributes(): void
    {
        $fillable = [
            'organization_id', 'inviter_id', 'email', 'token', 'role',
            'expires_at', 'status', 'metadata', 'accepted_by', 'accepted_at',
            'declined_at', 'decline_reason', 'cancelled_by', 'cancelled_at'
        ];

        $invitation = new Invitation();

        $this->assertEquals($fillable, $invitation->getFillable());
    }

    public function test_invitation_casts_dates_correctly(): void
    {
        $invitation = Invitation::factory()->create();

        $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->expires_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->created_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->updated_at);

        if ($invitation->accepted_at) {
            $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->accepted_at);
        }

        if ($invitation->declined_at) {
            $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->declined_at);
        }

        if ($invitation->cancelled_at) {
            $this->assertInstanceOf(\Carbon\Carbon::class, $invitation->cancelled_at);
        }
    }

    public function test_find_by_token_returns_correct_invitation(): void
    {
        $invitation = Invitation::factory()->create();
        $foundInvitation = Invitation::findByToken($invitation->token);

        $this->assertInstanceOf(Invitation::class, $foundInvitation);
        $this->assertEquals($invitation->id, $foundInvitation->id);
    }

    public function test_find_by_token_returns_null_for_invalid_token(): void
    {
        $foundInvitation = Invitation::findByToken('invalid-token');

        $this->assertNull($foundInvitation);
    }
}