<x-mail::message>
# You've been invited to join {{ $organizationName }}

Hello,

**{{ $inviterName }}** has invited you to join **{{ $organizationName }}** as a **{{ ucfirst($role) }}**.

<x-mail::button :url="$acceptUrl">
Accept Invitation
</x-mail::button>

## What happens next?

1. Click the "Accept Invitation" button above
2. Create an account or sign in if you already have one
3. You'll automatically be added to {{ $organizationName }} with {{ $role }} privileges

## Invitation Details

- **Organization:** {{ $organizationName }}
- **Role:** {{ ucfirst($role) }}
- **Invited by:** {{ $inviterName }}
- **Expires:** {{ $expiresAt }}

If you have any questions about this invitation, please contact {{ $inviterName }} directly.

---

*This invitation expires on {{ $expiresAt }}. If you don't accept it by then, you'll need to request a new invitation.*

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>