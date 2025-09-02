<x-mail::message>
# Invitation Accepted ✅

Great news! **{{ $acceptorName }}** has accepted your invitation to join **{{ $organizationName }}**.

## Invitation Details

- **New Member:** {{ $acceptorName }} ({{ $acceptorEmail }})
- **Organization:** {{ $organizationName }}
- **Role:** {{ ucfirst($role) }}
- **Accepted:** {{ $acceptedAt }}

{{ $acceptorName }} now has access to {{ $organizationName }} with {{ $role }} privileges.

<x-mail::button :url="url('/admin/organizations/' . $invitation->organization_id)">
View Organization
</x-mail::button>

You can manage their permissions and access through the organization dashboard.

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>