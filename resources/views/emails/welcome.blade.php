<x-mail::message>
# Welcome to {{ $appName }}

Hello {{ $userName }},

Your account has been created successfully. You can now sign in and start using the platform.

<x-mail::button :url="$loginUrl">
Sign In
</x-mail::button>

If you did not create this account, please contact our support team immediately.

Thanks,<br>
{{ $appName }}
</x-mail::message>
