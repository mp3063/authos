<x-mail::message>
# Multi-Factor Authentication Enabled

Hello {{ $userName }},

Multi-factor authentication has been successfully enabled on your account using the following method(s): **{{ implode(', ', array_map('strtoupper', $methods)) }}**.

Please ensure you have stored your backup codes in a safe location. These codes can be used to access your account if you lose access to your authenticator device.

If you did not enable MFA on your account, please contact support immediately and change your password.

Thanks,<br>
{{ $appName }}
</x-mail::message>
