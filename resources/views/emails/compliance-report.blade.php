@component('mail::message')
# Compliance Report Generated

A new **{{ $reportType }}** compliance report has been generated for **{{ $organization->name }}**.

## Report Summary

@component('mail::panel')
- **Generated:** {{ $generatedAt }}
- **Organization:** {{ $organization->name }}
- **Report Type:** {{ $reportType }}
@endcomponent

@component('mail::button', ['url' => $downloadUrl])
Download Report
@endcomponent

Thanks,<br>
{{ config('app.name') }}
@endcomponent
