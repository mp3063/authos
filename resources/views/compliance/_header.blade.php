<div class="header-band">
    @if (! empty($logoPath))
        <img src="{{ $logoPath }}" alt="" style="height: 24px; vertical-align: middle; margin-right: 8px;">
    @endif
    <span class="org-name">{{ $organization->name }}</span><br>
    <span class="report-type">{{ $reportLabel ?? 'Compliance Report' }}</span>
</div>
