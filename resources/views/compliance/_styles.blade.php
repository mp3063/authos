@php
    $primaryColor = $branding?->primary_color ?: '#1f2937';
@endphp
<style>
    @page { margin: 24mm 16mm 28mm 16mm; }
    body { font-family: DejaVu Sans, sans-serif; font-size: 10pt; color: #1f2937; line-height: 1.45; }
    h1, h2, h3 { color: {{ $primaryColor }}; margin: 0 0 8px 0; }
    h1 { font-size: 22pt; }
    h2 { font-size: 14pt; margin-top: 18px; border-bottom: 1px solid #d1d5db; padding-bottom: 4px; }
    h3 { font-size: 11pt; margin-top: 12px; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0 12px 0; }
    th, td { border: 1px solid #e5e7eb; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { background: #f3f4f6; font-weight: 600; }
    .meta { font-size: 9pt; color: #6b7280; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 9pt; background: #f3f4f6; color: #1f2937; }
    .header-band { background: {{ $primaryColor }}; color: #ffffff; padding: 12px 16px; margin-bottom: 12px; }
    .header-band .org-name { font-size: 16pt; font-weight: 600; }
    .header-band .report-type { font-size: 11pt; opacity: 0.9; }
    .footer { position: fixed; bottom: 0; left: 0; right: 0; height: 18mm; padding: 6mm 16mm 0 16mm; font-size: 8pt; color: #6b7280; border-top: 1px solid #e5e7eb; }
    .kv td.label { width: 40%; font-weight: 600; background: #fafafa; }
    .summary-grid td { width: 25%; text-align: center; }
    .summary-grid td .num { font-size: 20pt; color: {{ $primaryColor }}; font-weight: 700; }
    .summary-grid td .lbl { font-size: 9pt; color: #6b7280; }
    .text-muted { color: #6b7280; }
    .small { font-size: 9pt; }
</style>
