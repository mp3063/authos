<div class="footer">
    {{ $organization->name }} &middot;
    Generated {{ $generatedAt->format('Y-m-d H:i T') }} &middot;
    Period {{ $report['period']['from'] ?? '?' }} – {{ $report['period']['to'] ?? '?' }}
    <script type="text/php">
        if (isset($pdf)) {
            $pdf->page_text(520, 800, "Page {PAGE_NUM} of {PAGE_COUNT}", null, 8, [0.4, 0.4, 0.4]);
        }
    </script>
</div>
