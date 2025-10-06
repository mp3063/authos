<x-filament-widgets::widget>
    <x-filament::section>
        <x-slot name="heading">
            Security Monitoring
        </x-slot>

        <div class="space-y-4">
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="rounded-lg border border-gray-200 p-4">
                    <div class="text-2xl font-bold {{ $failed_logins > 50 ? 'text-danger-600' : 'text-gray-900' }}">
                        {{ $failed_logins }}
                    </div>
                    <div class="text-sm text-gray-600">Failed Logins (Today)</div>
                </div>

                <div class="rounded-lg border border-gray-200 p-4">
                    <div class="text-2xl font-bold {{ $critical_errors > 0 ? 'text-danger-600' : 'text-success-600' }}">
                        {{ $critical_errors }}
                    </div>
                    <div class="text-sm text-gray-600">Critical Errors (Today)</div>
                </div>

                <div class="rounded-lg border border-gray-200 p-4">
                    <div class="text-2xl font-bold {{ $error_rate > 1 ? 'text-warning-600' : 'text-gray-900' }}">
                        {{ number_format($error_rate, 2) }}
                    </div>
                    <div class="text-sm text-gray-600">Error Rate (per min)</div>
                </div>

                <div class="rounded-lg border border-gray-200 p-4">
                    <div class="text-2xl font-bold {{ count($suspicious_ips) > 0 ? 'text-danger-600' : 'text-success-600' }}">
                        {{ count($suspicious_ips) }}
                    </div>
                    <div class="text-sm text-gray-600">Suspicious IPs</div>
                </div>
            </div>

            @if(count($suspicious_ips) > 0)
                <div class="mt-4">
                    <h4 class="text-sm font-semibold text-gray-900 mb-2">Suspicious IP Addresses</h4>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Failed Attempts</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                @foreach(array_slice($suspicious_ips, 0, 5) as $ip)
                                    <tr>
                                        <td class="px-4 py-2 text-sm font-mono text-gray-900">{{ $ip->ip_address }}</td>
                                        <td class="px-4 py-2 text-sm text-danger-600 font-semibold">{{ $ip->attempts }}</td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>
                </div>
            @endif
        </div>
    </x-filament::section>
</x-filament-widgets::widget>
