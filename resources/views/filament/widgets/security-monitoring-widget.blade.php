<x-filament-widgets::widget>
    <x-filament::section>
        <x-slot name="heading">
            Security Monitoring
        </x-slot>

        <div class="flex flex-col gap-4">
            <div class="grid grid-cols-2 gap-4">
                <div class="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <div class="text-2xl font-bold {{ $failed_logins > 50 ? 'text-danger-600 dark:text-danger-400' : 'text-gray-950 dark:text-white' }}">
                        {{ $failed_logins }}
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Failed Logins (Today)</div>
                </div>

                <div class="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <div class="text-2xl font-bold {{ $critical_errors > 0 ? 'text-danger-600 dark:text-danger-400' : 'text-success-600 dark:text-success-400' }}">
                        {{ $critical_errors }}
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Critical Errors (Today)</div>
                </div>

                <div class="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <div class="text-2xl font-bold {{ $error_rate > 1 ? 'text-warning-600 dark:text-warning-400' : 'text-gray-950 dark:text-white' }}">
                        {{ number_format($error_rate, 2) }}
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Error Rate (per min)</div>
                </div>

                <div class="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <div class="text-2xl font-bold {{ count($suspicious_ips) > 0 ? 'text-danger-600 dark:text-danger-400' : 'text-success-600 dark:text-success-400' }}">
                        {{ count($suspicious_ips) }}
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Suspicious IPs</div>
                </div>
            </div>

            @if(count($suspicious_ips) > 0)
                <div class="mt-4">
                    <h4 class="text-sm font-semibold text-gray-950 dark:text-white mb-2">Suspicious IP Addresses</h4>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="border-b border-gray-200 dark:border-gray-700">
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">IP Address</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Failed Attempts</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach(array_slice($suspicious_ips, 0, 5) as $ip)
                                    <tr class="border-b border-gray-200 dark:border-gray-700">
                                        <td class="px-4 py-2 text-sm font-mono text-gray-950 dark:text-white">{{ $ip->ip_address }}</td>
                                        <td class="px-4 py-2 text-sm font-semibold text-danger-600 dark:text-danger-400">{{ $ip->attempts }}</td>
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
