<x-filament-widgets::widget>
    <x-filament::section>
        <x-slot name="heading">
            System Health
        </x-slot>

        <x-slot name="headerEnd">
            <span class="text-sm font-medium {{ $status === 'healthy' ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400' }}">
                {{ ucfirst($status) }}
            </span>
        </x-slot>

        <div class="flex flex-col gap-4">
            <div class="grid grid-cols-2 gap-4">
                @foreach($checks as $name => $check)
                    @php
                        $statusClasses = match($check['status']) {
                            'healthy' => 'border-success-300 dark:border-success-700 bg-success-50 dark:bg-success-950/30',
                            'degraded' => 'border-warning-300 dark:border-warning-700 bg-warning-50 dark:bg-warning-950/30',
                            default => 'border-danger-300 dark:border-danger-700 bg-danger-50 dark:bg-danger-950/30',
                        };
                        $iconClasses = match($check['status']) {
                            'healthy' => 'text-success-600 dark:text-success-400',
                            'degraded' => 'text-warning-600 dark:text-warning-400',
                            default => 'text-danger-600 dark:text-danger-400',
                        };
                    @endphp
                    <div class="rounded-lg border p-4 {{ $statusClasses }}">
                        <div class="flex items-center gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5 shrink-0 {{ $iconClasses }}">
                                @if($check['status'] === 'healthy')
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                @elseif($check['status'] === 'degraded')
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                                @else
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                @endif
                            </svg>
                            <span class="text-sm font-medium text-gray-950 dark:text-white">{{ ucfirst($name) }}</span>
                        </div>
                        <div class="mt-2 text-xs text-gray-500 dark:text-gray-400">
                            {{ $check['message'] }}
                        </div>
                        @if(isset($check['response_time_ms']))
                            <div class="mt-1 text-xs text-gray-400 dark:text-gray-500">
                                Response: {{ $check['response_time_ms'] }}ms
                            </div>
                        @endif
                    </div>
                @endforeach
            </div>

            <div class="text-xs text-gray-400 dark:text-gray-500 text-right">
                Last checked: {{ \Carbon\Carbon::parse($timestamp)->diffForHumans() }}
            </div>
        </div>
    </x-filament::section>
</x-filament-widgets::widget>
