<x-filament-widgets::widget>
    <x-filament::section>
        <x-slot name="heading">
            System Health
        </x-slot>

        <x-slot name="headerEnd">
            <span class="text-sm font-medium {{ $status === 'healthy' ? 'text-success-600' : 'text-danger-600' }}">
                {{ ucfirst($status) }}
            </span>
        </x-slot>

        <div class="space-y-4">
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                @foreach($checks as $name => $check)
                    <div class="rounded-lg border p-4 {{ $check['status'] === 'healthy' ? 'border-success-300 bg-success-50' : ($check['status'] === 'degraded' ? 'border-warning-300 bg-warning-50' : 'border-danger-300 bg-danger-50') }}">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center space-x-2">
                                @if($check['status'] === 'healthy')
                                    <x-heroicon-o-check-circle class="w-5 h-5 text-success-600" />
                                @elseif($check['status'] === 'degraded')
                                    <x-heroicon-o-exclamation-triangle class="w-5 h-5 text-warning-600" />
                                @else
                                    <x-heroicon-o-x-circle class="w-5 h-5 text-danger-600" />
                                @endif
                                <span class="text-sm font-medium text-gray-900">{{ ucfirst($name) }}</span>
                            </div>
                        </div>
                        <div class="mt-2 text-xs text-gray-600">
                            {{ $check['message'] }}
                        </div>
                        @if(isset($check['response_time_ms']))
                            <div class="mt-1 text-xs text-gray-500">
                                Response: {{ $check['response_time_ms'] }}ms
                            </div>
                        @endif
                    </div>
                @endforeach
            </div>

            <div class="text-xs text-gray-500 text-right">
                Last checked: {{ \Carbon\Carbon::parse($timestamp)->diffForHumans() }}
            </div>
        </div>
    </x-filament::section>
</x-filament-widgets::widget>
