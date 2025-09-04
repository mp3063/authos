<div class="space-y-6">
    <div class="grid grid-cols-2 gap-4">
        <div class="space-y-2">
            <h4 class="text-sm font-medium text-gray-500">Event Information</h4>
            <div class="bg-gray-50 rounded-lg p-3 space-y-2">
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Event Type:</span>
                    <span class="text-sm font-medium">{{ ucfirst(str_replace('_', ' ', $record->event)) }}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Timestamp:</span>
                    <span class="text-sm font-medium">{{ $record->created_at->format('M d, Y H:i:s T') }}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Status:</span>
                    <span class="text-sm font-medium {{ $record->event === 'login_success' ? 'text-green-600' : 'text-red-600' }}">
                        {{ in_array($record->event, ['login_failed', 'failed_mfa', 'suspicious_activity']) ? 'Failed' : 'Success' }}
                    </span>
                </div>
            </div>
        </div>

        <div class="space-y-2">
            <h4 class="text-sm font-medium text-gray-500">User Information</h4>
            <div class="bg-gray-50 rounded-lg p-3 space-y-2">
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">User:</span>
                    <span class="text-sm font-medium">{{ $record->user?->name ?? 'System' }}</span>
                </div>
                @if($record->user?->email)
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Email:</span>
                    <span class="text-sm font-medium">{{ $record->user->email }}</span>
                </div>
                @endif
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Organization:</span>
                    <span class="text-sm font-medium">{{ $record->user?->organization?->name ?? 'N/A' }}</span>
                </div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-2 gap-4">
        <div class="space-y-2">
            <h4 class="text-sm font-medium text-gray-500">Connection Details</h4>
            <div class="bg-gray-50 rounded-lg p-3 space-y-2">
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">IP Address:</span>
                    <span class="text-sm font-medium font-mono">{{ $record->ip_address }}</span>
                </div>
                @if($record->metadata && isset($record->metadata['location']))
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Location:</span>
                    <span class="text-sm font-medium">{{ $record->metadata['location'] }}</span>
                </div>
                @endif
                @if($record->user_agent)
                <div class="col-span-2">
                    <span class="text-sm text-gray-600">User Agent:</span>
                    <div class="mt-1 text-xs font-mono bg-white p-2 rounded border break-all">
                        {{ $record->user_agent }}
                    </div>
                </div>
                @endif
            </div>
        </div>

        <div class="space-y-2">
            <h4 class="text-sm font-medium text-gray-500">Application Details</h4>
            <div class="bg-gray-50 rounded-lg p-3 space-y-2">
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Application:</span>
                    <span class="text-sm font-medium">{{ $record->application?->name ?? 'N/A' }}</span>
                </div>
                @if($record->application)
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Client ID:</span>
                    <span class="text-sm font-medium font-mono">{{ Str::limit($record->application->client_id, 20) }}</span>
                </div>
                @endif
                <div class="flex justify-between">
                    <span class="text-sm text-gray-600">Session ID:</span>
                    <span class="text-sm font-medium font-mono">
                        {{ $record->metadata['session_id'] ?? 'N/A' }}
                    </span>
                </div>
            </div>
        </div>
    </div>

    @if($record->metadata && count($record->metadata) > 0)
    <div class="space-y-2">
        <h4 class="text-sm font-medium text-gray-500">Additional Metadata</h4>
        <div class="bg-gray-50 rounded-lg p-3">
            <pre class="text-xs text-gray-700 whitespace-pre-wrap">{{ json_encode($record->metadata, JSON_PRETTY_PRINT) }}</pre>
        </div>
    </div>
    @endif

    @if(in_array($record->event, ['login_failed', 'failed_mfa', 'suspicious_activity']))
    <div class="bg-red-50 border border-red-200 rounded-lg p-4">
        <div class="flex">
            <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
                </svg>
            </div>
            <div class="ml-3">
                <h3 class="text-sm font-medium text-red-800">
                    Security Alert
                </h3>
                <div class="mt-2 text-sm text-red-700">
                    <p>This event represents a potential security concern that may require investigation.</p>
                </div>
            </div>
        </div>
    </div>
    @endif
</div>