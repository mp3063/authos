<div class="fi-widget-application-access-matrix">
    <div class="fi-widget-header flex items-center justify-between">
        <h2 class="text-lg font-semibold text-gray-900">Application Access Matrix</h2>
        <div class="flex items-center space-x-4 text-sm text-gray-600">
            @if($hasPermission)
                @php $stats = $this->getAccessStats(); @endphp
                <span>{{ $stats['activeUsers'] ?? 0 }}/{{ $stats['totalUsers'] ?? 0 }} users with access</span>
                <span>•</span>
                <span>{{ $stats['accessRate'] ?? 0 }}% coverage</span>
            @endif
        </div>
    </div>

    @if(!$hasPermission)
        <div class="mt-4 p-6 bg-gray-50 rounded-lg text-center">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h3 class="mt-2 text-sm font-medium text-gray-900">Access Restricted</h3>
            <p class="mt-1 text-sm text-gray-500">You need organization admin permissions to view this matrix.</p>
        </div>
    @elseif($applications->isEmpty())
        <div class="mt-4 p-6 bg-gray-50 rounded-lg text-center">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            <h3 class="mt-2 text-sm font-medium text-gray-900">No Applications</h3>
            <p class="mt-1 text-sm text-gray-500">Create applications to manage user access.</p>
        </div>
    @elseif($users->isEmpty())
        <div class="mt-4 p-6 bg-gray-50 rounded-lg text-center">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z" />
            </svg>
            <h3 class="mt-2 text-sm font-medium text-gray-900">No Users</h3>
            <p class="mt-1 text-sm text-gray-500">No users have access to applications in this organization.</p>
        </div>
    @else
        <div class="mt-4 overflow-x-auto">
            <div class="inline-block min-w-full align-middle">
                <div class="overflow-hidden border border-gray-200 rounded-lg">
                    <table class="min-w-full divide-y divide-gray-200">
                        <!-- Header -->
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="sticky left-0 z-10 bg-gray-50 px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-r border-gray-200">
                                    User
                                </th>
                                @foreach($applications as $app)
                                    <th class="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider min-w-24">
                                        <div class="flex flex-col items-center space-y-1">
                                            <span class="truncate max-w-20" title="{{ $app->name }}">{{ Str::limit($app->name, 10) }}</span>
                                            <span class="text-xs text-gray-400 font-normal">
                                                {{ $app->users->count() }} users
                                            </span>
                                        </div>
                                    </th>
                                @endforeach
                                <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Total
                                </th>
                            </tr>
                        </thead>

                        <!-- Body -->
                        <tbody class="bg-white divide-y divide-gray-200">
                            @foreach($users as $user)
                                <tr class="hover:bg-gray-50">
                                    <!-- User column (sticky) -->
                                    <td class="sticky left-0 z-10 bg-white px-4 py-3 whitespace-nowrap border-r border-gray-200 hover:bg-gray-50">
                                        <div class="flex items-center space-x-3">
                                            <div class="flex-shrink-0 h-8 w-8">
                                                @if($user->avatar)
                                                    <img class="h-8 w-8 rounded-full" src="{{ $user->avatar }}" alt="">
                                                @else
                                                    <div class="h-8 w-8 rounded-full bg-blue-100 flex items-center justify-center">
                                                        <span class="text-sm font-medium text-blue-800">
                                                            {{ substr($user->name, 0, 1) }}
                                                        </span>
                                                    </div>
                                                @endif
                                            </div>
                                            <div class="min-w-0 flex-1">
                                                <p class="text-sm font-medium text-gray-900 truncate">{{ $user->name }}</p>
                                                <p class="text-xs text-gray-500 truncate">{{ $user->email }}</p>
                                            </div>
                                        </div>
                                    </td>

                                    <!-- Application access columns -->
                                    @foreach($applications as $app)
                                        @php
                                            $access = $accessMatrix[$user->id][$app->id] ?? ['hasAccess' => false];
                                        @endphp
                                        <td class="px-3 py-3 text-center">
                                            <div class="flex flex-col items-center space-y-1">
                                                @if($access['hasAccess'])
                                                    <!-- Has Access -->
                                                    <button 
                                                        wire:click="revokeAccess({{ $user->id }}, {{ $app->id }})"
                                                        wire:confirm="Are you sure you want to revoke {{ $user->name }}'s access to {{ $app->name }}?"
                                                        class="inline-flex items-center justify-center w-6 h-6 rounded-full bg-green-100 text-green-800 hover:bg-red-100 hover:text-red-800 transition-colors duration-200"
                                                        title="Click to revoke access"
                                                    >
                                                        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                                                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                                                        </svg>
                                                    </button>
                                                    @if($access['lastLogin'])
                                                        <span class="text-xs text-gray-500">
                                                            {{ Carbon\Carbon::parse($access['lastLogin'])->diffForHumans() }}
                                                        </span>
                                                    @else
                                                        <span class="text-xs text-gray-400">Never used</span>
                                                    @endif
                                                @else
                                                    <!-- No Access -->
                                                    <button 
                                                        wire:click="grantAccess({{ $user->id }}, {{ $app->id }})"
                                                        wire:confirm="Are you sure you want to grant {{ $user->name }} access to {{ $app->name }}?"
                                                        class="inline-flex items-center justify-center w-6 h-6 rounded-full bg-gray-100 text-gray-400 hover:bg-green-100 hover:text-green-800 transition-colors duration-200"
                                                        title="Click to grant access"
                                                    >
                                                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                                        </svg>
                                                    </button>
                                                    <span class="text-xs text-gray-400">No access</span>
                                                @endif
                                            </div>
                                        </td>
                                    @endforeach

                                    <!-- Total column -->
                                    <td class="px-4 py-3 text-center">
                                        @php
                                            $userTotalAccess = collect($accessMatrix[$user->id] ?? [])->where('hasAccess', true)->count();
                                        @endphp
                                        <div class="flex flex-col items-center space-y-1">
                                            <span class="text-sm font-medium text-gray-900">
                                                {{ $userTotalAccess }}/{{ $applications->count() }}
                                            </span>
                                            <div class="w-12 bg-gray-200 rounded-full h-2">
                                                <div class="bg-blue-600 h-2 rounded-full" 
                                                     style="width: {{ $applications->count() > 0 ? ($userTotalAccess / $applications->count()) * 100 : 0 }}%"></div>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>

                        <!-- Footer with totals -->
                        <tfoot class="bg-gray-50">
                            <tr>
                                <td class="sticky left-0 z-10 bg-gray-50 px-4 py-3 text-sm font-medium text-gray-900 border-r border-gray-200">
                                    Totals
                                </td>
                                @foreach($applications as $app)
                                    @php
                                        $appTotalUsers = collect($accessMatrix)->sum(fn($userAccess) => $userAccess[$app->id]['hasAccess'] ?? false);
                                    @endphp
                                    <td class="px-3 py-3 text-center">
                                        <div class="flex flex-col items-center space-y-1">
                                            <span class="text-sm font-medium text-gray-900">
                                                {{ $appTotalUsers }}/{{ $users->count() }}
                                            </span>
                                            <div class="w-12 bg-gray-200 rounded-full h-2">
                                                <div class="bg-green-600 h-2 rounded-full" 
                                                     style="width: {{ $users->count() > 0 ? ($appTotalUsers / $users->count()) * 100 : 0 }}%"></div>
                                            </div>
                                        </div>
                                    </td>
                                @endforeach
                                <td class="px-4 py-3 text-center">
                                    @php
                                        $stats = $this->getAccessStats();
                                    @endphp
                                    <div class="flex flex-col items-center space-y-1">
                                        <span class="text-sm font-medium text-gray-900">
                                            {{ $stats['totalGrantedAccess'] }}/{{ $stats['totalPossibleAccess'] }}
                                        </span>
                                        <span class="text-xs text-gray-500">{{ $stats['accessRate'] }}%</span>
                                    </div>
                                </td>
                            </tr>
                        </tfoot>
                    </table>
                </div>
            </div>
        </div>

        <!-- Legend -->
        <div class="mt-4 flex items-center justify-between text-sm text-gray-600">
            <div class="flex items-center space-x-4">
                <div class="flex items-center space-x-2">
                    <div class="w-4 h-4 rounded-full bg-green-100 flex items-center justify-center">
                        <svg class="w-3 h-3 text-green-800" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <span>Has Access (Click to revoke)</span>
                </div>
                <div class="flex items-center space-x-2">
                    <div class="w-4 h-4 rounded-full bg-gray-100 flex items-center justify-center">
                        <svg class="w-3 h-3 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                        </svg>
                    </div>
                    <span>No Access (Click to grant)</span>
                </div>
            </div>
            <div class="text-xs text-gray-500">
                Last updated: {{ now()->format('H:i:s') }}
            </div>
        </div>
    @endif
</div>