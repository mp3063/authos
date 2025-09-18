<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Authorization Request</title>

    <!-- Styles -->
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div class="bg-white shadow-md rounded-lg p-6">
                <div class="text-center">
                    <h2 class="mt-6 text-3xl font-extrabold text-gray-900">Authorization Request</h2>
                    <p class="mt-2 text-sm text-gray-600">
                        <strong>{{ $client->name }}</strong> is requesting permission to access your account
                    </p>
                </div>

                <div class="mt-8">
                    <div class="bg-gray-50 px-4 py-3 rounded-md">
                        <h3 class="text-sm font-medium text-gray-900">This application will be able to:</h3>
                        <ul class="mt-2 text-sm text-gray-600 space-y-1">
                            @if (count($scopes) > 0)
                                @foreach ($scopes as $scope)
                                    <li>• {{ $scope->description }}</li>
                                @endforeach
                            @else
                                <li>• Access your basic profile information</li>
                            @endif
                        </ul>
                    </div>

                    <div class="mt-6 flex flex-col space-y-4">
                        <!-- Authorize Form -->
                        <form method="post" action="{{ route('passport.authorizations.approve') }}">
                            @csrf
                            <input type="hidden" name="state" value="{{ $request->state }}">
                            <input type="hidden" name="client_id" value="{{ $client->id }}">
                            <input type="hidden" name="auth_token" value="{{ $authToken }}">

                            <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                                Authorize
                            </button>
                        </form>

                        <!-- Cancel Form -->
                        <form method="post" action="{{ route('passport.authorizations.deny') }}">
                            @csrf
                            <input type="hidden" name="state" value="{{ $request->state }}">
                            <input type="hidden" name="client_id" value="{{ $client->id }}">
                            <input type="hidden" name="auth_token" value="{{ $authToken }}">

                            <button type="submit" class="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                                Cancel
                            </button>
                        </form>
                    </div>

                    <div class="mt-6 text-center">
                        <p class="text-xs text-gray-500">
                            You are logged in as <strong>{{ $user->name }}</strong> ({{ $user->email }})
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>