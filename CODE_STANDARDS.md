# Code Standards

This document defines the coding standards and best practices for the AuthOS Laravel 12 application.

## Table of Contents

- [General Principles](#general-principles)
- [Laravel Best Practices](#laravel-best-practices)
- [Filament Conventions](#filament-conventions)
- [PHP Standards](#php-standards)
- [Security Guidelines](#security-guidelines)
- [Performance Guidelines](#performance-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Database Conventions](#database-conventions)
- [API Design](#api-design)

## General Principles

### SOLID Principles

- **Single Responsibility**: Each class should have one reason to change
- **Open/Closed**: Open for extension, closed for modification
- **Liskov Substitution**: Derived classes must be substitutable for base classes
- **Interface Segregation**: Clients shouldn't depend on interfaces they don't use
- **Dependency Inversion**: Depend on abstractions, not concretions

### DRY (Don't Repeat Yourself)

- Extract reusable logic into services, traits, or helpers
- Use inheritance and composition appropriately
- Avoid code duplication

### KISS (Keep It Simple, Stupid)

- Write simple, readable code
- Avoid over-engineering
- Use clear, descriptive names

## Laravel Best Practices

### Naming Conventions

#### Controllers

```php
// Singular, descriptive names
class UserController extends Controller
{
    // RESTful method names
    public function index() {}
    public function create() {}
    public function store(Request $request) {}
    public function show(User $user) {}
    public function edit(User $user) {}
    public function update(Request $request, User $user) {}
    public function destroy(User $user) {}
}
```

#### Models

```php
// Singular, PascalCase
class User extends Model
{
    // Use type hints
    protected $fillable = ['name', 'email'];
    
    // Relationship methods are camelCase
    public function posts(): HasMany
    {
        return $this->hasMany(Post::class);
    }
    
    // Accessor/Mutator methods
    protected function name(): Attribute
    {
        return Attribute::make(
            get: fn (string $value) => ucfirst($value),
            set: fn (string $value) => strtolower($value),
        );
    }
}
```

#### Routes

```php
// Use named routes
Route::get('/users', [UserController::class, 'index'])->name('users.index');

// Group related routes
Route::prefix('admin')->name('admin.')->group(function () {
    Route::resource('users', UserController::class);
});

// Use route model binding
Route::get('/users/{user}', [UserController::class, 'show']);
```

### Service Layer Pattern

```php
// app/Services/UserService.php
namespace App\Services;

class UserService
{
    public function createUser(array $data): User
    {
        // Business logic here
        return User::create($data);
    }
}

// In controller
public function store(Request $request, UserService $userService)
{
    $user = $userService->createUser($request->validated());
    
    return response()->json($user, 201);
}
```

### Repository Pattern (Optional)

```php
// app/Repositories/UserRepository.php
namespace App\Repositories;

class UserRepository
{
    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }
}
```

### Form Requests

```php
// app/Http/Requests/StoreUserRequest.php
namespace App\Http\Requests;

class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users'],
        ];
    }

    public function messages(): array
    {
        return [
            'email.unique' => 'This email is already registered.',
        ];
    }
}
```

### Resources

```php
// app/Http/Resources/UserResource.php
namespace App\Http\Resources;

class UserResource extends JsonResource
{
    public function toArray($request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'created_at' => $this->created_at->toIso8601String(),
            // Conditional relationships
            'posts' => PostResource::collection($this->whenLoaded('posts')),
        ];
    }
}
```

## Filament Conventions

### Resource Naming

```php
// app/Filament/Resources/UserResource.php
class UserResource extends Resource
{
    protected static ?string $model = User::class;
    protected static ?string $navigationIcon = 'heroicon-o-users';
    protected static ?string $navigationGroup = 'User Management';
    protected static ?int $navigationSort = 1;
}
```

### Form Building

```php
public static function form(Form $form): Form
{
    return $form
        ->schema([
            Section::make('User Information')
                ->schema([
                    TextInput::make('name')
                        ->required()
                        ->maxLength(255),
                    TextInput::make('email')
                        ->email()
                        ->required()
                        ->unique(ignoreRecord: true),
                ])
                ->columns(2),
        ]);
}
```

### Table Configuration

```php
public static function table(Table $table): Table
{
    return $table
        ->columns([
            TextColumn::make('id')->sortable(),
            TextColumn::make('name')->searchable()->sortable(),
            TextColumn::make('email')->searchable(),
            BooleanColumn::make('is_active'),
            TextColumn::make('created_at')->dateTime()->sortable(),
        ])
        ->filters([
            SelectFilter::make('is_active')
                ->options([
                    '1' => 'Active',
                    '0' => 'Inactive',
                ]),
        ])
        ->actions([
            Tables\Actions\EditAction::make(),
            Tables\Actions\DeleteAction::make(),
        ])
        ->bulkActions([
            Tables\Actions\DeleteBulkAction::make(),
        ]);
}
```

## PHP Standards

### Type Declarations

Always use type declarations:

```php
// Good
public function calculateTotal(int $quantity, float $price): float
{
    return $quantity * $price;
}

// Bad
public function calculateTotal($quantity, $price)
{
    return $quantity * $price;
}
```

### Return Types

Always declare return types:

```php
// Good
public function getUser(int $id): ?User
{
    return User::find($id);
}

// With union types (PHP 8+)
public function getData(): array|Collection
{
    return collect([]);
}
```

### Null Safety

Use null coalescing and null safe operators:

```php
// Null coalescing
$name = $user->name ?? 'Guest';

// Null safe operator
$country = $user?->address?->country;
```

### Array Syntax

Always use short array syntax:

```php
// Good
$array = ['foo', 'bar'];
$assoc = ['key' => 'value'];

// Bad
$array = array('foo', 'bar');
```

### String Concatenation

Use single quotes for simple strings:

```php
// Good
$message = 'Hello, ' . $name . '!';
$message = "Hello, {$name}!"; // For interpolation

// Bad
$message = "Hello, " . $name . "!";
```

### Comparison Operators

Use strict comparisons:

```php
// Good
if ($value === null) {}
if (count($array) > 0) {}

// Bad
if ($value == null) {}
if (count($array)) {}
```

## Security Guidelines

### Input Validation

```php
// Always validate user input
$request->validate([
    'email' => ['required', 'email'],
    'password' => ['required', 'min:8'],
]);
```

### Mass Assignment Protection

```php
// Use $fillable or $guarded
class User extends Model
{
    protected $fillable = ['name', 'email'];
    // OR
    protected $guarded = ['id', 'is_admin'];
}
```

### SQL Injection Prevention

```php
// Good - Use query builder or Eloquent
User::where('email', $email)->first();

// Bad - Raw SQL without bindings
DB::select("SELECT * FROM users WHERE email = '$email'");

// If you must use raw SQL, use bindings
DB::select('SELECT * FROM users WHERE email = ?', [$email]);
```

### XSS Prevention

```php
// Blade automatically escapes
{{ $userInput }} // Escaped

// Raw output (use with caution)
{!! $trustedHtml !!} // Not escaped
```

### CSRF Protection

```php
// Always use CSRF tokens in forms
<form method="POST">
    @csrf
    <!-- form fields -->
</form>
```

### Authentication & Authorization

```php
// Use policies
class PostPolicy
{
    public function update(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }
}

// In controller
public function update(Request $request, Post $post)
{
    $this->authorize('update', $post);
    // Update logic
}
```

## Performance Guidelines

### Eager Loading

```php
// Good - Eager load relationships
$users = User::with('posts', 'comments')->get();

// Bad - N+1 queries
$users = User::all();
foreach ($users as $user) {
    echo $user->posts->count(); // Separate query for each user
}
```

### Chunking Large Results

```php
// Good - For large datasets
User::chunk(1000, function ($users) {
    foreach ($users as $user) {
        // Process user
    }
});

// With lazy() for better memory usage
User::lazy()->each(function ($user) {
    // Process user
});
```

### Caching

```php
// Cache expensive queries
$users = Cache::remember('users.active', 3600, function () {
    return User::where('active', true)->get();
});

// Cache tags for organized invalidation
Cache::tags(['users', 'active'])->remember('users.active', 3600, fn () => 
    User::where('active', true)->get()
);
```

### Database Indexing

```php
// Add indexes in migrations
Schema::table('users', function (Blueprint $table) {
    $table->index('email');
    $table->index(['organization_id', 'created_at']);
});
```

## Testing Guidelines

### Test Structure (AAA Pattern)

```php
public function test_user_can_update_profile(): void
{
    // Arrange
    $user = User::factory()->create();
    $data = ['name' => 'New Name'];

    // Act
    $response = $this->actingAs($user)
        ->put('/api/v1/profile', $data);

    // Assert
    $response->assertStatus(200);
    $this->assertDatabaseHas('users', [
        'id' => $user->id,
        'name' => 'New Name',
    ]);
}
```

### Test Naming

```php
// Good - Descriptive test names
public function test_user_cannot_access_another_users_data(): void
public function test_token_expires_after_one_hour(): void
public function test_mfa_is_required_for_high_security_organizations(): void

// Bad - Vague test names
public function test_access(): void
public function test_token(): void
```

### Factories

```php
// Use factories for test data
class UserFactory extends Factory
{
    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'password' => bcrypt('password'),
        ];
    }

    // Custom states
    public function admin(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_admin' => true,
        ]);
    }
}

// In tests
$admin = User::factory()->admin()->create();
```

## Database Conventions

### Migration Naming

```php
// Create table
2024_01_01_000000_create_users_table.php

// Add column
2024_01_02_000000_add_phone_to_users_table.php

// Add index
2024_01_03_000000_add_index_to_users_email.php
```

### Table Names

- Plural, snake_case: `users`, `oauth_tokens`, `authentication_logs`
- Pivot tables: alphabetically ordered, singular: `organization_user`

### Column Names

```php
// Good
$table->string('first_name');
$table->timestamp('email_verified_at')->nullable();
$table->foreignId('organization_id')->constrained();

// Foreign keys
$table->foreignId('user_id')->constrained()->cascadeOnDelete();
```

## API Design

### RESTful Endpoints

```php
GET    /api/v1/users           # List users
POST   /api/v1/users           # Create user
GET    /api/v1/users/{id}      # Show user
PUT    /api/v1/users/{id}      # Update user (full)
PATCH  /api/v1/users/{id}      # Update user (partial)
DELETE /api/v1/users/{id}      # Delete user
```

### Response Format

```php
// Success response
return response()->json([
    'data' => $resource,
    'message' => 'User created successfully',
], 201);

// Error response
return response()->json([
    'message' => 'Validation failed',
    'errors' => $validator->errors(),
], 422);

// Paginated response
return UserResource::collection(
    User::paginate(15)
);
```

### Versioning

```php
// Route versioning
Route::prefix('v1')->group(function () {
    Route::apiResource('users', UserController::class);
});

Route::prefix('v2')->group(function () {
    Route::apiResource('users', V2\UserController::class);
});
```

## Documentation

### PHPDoc Blocks

```php
/**
 * Create a new user with the given data.
 *
 * @param array<string, mixed> $data The user data
 * @return User The created user
 * @throws ValidationException If validation fails
 */
public function createUser(array $data): User
{
    // Implementation
}
```

### Inline Comments

```php
// Good - Explain WHY, not WHAT
// Refresh token must be rotated for security compliance
$token->refresh();

// Bad - States the obvious
// Set the name variable
$name = $user->name;
```

## Code Organization

### File Structure

```
app/
├── Console/
├── Exceptions/
├── Filament/
│   ├── Resources/
│   └── Widgets/
├── Http/
│   ├── Controllers/
│   ├── Middleware/
│   ├── Requests/
│   └── Resources/
├── Models/
├── Policies/
├── Providers/
├── Rules/
└── Services/
```

### Class Organization

```php
class User extends Model
{
    // Constants
    public const STATUS_ACTIVE = 'active';
    
    // Traits
    use HasFactory, SoftDeletes;
    
    // Properties
    protected $fillable = [];
    protected $casts = [];
    
    // Relationships
    public function posts(): HasMany {}
    
    // Accessors/Mutators
    protected function name(): Attribute {}
    
    // Public methods
    public function activate(): void {}
    
    // Protected methods
    protected function someHelper(): void {}
}
```

---

**Remember**: These are guidelines, not strict rules. Use your best judgment, and when in doubt, prioritize readability and maintainability.
