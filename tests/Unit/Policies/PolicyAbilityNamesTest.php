<?php

namespace Tests\Unit\Policies;

use App\Models\Permission;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use ReflectionMethod;
use Tests\TestCase;

class PolicyAbilityNamesTest extends TestCase
{
    #[Test]
    public function every_public_policy_ability_is_reserved_against_permission_names(): void
    {
        $abilities = collect(glob(app_path('Policies/*.php')))
            ->map(fn (string $file) => new ReflectionClass('App\\Policies\\'.basename($file, '.php')))
            ->filter(fn (ReflectionClass $class) => $class->isInstantiable())
            ->flatMap(fn (ReflectionClass $class) => collect($class->getMethods(ReflectionMethod::IS_PUBLIC))
                ->reject(fn (ReflectionMethod $method) => $method->isConstructor() || $method->getName() === 'before')
                ->map(fn (ReflectionMethod $method) => $method->getName()))
            ->unique()
            ->values();

        $this->assertSame([], $abilities->diff(Permission::POLICY_ABILITY_NAMES)->values()->all());
    }
}
