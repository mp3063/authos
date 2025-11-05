<?php

namespace Tests\Unit\{Category};

use PHPUnit\Framework\TestCase;

/**
 * Template for Unit Tests
 *
 * Unit tests verify isolated logic without external dependencies.
 * Use for complex algorithms, business logic, and validation rules.
 *
 * When to use Unit tests:
 * ✓ Complex algorithms (PKCE, token generation, rate limiting)
 * ✓ Pure business logic with many edge cases
 * ✓ Validation rules with multiple conditions
 * ✓ Error handling and exception scenarios
 * ✓ Background jobs that can't be triggered via HTTP
 *
 * When NOT to use Unit tests:
 * ✗ Testing framework features (Eloquent relationships, casts)
 * ✗ Testing implementation details (private methods, internal state)
 * ✗ Testing flows that can be covered by E2E tests
 *
 * @group unit
 * @group {category}
 */
class ExampleServiceTest extends TestCase
{
    /**
     * The service under test
     */
    private $service;

    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Instantiate the service/class under test
        $this->service = new \App\Services\ExampleService();
    }

    /**
     * Test basic success scenario
     *
     * @test
     */
    public function method_returns_expected_result_for_valid_input()
    {
        // ARRANGE: Set up input data
        $input = 'test-input';

        // ACT: Call the method
        $result = $this->service->processInput($input);

        // ASSERT: Verify result
        $this->assertEquals('expected-output', $result);
    }

    /**
     * Test edge case
     *
     * @test
     */
    public function method_handles_edge_case_correctly()
    {
        // ARRANGE: Set up edge case input
        $edgeInput = '';

        // ACT: Call the method
        $result = $this->service->processInput($edgeInput);

        // ASSERT: Verify edge case handling
        $this->assertNull($result);
    }

    /**
     * Test exception scenario
     *
     * @test
     */
    public function method_throws_exception_for_invalid_input()
    {
        // ARRANGE: Set up invalid input
        $invalidInput = null;

        // ASSERT: Verify exception is thrown
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Input cannot be null');

        // ACT: Call the method (should throw)
        $this->service->processInput($invalidInput);
    }

    /**
     * Test with multiple scenarios using data provider
     *
     * @test
     * @dataProvider inputScenarios
     */
    public function method_handles_various_inputs_correctly($input, $expected)
    {
        // ACT: Call the method
        $result = $this->service->processInput($input);

        // ASSERT: Verify result matches expected
        $this->assertEquals($expected, $result);
    }

    /**
     * Data provider for multiple scenarios
     */
    public static function inputScenarios(): array
    {
        return [
            'normal input' => ['input1', 'output1'],
            'special characters' => ['input@#$', 'output@#$'],
            'empty string' => ['', null],
            'long input' => [str_repeat('a', 1000), 'long-output'],
        ];
    }

    /**
     * Test complex algorithm with multiple assertions
     *
     * @test
     */
    public function algorithm_produces_correct_results()
    {
        // ARRANGE: Set up complex input
        $codeVerifier = str_repeat('a', 64);

        // ACT: Generate code challenge using S256 method
        $codeChallenge = $this->service->generateCodeChallenge($codeVerifier, 'S256');

        // ASSERT: Verify format
        $this->assertMatchesRegularExpression(
            '/^[A-Za-z0-9_-]{43}$/',
            $codeChallenge,
            'Code challenge must be 43 characters of base64url'
        );

        // ASSERT: Verify it's different from verifier
        $this->assertNotEquals($codeVerifier, $codeChallenge);

        // ASSERT: Verify it can be verified
        $this->assertTrue(
            $this->service->verifyCodeChallenge($codeVerifier, $codeChallenge, 'S256')
        );
    }

    /**
     * Test method with dependency injection (using mock)
     *
     * @test
     */
    public function method_with_external_dependency()
    {
        // ARRANGE: Create mock for external service
        $mockExternal = $this->createMock(\App\Services\ExternalService::class);
        $mockExternal->expects($this->once())
            ->method('fetchData')
            ->willReturn(['key' => 'value']);

        // Create service with mocked dependency
        $service = new \App\Services\ExampleService($mockExternal);

        // ACT: Call method that uses dependency
        $result = $service->processWithExternal();

        // ASSERT: Verify result
        $this->assertEquals('processed-value', $result);
    }

    /**
     * Test boundary conditions
     *
     * @test
     */
    public function method_handles_boundary_conditions()
    {
        // Test minimum boundary
        $minResult = $this->service->calculate(0);
        $this->assertEquals(0, $minResult);

        // Test maximum boundary
        $maxResult = $this->service->calculate(PHP_INT_MAX);
        $this->assertIsInt($maxResult);

        // Test just below boundary
        $belowResult = $this->service->calculate(-1);
        $this->assertEquals(0, $belowResult);

        // Test just above boundary
        $aboveResult = $this->service->calculate(101);
        $this->assertEquals(100, $aboveResult);
    }

    /**
     * Test performance characteristics (optional)
     *
     * @test
     */
    public function method_executes_within_performance_bounds()
    {
        // ARRANGE: Large input
        $largeInput = str_repeat('data', 10000);

        // ACT: Time the execution
        $start = microtime(true);
        $result = $this->service->processInput($largeInput);
        $duration = microtime(true) - $start;

        // ASSERT: Verify it completes within acceptable time
        $this->assertLessThan(
            0.1,
            $duration,
            'Method should complete within 100ms for large input'
        );

        // ASSERT: Result is still correct
        $this->assertNotNull($result);
    }
}
