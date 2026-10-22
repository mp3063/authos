<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ApiDocsPageTest extends TestCase
{
    #[Test]
    public function it_redirects_docs_to_the_swagger_page(): void
    {
        $this->get('/docs')->assertRedirect('/docs/index.html');
    }

    #[Test]
    public function it_serves_the_spec_the_swagger_page_loads(): void
    {
        $page = file_get_contents(public_path('docs/index.html'));

        $this->assertStringContainsString("url: 'openapi.yaml'", $page);
        $this->assertFileExists(public_path('docs/openapi.yaml'));
        $this->assertFileExists(public_path('docs/postman-collection.json'));
    }
}
