<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('webhooks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('name', 255);
            $table->string('url', 500);
            $table->text('secret'); // Encrypted secrets can be longer than 255 chars
            $table->json('events'); // Array of subscribed event types
            $table->boolean('is_active')->default(true);
            $table->text('description')->nullable();
            $table->json('headers')->nullable(); // Custom headers
            $table->integer('timeout_seconds')->default(30);
            $table->json('ip_whitelist')->nullable(); // Optional IP restrictions
            $table->timestamp('last_delivered_at')->nullable();
            $table->timestamp('last_failed_at')->nullable();
            $table->integer('failure_count')->default(0);
            $table->json('metadata')->nullable(); // Custom organization data
            $table->timestamps();
            $table->softDeletes();

            // Indexes for performance
            $table->index(['organization_id', 'is_active']);
            $table->index(['organization_id', 'created_at']);
            $table->unique(['organization_id', 'url']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webhooks');
    }
};
