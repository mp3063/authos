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
        Schema::create('webhook_deliveries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('webhook_id')->constrained()->cascadeOnDelete();
            $table->string('event_type', 100)->index();
            $table->json('payload'); // Full event payload sent
            $table->string('status', 50)->default('pending'); // pending, sending, success, failed, retrying
            $table->integer('http_status_code')->nullable();
            $table->text('response_body')->nullable(); // Truncated to 10KB
            $table->json('response_headers')->nullable();
            $table->text('error_message')->nullable();
            $table->integer('attempt_number')->default(1);
            $table->integer('max_attempts')->default(6);
            $table->timestamp('next_retry_at')->nullable();
            $table->string('signature', 255);
            $table->integer('request_duration_ms')->nullable();
            $table->timestamp('sent_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();

            // Indexes for performance and queries
            $table->index(['webhook_id', 'created_at']);
            $table->index(['status', 'next_retry_at']);
            $table->index(['event_type', 'created_at']);
            $table->index(['webhook_id', 'status', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webhook_deliveries');
    }
};
