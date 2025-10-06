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
        Schema::create('security_incidents', function (Blueprint $table) {
            $table->id();
            $table->string('type'); // brute_force, sql_injection, xss_attempt, credential_stuffing, etc.
            $table->string('severity'); // low, medium, high, critical
            $table->string('ip_address');
            $table->string('user_agent')->nullable();
            $table->foreignId('user_id')->nullable()->constrained()->onDelete('cascade');
            $table->string('endpoint')->nullable();
            $table->text('description');
            $table->json('metadata')->nullable(); // Additional context
            $table->string('status')->default('open'); // open, investigating, resolved, false_positive
            $table->timestamp('detected_at');
            $table->timestamp('resolved_at')->nullable();
            $table->text('resolution_notes')->nullable();
            $table->string('action_taken')->nullable(); // blocked_ip, locked_account, notified_admin
            $table->timestamps();

            $table->index(['type', 'severity', 'created_at']);
            $table->index('ip_address');
            $table->index('status');
            $table->index('detected_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_incidents');
    }
};
