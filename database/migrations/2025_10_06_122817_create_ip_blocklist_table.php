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
        Schema::create('ip_blocklist', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->unique();
            $table->string('block_type'); // temporary, permanent, suspicious
            $table->string('reason');
            $table->text('description')->nullable();
            $table->timestamp('blocked_at');
            $table->timestamp('expires_at')->nullable(); // Null for permanent blocks
            $table->foreignId('blocked_by')->nullable()->constrained('users')->onDelete('set null'); // Admin who blocked
            $table->integer('incident_count')->default(0);
            $table->json('metadata')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['ip_address', 'is_active']);
            $table->index('expires_at');
            $table->index('block_type');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ip_blocklist');
    }
};
