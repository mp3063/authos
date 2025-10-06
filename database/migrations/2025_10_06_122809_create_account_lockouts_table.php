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
        Schema::create('account_lockouts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained()->onDelete('cascade');
            $table->string('email'); // Store email for failed attempts without user
            $table->string('ip_address')->nullable();
            $table->string('lockout_type'); // progressive, permanent, admin_initiated
            $table->integer('attempt_count')->default(0);
            $table->timestamp('locked_at');
            $table->timestamp('unlock_at')->nullable(); // Null for permanent locks
            $table->timestamp('unlocked_at')->nullable();
            $table->string('unlock_method')->nullable(); // auto, admin, user_request
            $table->string('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'locked_at']);
            $table->index(['email', 'locked_at']);
            $table->index(['ip_address', 'locked_at']);
            $table->index('unlock_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('account_lockouts');
    }
};
