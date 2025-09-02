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
        Schema::create('sso_sessions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('application_id')->constrained()->onDelete('cascade');
            $table->string('session_token')->unique();
            $table->string('refresh_token')->unique();
            $table->string('external_session_id')->nullable();
            $table->ipAddress('ip_address');
            $table->text('user_agent');
            $table->timestamp('expires_at');
            $table->timestamp('last_activity_at');
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'application_id']);
            $table->index(['session_token']);
            $table->index(['expires_at']);
            $table->index(['last_activity_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sso_sessions');
    }
};
