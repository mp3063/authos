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
        Schema::create('social_accounts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('provider'); // google, github, facebook, twitter, linkedin
            $table->string('provider_id');
            $table->string('provider_token', 1000)->nullable();
            $table->string('provider_refresh_token', 1000)->nullable();
            $table->timestamp('token_expires_at')->nullable();
            $table->string('avatar')->nullable();
            $table->string('email')->nullable();
            $table->string('name')->nullable();
            $table->json('provider_data')->nullable(); // Store additional provider-specific data
            $table->timestamps();

            // Ensure one provider per user
            $table->unique(['user_id', 'provider']);

            // Index for provider lookups
            $table->index(['provider', 'provider_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('social_accounts');
    }
};
