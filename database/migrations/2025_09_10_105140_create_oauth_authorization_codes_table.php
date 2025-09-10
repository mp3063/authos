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
        Schema::create('oauth_authorization_codes', function (Blueprint $table) {
            $table->string('id', 100)->primary();
            $table->unsignedBigInteger('user_id');
            $table->uuid('client_id');
            $table->json('scopes')->nullable();
            $table->text('redirect_uri');
            $table->string('code_challenge', 128)->nullable();
            $table->string('code_challenge_method', 10)->nullable();
            $table->string('state', 512)->nullable();
            $table->boolean('revoked')->default(false);
            $table->datetime('expires_at');
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->foreign('client_id')->references('id')->on('oauth_clients')->onDelete('cascade');
            $table->index(['user_id', 'client_id']);
            $table->index('expires_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('oauth_authorization_codes');
    }
};
