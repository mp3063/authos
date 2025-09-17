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
        Schema::table('oauth_refresh_tokens', function (Blueprint $table) {
            $table->unsignedBigInteger('user_id')->nullable()->after('access_token_id');
            $table->uuid('client_id')->nullable()->after('user_id');
            $table->json('scopes')->nullable()->after('client_id');

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->foreign('client_id')->references('id')->on('oauth_clients')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table) {
            $table->dropForeign(['user_id']);
            $table->dropForeign(['client_id']);
            $table->dropColumn(['user_id', 'client_id', 'scopes']);
        });
    }
};
