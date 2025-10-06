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
        Schema::create('webhook_events', function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->unique(); // e.g., user.created, auth.login
            $table->string('category', 50)->index(); // user, auth, org, app, mfa, sso, role
            $table->text('description');
            $table->json('payload_schema')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->string('version', 20)->default('1.0');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webhook_events');
    }
};
