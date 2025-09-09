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
        Schema::create('sso_configurations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('application_id')->constrained()->onDelete('cascade');
            $table->string('name')->nullable();
            $table->string('provider')->nullable(); // oidc, saml2, etc.
            $table->string('logout_url');
            $table->string('callback_url');
            $table->json('allowed_domains');
            $table->integer('session_lifetime')->default(3600); // seconds
            $table->json('settings')->nullable();
            $table->json('configuration')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->unique('application_id');
            $table->index(['is_active']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sso_configurations');
    }
};
