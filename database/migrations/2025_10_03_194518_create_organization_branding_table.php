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
        Schema::create('organization_branding', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('logo_path')->nullable();
            $table->string('login_background_path')->nullable();
            $table->string('primary_color')->default('#3b82f6'); // Blue-500
            $table->string('secondary_color')->default('#10b981'); // Green-500
            $table->text('custom_css')->nullable();
            $table->json('email_templates')->nullable();
            $table->json('settings')->nullable();
            $table->timestamps();

            $table->unique('organization_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('organization_branding');
    }
};
