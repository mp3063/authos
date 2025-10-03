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
        Schema::create('custom_domains', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('domain')->unique();
            $table->string('verification_code');
            $table->timestamp('verified_at')->nullable();
            $table->json('ssl_certificate')->nullable();
            $table->json('dns_records')->nullable();
            $table->boolean('is_active')->default(false);
            $table->json('settings')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'is_active']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('custom_domains');
    }
};
