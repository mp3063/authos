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
        Schema::create('migration_jobs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->onDelete('cascade');
            $table->string('source'); // auth0, okta, cognito, etc.
            $table->string('status')->default('pending'); // pending, running, completed, failed
            $table->json('config')->nullable(); // Migration configuration
            $table->json('stats')->nullable(); // Migration statistics
            $table->json('migrated_data')->nullable(); // Migrated user data
            $table->unsignedInteger('total_items')->default(0); // Total items to migrate
            $table->json('error_log')->nullable(); // Error details if failed
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'status']);
            $table->index('source');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('migration_jobs');
    }
};
