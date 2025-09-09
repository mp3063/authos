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
        Schema::create('application_groups', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->onDelete('cascade');
            $table->string('name');
            $table->text('description')->nullable();
            $table->foreignId('parent_id')->nullable()->constrained('application_groups')->onDelete('cascade');
            $table->boolean('is_active')->default(true);
            $table->json('settings')->nullable(); // Additional configuration
            $table->timestamps();

            // Indexes for better performance
            $table->index(['organization_id', 'parent_id']);
            $table->index('parent_id');
            $table->index(['organization_id', 'is_active']);

            // Unique constraint to prevent duplicate groups per organization
            $table->unique(['organization_id', 'name']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('application_groups');
    }
};
