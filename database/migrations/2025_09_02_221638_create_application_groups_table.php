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
            $table->foreignId('parent_application_id')->constrained('applications')->onDelete('cascade');
            $table->json('child_application_ids')->nullable(); // Array of application IDs
            $table->boolean('cascade_permissions')->default(true);
            $table->json('settings')->nullable(); // Additional configuration
            $table->timestamps();

            // Indexes for better performance
            $table->index(['organization_id', 'parent_application_id']);
            $table->index('parent_application_id');
            
            // Unique constraint to prevent duplicate groups per organization
            $table->unique(['organization_id', 'parent_application_id', 'name']);
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
