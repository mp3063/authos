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
        Schema::create('custom_roles', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->onDelete('cascade');
            $table->string('name');
            $table->string('display_name')->nullable();
            $table->text('description')->nullable();
            $table->jsonb('permissions')->default('[]');
            $table->boolean('is_system')->default(false);
            $table->foreignId('created_by')->nullable()->constrained('users')->onDelete('cascade');
            $table->boolean('is_active')->default(true);
            $table->boolean('is_default')->default(false);
            $table->timestamps();
            $table->softDeletes();

            // Unique role name per organization
            $table->unique(['organization_id', 'name'], 'custom_roles_org_name_unique');

            // Indexes for performance
            $table->index(['organization_id', 'is_active']);
            $table->index(['organization_id', 'is_system']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('custom_roles');
    }
};
