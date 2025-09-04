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
        Schema::create('user_custom_roles', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('custom_role_id')->constrained()->onDelete('cascade');
            $table->timestamp('granted_at')->nullable();
            $table->foreignId('granted_by')->nullable()->constrained('users')->onDelete('cascade');
            $table->timestamps();

            // Unique constraint to prevent duplicate role assignments
            $table->unique(['user_id', 'custom_role_id'], 'user_custom_role_unique');
            
            // Indexes for performance
            $table->index(['user_id', 'granted_at']);
            $table->index(['custom_role_id', 'granted_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_custom_roles');
    }
};
