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
        Schema::table('users', function (Blueprint $table) {
            // Add organization_id column with foreign key constraint
            $table->unsignedBigInteger('organization_id')->nullable()->after('profile');
            $table->timestamp('password_changed_at')->nullable()->after('organization_id');
            $table->boolean('is_active')->default(true)->after('password_changed_at');
            
            // Add foreign key constraint if organizations table exists
            if (Schema::hasTable('organizations')) {
                $table->foreign('organization_id')->references('id')->on('organizations')->onDelete('set null');
            }
            
            // Add index for better performance
            $table->index(['organization_id']);
            $table->index(['is_active']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Drop foreign key constraint first
            if (Schema::hasTable('organizations')) {
                $table->dropForeign(['organization_id']);
            }
            
            // Drop indexes
            $table->dropIndex(['organization_id']);
            $table->dropIndex(['is_active']);
            
            // Drop columns
            $table->dropColumn([
                'organization_id',
                'password_changed_at',
                'is_active'
            ]);
        });
    }
};
