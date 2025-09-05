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
            // Social login fields
            $table->string('provider')->nullable()->after('is_active');
            $table->string('provider_id')->nullable()->after('provider');
            $table->text('provider_token')->nullable()->after('provider_id');
            $table->text('provider_refresh_token')->nullable()->after('provider_token');
            $table->json('provider_data')->nullable()->after('provider_refresh_token');
            
            // Make password nullable for social-only users
            $table->string('password')->nullable()->change();
            
            // Add indexes for better performance
            $table->index(['provider', 'provider_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Drop indexes first
            $table->dropIndex(['provider', 'provider_id']);
            
            // Drop columns
            $table->dropColumn([
                'provider',
                'provider_id', 
                'provider_token',
                'provider_refresh_token',
                'provider_data'
            ]);
            
            // Restore password as required (note: this might fail if there are users without passwords)
            $table->string('password')->nullable(false)->change();
        });
    }
};
