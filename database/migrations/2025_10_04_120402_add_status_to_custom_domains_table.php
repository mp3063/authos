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
        Schema::table('custom_domains', function (Blueprint $table) {
            $table->string('status')->default('pending')->after('domain');
            $table->string('verification_method')->nullable()->after('verification_code');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('custom_domains', function (Blueprint $table) {
            $table->dropColumn(['status', 'verification_method']);
        });
    }
};
