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
        Schema::table('ldap_configurations', function (Blueprint $table) {
            $table->string('sync_status')->nullable()->after('last_sync_at'); // 'pending', 'processing', 'completed', 'failed'
            $table->json('last_sync_result')->nullable()->after('sync_status');
            $table->text('last_sync_error')->nullable()->after('last_sync_result');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('ldap_configurations', function (Blueprint $table) {
            $table->dropColumn(['sync_status', 'last_sync_result', 'last_sync_error']);
        });
    }
};
