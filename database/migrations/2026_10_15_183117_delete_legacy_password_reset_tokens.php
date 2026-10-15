<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        DB::table('password_reset_tokens')->where('token', 'not like', '$2y$%')->delete();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void {}
};
