<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::table('users')
            ->whereNotNull('two_factor_recovery_codes')
            ->orderBy('id')
            ->select(['id', 'two_factor_recovery_codes'])
            ->chunkById(500, function ($users): void {
                foreach ($users as $user) {
                    $decoded = json_decode($user->two_factor_recovery_codes, true);

                    if (is_string($decoded) && is_array(json_decode($decoded, true))) {
                        DB::table('users')->where('id', $user->id)->update(['two_factor_recovery_codes' => $decoded]);
                    }
                }
            });
    }

    public function down(): void {}
};
