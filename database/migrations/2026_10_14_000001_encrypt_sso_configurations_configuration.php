<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('sso_configurations', function (Blueprint $table) {
            $table->text('configuration')->nullable()->change();
        });

        foreach ($this->rows() as $row) {
            if (! is_array(json_decode($row->configuration, true))) {
                continue;
            }

            DB::table('sso_configurations')
                ->where('id', $row->id)
                ->update(['configuration' => Crypt::encryptString($row->configuration)]);
        }
    }

    public function down(): void
    {
        foreach ($this->rows() as $row) {
            try {
                $plain = Crypt::decryptString($row->configuration);
            } catch (Throwable) {
                continue;
            }

            DB::table('sso_configurations')->where('id', $row->id)->update(['configuration' => $plain]);
        }

        Schema::table('sso_configurations', function (Blueprint $table) {
            $table->json('configuration')->nullable()->change();
        });
    }

    private function rows(): array
    {
        return DB::table('sso_configurations')
            ->whereNotNull('configuration')
            ->get(['id', 'configuration'])
            ->all();
    }
};
