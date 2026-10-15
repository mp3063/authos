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
        $plain = [];

        foreach ($this->rows() as $row) {
            try {
                $plain[$row->id] = Crypt::decryptString($row->configuration);
            } catch (Throwable $e) {
                throw new RuntimeException("sso_configurations row {$row->id} cannot be decrypted with the current APP_KEY; restore the key it was encrypted with before rolling back.", 0, $e);
            }
        }

        foreach ($plain as $id => $json) {
            DB::table('sso_configurations')->where('id', $id)->update(['configuration' => $json]);
        }

        Schema::table('sso_configurations', function (Blueprint $table) {
            $this->restoreJsonColumn($table);
        });
    }

    public function restoreJsonColumn(Blueprint $table): void
    {
        $table->json('configuration')->nullable()->using('"configuration"::json')->change();
    }

    private function rows(): array
    {
        return DB::table('sso_configurations')
            ->whereNotNull('configuration')
            ->get(['id', 'configuration'])
            ->all();
    }
};
