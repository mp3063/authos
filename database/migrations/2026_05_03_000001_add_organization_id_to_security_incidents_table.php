<?php

use App\Models\SecurityIncident;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_incidents', function (Blueprint $table) {
            $table->foreignId('organization_id')
                ->nullable()
                ->after('user_id')
                ->constrained()
                ->nullOnDelete();

            $table->index(['organization_id', 'status', 'detected_at'], 'sec_inc_org_status_detected_idx');
        });

        // Backfill organization_id from users table. Portable across PostgreSQL/SQLite.
        // Anonymous-attacker rows (user_id IS NULL) remain organization_id NULL by design.
        SecurityIncident::query()
            ->whereNotNull('user_id')
            ->whereNull('organization_id')
            ->select(['id', 'user_id'])
            ->chunkById(1000, function ($incidents): void {
                $userIds = $incidents->pluck('user_id')->unique()->all();
                $userOrgMap = DB::table('users')
                    ->whereIn('id', $userIds)
                    ->pluck('organization_id', 'id');

                foreach ($incidents as $incident) {
                    $orgId = $userOrgMap->get($incident->user_id);
                    if ($orgId !== null) {
                        DB::table('security_incidents')
                            ->where('id', $incident->id)
                            ->update(['organization_id' => $orgId]);
                    }
                }
            });
    }

    public function down(): void
    {
        Schema::table('security_incidents', function (Blueprint $table) {
            $table->dropIndex('sec_inc_org_status_detected_idx');
            $table->dropConstrainedForeignId('organization_id');
        });
    }
};
