<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scheduled_compliance_reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->foreignId('created_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('report_type', 32);     // soc2 | iso27001 | gdpr
            $table->string('frequency', 32);       // daily | weekly | monthly | quarterly
            $table->json('recipients');
            $table->timestamp('next_run_at');
            $table->timestamp('last_run_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['is_active', 'next_run_at'], 'sched_comp_active_next_idx');
            $table->index(['organization_id', 'is_active'], 'sched_comp_org_active_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scheduled_compliance_reports');
    }
};
