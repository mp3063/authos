<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('compliance_reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->foreignId('generated_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('scheduled_report_id')
                ->nullable()
                ->constrained('scheduled_compliance_reports')
                ->nullOnDelete();
            $table->string('report_type', 32);                       // soc2 | iso27001 | gdpr
            $table->string('status', 32)->default('generating');     // generating | completed | failed
            $table->date('period_start');
            $table->date('period_end');
            $table->string('file_path_pdf')->nullable();
            $table->string('file_path_json')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamp('generated_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->json('summary')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'report_type', 'created_at'], 'comp_rpt_org_type_created_idx');
            $table->index(['status', 'expires_at'], 'comp_rpt_status_expires_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('compliance_reports');
    }
};
