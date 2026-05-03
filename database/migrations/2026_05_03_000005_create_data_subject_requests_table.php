<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('data_subject_requests', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('request_type', 32);                 // access | rectification | deletion | portability | restriction
            $table->string('status', 32)->default('pending');   // pending | in_progress | completed | rejected
            $table->timestamp('requested_at');
            $table->timestamp('completed_at')->nullable();
            $table->text('notes')->nullable();
            $table->foreignId('handled_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['organization_id', 'status'], 'dsr_org_status_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('data_subject_requests');
    }
};
