<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_consents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('consent_type', 64);      // terms | privacy | marketing | data_processing
            $table->string('terms_version', 32)->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->timestamp('given_at')->nullable();
            $table->timestamp('withdrawn_at')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'consent_type'], 'user_consents_org_type_idx');
            $table->index(['user_id', 'consent_type', 'withdrawn_at'], 'user_consents_user_type_w_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_consents');
    }
};
