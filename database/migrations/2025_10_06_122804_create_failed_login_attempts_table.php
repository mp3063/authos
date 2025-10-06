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
        Schema::create('failed_login_attempts', function (Blueprint $table) {
            $table->id();
            $table->string('email');
            $table->string('ip_address');
            $table->string('user_agent')->nullable();
            $table->string('attempt_type')->default('password'); // password, mfa, social
            $table->text('failure_reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('attempted_at');
            $table->timestamps();

            $table->index(['ip_address', 'attempted_at']);
            $table->index(['email', 'attempted_at']);
            $table->index('attempted_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('failed_login_attempts');
    }
};
