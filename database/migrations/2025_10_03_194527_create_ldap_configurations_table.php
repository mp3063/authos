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
        Schema::create('ldap_configurations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('host');
            $table->integer('port')->default(389);
            $table->string('base_dn');
            $table->string('username');
            $table->text('password'); // Encrypted
            $table->boolean('use_ssl')->default(false);
            $table->boolean('use_tls')->default(false);
            $table->string('user_filter')->nullable();
            $table->string('user_attribute')->default('uid');
            $table->boolean('is_active')->default(false);
            $table->timestamp('last_sync_at')->nullable();
            $table->json('sync_settings')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'is_active']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ldap_configurations');
    }
};
