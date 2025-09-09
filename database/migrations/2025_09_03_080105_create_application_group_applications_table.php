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
        Schema::create('application_group_applications', function (Blueprint $table) {
            $table->id();
            $table->foreignId('application_group_id')->constrained()->onDelete('cascade');
            $table->foreignId('application_id')->constrained()->onDelete('cascade');
            $table->timestamps();

            // Unique constraint to prevent duplicates
            $table->unique(['application_group_id', 'application_id']);

            // Indexes for better performance
            $table->index('application_group_id');
            $table->index('application_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('application_group_applications');
    }
};
