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
        Schema::create('bulk_import_jobs', function (Blueprint $table) {
            $table->id();
            $table->enum('type', ['import', 'export', 'users'])->default('import');
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->foreignId('created_by')->constrained('users')->cascadeOnDelete();

            // Statistics
            $table->unsignedInteger('total_records')->default(0);
            $table->unsignedInteger('valid_records')->default(0);
            $table->unsignedInteger('invalid_records')->default(0);
            $table->unsignedInteger('processed_records')->default(0);
            $table->unsignedInteger('failed_records')->default(0);
            $table->unsignedInteger('successful_records')->default(0);

            // Status tracking
            $table->enum('status', ['pending', 'processing', 'completed', 'completed_with_errors', 'failed', 'cancelled'])->default('pending');

            // Configuration and results
            $table->json('options')->nullable(); // Import/export options
            $table->json('validation_report')->nullable(); // Summary of validation
            $table->json('errors')->nullable(); // Detailed error records
            $table->json('records')->nullable(); // Import records data
            $table->json('filters')->nullable(); // Export filters

            // Import/Export specific fields
            $table->string('export_type')->nullable(); // Type of export (users, applications, etc.)
            $table->string('format')->nullable(); // Export format (csv, json, xlsx)

            // File information
            $table->string('file_path')->nullable(); // Path to uploaded/generated file
            $table->string('file_format')->nullable(); // csv, json, xlsx
            $table->unsignedBigInteger('file_size')->nullable(); // In bytes
            $table->string('error_file_path')->nullable(); // Path to error report file

            // Timing
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->unsignedInteger('processing_time')->nullable(); // In seconds

            $table->timestamps();

            // Indexes for performance
            $table->index(['organization_id', 'type', 'status']);
            $table->index(['organization_id', 'created_by']);
            $table->index('status');
            $table->index('created_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('bulk_import_jobs');
    }
};
