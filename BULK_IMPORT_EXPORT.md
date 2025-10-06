# Bulk User Import/Export Documentation

## Overview

The Bulk Import/Export system provides comprehensive functionality for importing and exporting users in your Laravel 12 authentication service. It supports multiple file formats (CSV, JSON, Excel), validation, error reporting, and background processing.

## Features

- **Multi-format Support**: CSV, JSON, and Excel (XLSX)
- **Validation**: Comprehensive validation before import
- **Background Processing**: Queue-based async processing
- **Error Reporting**: Detailed error reports with row-level details
- **Progress Tracking**: Real-time progress updates
- **Organization Isolation**: Multi-tenant security
- **Retry Failed Jobs**: Automatic retry capability
- **Export Filtering**: Advanced filtering options

## API Endpoints

### Import Users

**POST** `/api/v1/bulk/users/import`

Upload a file to import users.

**Request:**
```bash
curl -X POST http://authos.test/api/v1/bulk/users/import \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@users.csv" \
  -F "format=csv" \
  -F "update_existing=false" \
  -F "skip_invalid=true" \
  -F "send_invitations=false" \
  -F "auto_generate_passwords=false"
```

**Parameters:**
- `file` (required): File to import (max 10MB)
- `format` (required): File format (csv, json, xlsx)
- `update_existing` (optional): Update existing users (default: false)
- `skip_invalid` (optional): Skip invalid records (default: true)
- `send_invitations` (optional): Send email invitations (default: false)
- `auto_generate_passwords` (optional): Auto-generate passwords (default: false)
- `default_role` (optional): Default role for imported users
- `batch_size` (optional): Batch processing size (default: 100)

**Response:**
```json
{
  "success": true,
  "message": "Import job started successfully",
  "data": {
    "job_id": 1,
    "status": "pending",
    "type": "import"
  }
}
```

### Export Users

**POST** `/api/v1/bulk/users/export`

Export users to a file.

**Request:**
```bash
curl -X POST http://authos.test/api/v1/bulk/users/export \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "csv",
    "fields": ["id", "email", "name", "created_at"],
    "date_from": "2024-01-01",
    "date_to": "2024-12-31",
    "active_only": true
  }'
```

**Parameters:**
- `format` (required): Export format (csv, json, xlsx)
- `fields` (optional): Fields to include in export
- `roles` (optional): Filter by roles
- `date_from` (optional): Filter by creation date
- `date_to` (optional): Filter by creation date
- `email_verified_only` (optional): Only verified users
- `active_only` (optional): Only active users
- `limit` (optional): Limit number of records (max 10,000)

**Response:**
```json
{
  "success": true,
  "message": "Export job started successfully",
  "data": {
    "job_id": 2,
    "status": "pending",
    "type": "export"
  }
}
```

### List Import/Export Jobs

**GET** `/api/v1/bulk/imports?type=import&status=completed`

List all import/export jobs for your organization.

**Query Parameters:**
- `type` (optional): Filter by type (import, export)
- `status` (optional): Filter by status (pending, processing, completed, failed, cancelled)
- `per_page` (optional): Results per page (default: 15)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "type": "import",
      "status": "completed",
      "total_records": 100,
      "valid_records": 95,
      "invalid_records": 5,
      "processed_records": 95,
      "failed_records": 0,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "pagination": {
    "current_page": 1,
    "per_page": 15,
    "total": 1,
    "last_page": 1
  }
}
```

### Get Job Status

**GET** `/api/v1/bulk/imports/{job_id}`

Get detailed status of a specific job.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "type": "import",
    "status": "completed",
    "status_label": "Completed",
    "total_records": 100,
    "valid_records": 95,
    "invalid_records": 5,
    "processed_records": 95,
    "failed_records": 0,
    "progress_percentage": 100,
    "file_format": "csv",
    "file_size": "10.5 KB",
    "validation_report": {
      "total_records": 100,
      "valid_records": 95,
      "invalid_records": 5,
      "summary": {
        "duplicate_emails": 2,
        "invalid_emails": 2,
        "weak_passwords": 1
      }
    },
    "has_errors": true,
    "error_count": 5,
    "started_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:35:00Z",
    "processing_time": 300,
    "error_file_url": "http://authos.test/storage/exports/errors_1.csv"
  }
}
```

### Download Error Report

**GET** `/api/v1/bulk/imports/{job_id}/errors`

Download CSV file with error details.

### Download Export File

**GET** `/api/v1/bulk/exports/{job_id}/download`

Download the exported file.

### Cancel Job

**POST** `/api/v1/bulk/imports/{job_id}/cancel`

Cancel a pending or processing job.

### Retry Failed Job

**POST** `/api/v1/bulk/imports/{job_id}/retry`

Retry a failed import job.

### Delete Job

**DELETE** `/api/v1/bulk/imports/{job_id}`

Delete a completed or failed job.

## Import File Formats

### CSV Format

```csv
email,name,password,role,organization_id,metadata
john.doe@example.com,John Doe,SecurePass123,User,,"{""department"":""IT""}"
jane.smith@example.com,Jane Smith,SecurePass456,Organization Admin,,"{""department"":""HR""}"
```

**Required Fields:**
- `email`: Valid email address (unique)
- `name`: User's full name (max 255 characters)
- `password`: Password (min 8 characters, unless auto-generate is enabled)

**Optional Fields:**
- `role`: Role name (must exist in system)
- `organization_id`: Organization ID (defaults to current user's organization)
- `metadata`: Additional data in JSON format

### JSON Format

```json
{
  "users": [
    {
      "email": "john.doe@example.com",
      "name": "John Doe",
      "password": "SecurePass123",
      "role": "User",
      "metadata": {
        "department": "IT"
      }
    },
    {
      "email": "jane.smith@example.com",
      "name": "Jane Smith",
      "password": "SecurePass456",
      "role": "Organization Admin",
      "metadata": {
        "department": "HR"
      }
    }
  ]
}
```

### Excel Format

Excel files (.xlsx) follow the same structure as CSV files, with headers in the first row.

## Export File Formats

### Available Fields

- `id`: User ID
- `email`: Email address
- `name`: Full name
- `email_verified_at`: Email verification timestamp
- `created_at`: Account creation timestamp
- `updated_at`: Last update timestamp
- `organization_name`: Organization name
- `organization_id`: Organization ID
- `roles`: Comma-separated role names
- `is_active`: Active status (Yes/No)
- `mfa_enabled`: MFA status (Yes/No)
- `provider`: Login provider (Google, GitHub, etc.)

## Validation Rules

### Email Validation
- Must be valid email format
- Must be unique (unless `update_existing` is true)
- Required field

### Password Validation
- Minimum 8 characters
- Maximum 255 characters
- Required for new users (unless `auto_generate_passwords` is true)
- Not required when updating existing users

### Name Validation
- Required field
- Maximum 255 characters

### Role Validation
- Must exist in the system
- Must be accessible to the organization

## Error Handling

### Error Report Format

When errors occur, you can download a CSV error report with:

```csv
row,email,name,errors
5,invalid-email,John Doe,"Invalid email format"
7,test@example.com,Jane Smith,"Email already exists in the system"
12,user@test.com,,"Field 'name' is required"
```

### Common Errors

- **Invalid email format**: Email doesn't match RFC standards
- **Email already exists**: Duplicate email (when not updating)
- **Missing required fields**: Required fields are empty
- **Invalid role**: Role doesn't exist in system
- **Weak password**: Password doesn't meet minimum requirements

## Performance Considerations

### Batch Processing

- Default batch size: 100 records
- Recommended range: 10-500 records per batch
- Larger batches = faster processing but more memory usage

### File Size Limits

- Maximum file size: 10MB
- Estimated capacity:
  - CSV: ~50,000 users
  - JSON: ~30,000 users
  - Excel: ~40,000 users

### Processing Time

- Small files (< 100 users): 1-2 seconds
- Medium files (100-1,000 users): 5-30 seconds
- Large files (1,000-10,000 users): 1-5 minutes
- Very large files (> 10,000 users): 5-15 minutes

## Security Features

### Organization Isolation

- Users can only import/export within their organization
- Super admins have cross-organization access
- All operations are audit-logged

### File Validation

- MIME type validation
- File extension validation
- File size limits enforced
- Virus scanning (if configured)

### Data Protection

- Passwords are hashed before storage
- Sensitive data is not included in exports
- Files are stored securely with access controls

## Best Practices

### Before Import

1. **Prepare your data**
   - Use provided templates
   - Validate data externally
   - Remove duplicates

2. **Test with small batches**
   - Start with 10-50 records
   - Verify results
   - Scale up gradually

3. **Choose appropriate options**
   - `skip_invalid`: Recommended for large imports
   - `update_existing`: Use cautiously
   - `send_invitations`: Only for new user onboarding

### During Import

1. **Monitor progress**
   - Check job status regularly
   - Review validation reports
   - Download error reports if needed

2. **Handle errors**
   - Review error details
   - Fix source data
   - Retry if needed

### After Import

1. **Verify results**
   - Check user count
   - Verify role assignments
   - Test user logins

2. **Clean up**
   - Delete completed jobs after verification
   - Archive error reports
   - Update documentation

## Troubleshooting

### Import Failed

**Symptoms**: Job status shows "failed"

**Solutions**:
1. Download error report
2. Fix data issues
3. Use "Retry" button
4. Check file format

### Validation Errors

**Symptoms**: Many invalid records

**Solutions**:
1. Review error report
2. Check required fields
3. Validate email formats
4. Verify role names exist

### Timeout Errors

**Symptoms**: Job stuck in "processing"

**Solutions**:
1. Reduce batch size
2. Split large files
3. Check queue worker status
4. Contact administrator

### Permission Errors

**Symptoms**: "Unauthorized" responses

**Solutions**:
1. Verify user has `users.create` permission
2. Check organization context
3. Verify API token is valid

## Sample Files

Sample import templates are available in:
- `/storage/app/samples/users_import_template.csv`
- `/storage/app/samples/users_import_template.json`

## Queue Configuration

Ensure your queue worker is running:

```bash
herd php artisan queue:work --queue=default --tries=3 --timeout=600
```

## Monitoring

### Check Job Status

```bash
herd php artisan queue:monitor
```

### View Failed Jobs

```bash
herd php artisan queue:failed
```

### Retry Failed Jobs

```bash
herd php artisan queue:retry all
```

## Support

For issues or questions:
- Check error reports for detailed messages
- Review validation rules
- Contact support with job ID
