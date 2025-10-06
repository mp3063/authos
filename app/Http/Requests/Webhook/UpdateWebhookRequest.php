<?php

namespace App\Http\Requests\Webhook;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateWebhookRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('webhooks.update');
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => 'sometimes|string|max:255',
            'url' => 'sometimes|url|max:2048',
            'events' => 'sometimes|array|min:1',
            'events.*' => [
                'required',
                'string',
                Rule::exists('webhook_events', 'name')->where('is_active', true),
            ],
            'is_active' => 'sometimes|boolean',
            'description' => 'sometimes|nullable|string|max:1000',
            'custom_headers' => 'sometimes|nullable|array|max:10',
            'custom_headers.*' => 'string|max:1000',
            'timeout_seconds' => 'sometimes|integer|min:1|max:30',
            'ip_whitelist' => 'sometimes|nullable|array|max:20',
            'ip_whitelist.*' => 'ip',
            'metadata' => 'sometimes|nullable|array',
        ];
    }

    /**
     * Get custom validation messages.
     */
    public function messages(): array
    {
        return [
            'url.url' => 'Webhook URL must be a valid URL',
            'events.min' => 'At least one event must be selected',
            'events.*.exists' => 'Selected event is not valid or inactive',
            'custom_headers.max' => 'Maximum of 10 custom headers allowed',
            'timeout_seconds.min' => 'Timeout must be at least 1 second',
            'timeout_seconds.max' => 'Timeout cannot exceed 30 seconds',
            'ip_whitelist.max' => 'Maximum of 20 IP addresses allowed',
            'ip_whitelist.*.ip' => 'All whitelist entries must be valid IP addresses',
        ];
    }

    /**
     * Prepare data for validation.
     */
    protected function prepareForValidation(): void
    {
        // Ensure custom_headers is an object/array, not a string
        if ($this->has('custom_headers') && is_string($this->custom_headers)) {
            $this->merge([
                'custom_headers' => json_decode($this->custom_headers, true) ?? [],
            ]);
        }
    }

    /**
     * Get validated data with field name mapping
     */
    public function validated($key = null, $default = null): array
    {
        $validated = parent::validated();

        // Rename custom_headers to headers (database field name)
        if (isset($validated['custom_headers'])) {
            $validated['headers'] = $validated['custom_headers'];
            unset($validated['custom_headers']);
        }

        return $validated;
    }
}
