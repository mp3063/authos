<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Generic request for listing/pagination endpoints
 */
class ListRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'page' => ['sometimes', 'integer', 'min:1'],
            'per_page' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'search' => ['sometimes', 'string', 'max:255'],
            'sort' => ['sometimes', 'string', 'max:50'],
            'order' => ['sometimes', 'string', 'in:asc,desc'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'page.integer' => 'Page must be a positive integer',
            'page.min' => 'Page must be at least 1',
            'per_page.integer' => 'Per page must be a positive integer',
            'per_page.min' => 'Per page must be at least 1',
            'per_page.max' => 'Per page cannot exceed 100',
            'search.max' => 'Search term cannot exceed 255 characters',
            'order.in' => 'Order must be either "asc" or "desc"',
        ];
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(\Illuminate\Contracts\Validation\Validator $validator)
    {
        throw new \Illuminate\Http\Exceptions\HttpResponseException(
            response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422)
        );
    }

    /**
     * Get validated pagination parameters.
     */
    public function getPaginationParams(): array
    {
        return [
            'page' => $this->input('page', 1),
            'per_page' => $this->input('per_page', 15),
            'search' => $this->input('search'),
            'sort' => $this->input('sort'),
            'order' => $this->input('order', 'desc'),
        ];
    }
}
