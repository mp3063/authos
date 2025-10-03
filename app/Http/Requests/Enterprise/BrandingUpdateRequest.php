<?php

namespace App\Http\Requests\Enterprise;

use Illuminate\Foundation\Http\FormRequest;

class BrandingUpdateRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('organizations.update');
    }

    public function rules(): array
    {
        return [
            'logo' => ['nullable', 'image', 'max:2048', 'mimes:png,jpg,jpeg,svg'],
            'background' => ['nullable', 'image', 'max:5120', 'mimes:png,jpg,jpeg'],
            'primary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'secondary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'custom_css' => ['nullable', 'string', 'max:50000'],
            'email_templates' => ['nullable', 'array'],
            'email_templates.*' => ['string'],
            'settings' => ['nullable', 'array'],
        ];
    }

    public function messages(): array
    {
        return [
            'logo.image' => 'Logo must be an image file',
            'logo.max' => 'Logo file size cannot exceed 2MB',
            'logo.mimes' => 'Logo must be in PNG, JPG, JPEG, or SVG format',
            'background.image' => 'Background must be an image file',
            'background.max' => 'Background file size cannot exceed 5MB',
            'background.mimes' => 'Background must be in PNG, JPG, or JPEG format',
            'primary_color.regex' => 'Primary color must be a valid hex color code (e.g., #3B82F6)',
            'secondary_color.regex' => 'Secondary color must be a valid hex color code (e.g., #10B981)',
            'custom_css.max' => 'Custom CSS cannot exceed 50000 characters',
        ];
    }
}
