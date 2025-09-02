<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BulkInviteUsersRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return auth()->check() && auth()->user()->can('organization.manage_invitations');
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'invitations' => 'required|array|min:1|max:100',
            'invitations.*.email' => 'required|email|max:255',
            'invitations.*.role' => 'sometimes|string|max:255',
            'invitations.*.custom_role_id' => 'sometimes|integer|exists:custom_roles,id',
            'invitations.*.send_email' => 'sometimes|boolean',
            'invitations.*.expires_in_days' => 'sometimes|integer|min:1|max:30',
            'invitations.*.metadata' => 'sometimes|array',
        ];
    }

    /**
     * Get custom messages for validation errors
     */
    public function messages(): array
    {
        return [
            'invitations.required' => 'At least one invitation is required.',
            'invitations.max' => 'Cannot send more than 100 invitations at once.',
            'invitations.*.email.required' => 'Email is required for each invitation.',
            'invitations.*.email.email' => 'Each email must be a valid email address.',
            'invitations.*.custom_role_id.exists' => 'The selected custom role does not exist.',
        ];
    }

    /**
     * Get custom attribute names for validation errors
     */
    public function attributes(): array
    {
        return [
            'invitations.*.email' => 'email',
            'invitations.*.role' => 'role',
            'invitations.*.custom_role_id' => 'custom role',
        ];
    }
}
