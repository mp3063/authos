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
        return auth()->check() && auth()->user()->can('users.create');
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
            'invitations.*.role' => 'required|string|max:255',
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
            'invitations.max' => 'Cannot send more than 100 invitations at once.',
        ];
    }
}
