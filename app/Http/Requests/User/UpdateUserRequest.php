<?php

namespace App\Http\Requests\User;

use App\Models\User;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class UpdateUserRequest extends FormRequest
{
    private ?User $target = null;

    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $caller = $this->user();
        $target = $this->target();

        if ($target->is($caller)) {
            return $caller->hasOrganizationPermission('users.update');
        }

        return $caller->can('update', $target);
    }

    private function target(): User
    {
        $caller = $this->user();

        return $this->target ??= User::query()
            ->when(! $caller->isSuperAdmin(), fn ($query) => $query
                ->whereNotNull('organization_id')
                ->where('organization_id', $caller->organization_id))
            ->findOrFail($this->route('id'));
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        $userId = $this->target()->id;

        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => [
                'sometimes',
                'email',
                'max:255',
                Rule::unique('users', 'email')->ignore($userId),
            ],
            'password' => $this->user()->isSuperAdmin()
                ? [
                    'sometimes',
                    'string',
                    Password::min(8)
                        ->mixedCase()
                        ->numbers()
                        ->symbols()
                        ->uncompromised(),
                ]
                : ['prohibited'],
            'organization_id' => $this->user()->isSuperAdmin()
                ? ['sometimes', 'integer', 'exists:organizations,id']
                : ['prohibited'],
            'profile' => ['sometimes', 'array'],
            'profile.timezone' => ['sometimes', 'string', 'timezone'],
            'profile.language' => ['sometimes', 'string', 'in:en,es,fr,de,it,pt,nl,ru,ja,zh'],
            'profile.theme' => ['sometimes', 'string', 'in:light,dark,auto'],
            'profile.department' => ['sometimes', 'string', 'max:100'],
            'profile.job_title' => ['sometimes', 'string', 'max:100'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException(
            response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422)
        );
    }
}
