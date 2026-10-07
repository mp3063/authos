<?php

namespace App\Rules;

use App\Models\User;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Translation\PotentiallyTranslatedString;
use Override;

class CurrentPasswordMatches implements ValidationRule
{
    public function __construct(private readonly ?User $user) {}

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    #[Override]
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! Hash::check($value, $this->user->password)) {
            $fail('The current password is incorrect.');
        }
    }
}
