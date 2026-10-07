<?php

namespace App\Rules;

use App\Models\Webhook;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Translation\PotentiallyTranslatedString;
use Override;

class MaxWebhooksPerOrganization implements ValidationRule
{
    public function __construct(private readonly int|string|null $organizationId) {}

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    #[Override]
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $webhookCount = Webhook::where('organization_id', $this->organizationId)->count();
        if ($webhookCount >= 10) {
            $fail('Maximum of 10 webhooks allowed per organization');
        }
    }
}
