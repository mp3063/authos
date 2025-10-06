<?php

namespace App\Enums;

enum WebhookDeliveryStatus: string
{
    case PENDING = 'pending';
    case SENDING = 'sending';
    case SUCCESS = 'success';
    case FAILED = 'failed';
    case RETRYING = 'retrying';

    public function getLabel(): string
    {
        return match ($this) {
            self::PENDING => 'Pending',
            self::SENDING => 'Sending',
            self::SUCCESS => 'Success',
            self::FAILED => 'Failed',
            self::RETRYING => 'Retrying',
        };
    }

    public function getColor(): string
    {
        return match ($this) {
            self::PENDING => 'gray',
            self::SENDING => 'blue',
            self::SUCCESS => 'success',
            self::FAILED => 'danger',
            self::RETRYING => 'warning',
        };
    }

    public function isTerminal(): bool
    {
        return in_array($this, [self::SUCCESS, self::FAILED]);
    }

    public function canRetry(): bool
    {
        return in_array($this, [self::FAILED, self::RETRYING]);
    }
}
