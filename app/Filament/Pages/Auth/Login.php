<?php

namespace App\Filament\Pages\Auth;

use Filament\Actions\Action;
use Filament\Auth\Pages\Login as BaseLogin;
use Filament\Schemas\Schema;

class Login extends BaseLogin
{
    public function form(Schema $schema): Schema
    {
        return $schema
            ->components([
                $this->getEmailFormComponent(),
                $this->getPasswordFormComponent(),
                $this->getRememberFormComponent(),
            ]);
    }

    public function getFormActions(): array
    {
        $actions = parent::getFormActions();
        $actions[] = Action::make('Sign in with Google')
            ->url('/auth/social/google')
            ->icon('heroicon-m-arrow-top-right-on-square');

        return $actions;
    }
}
