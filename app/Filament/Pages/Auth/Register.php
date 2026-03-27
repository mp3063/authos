<?php

namespace App\Filament\Pages\Auth;

use App\Filament\Pages\Auth\Concerns\HasSocialLoginButtons;
use App\Models\Organization;
use Filament\Auth\Pages\Register as BaseRegister;
use Filament\Forms\Components\Select;
use Filament\Schemas\Components\Html;
use Filament\Schemas\Components\RenderHook;
use Filament\Schemas\Schema;
use Filament\View\PanelsRenderHook;

class Register extends BaseRegister
{
    use HasSocialLoginButtons;

    public function form(Schema $schema): Schema
    {
        return $schema
            ->components([
                $this->getOrganizationFormComponent(),
                $this->getNameFormComponent(),
                $this->getEmailFormComponent(),
                $this->getPasswordFormComponent(),
                $this->getPasswordConfirmationFormComponent(),
            ]);
    }

    /**
     * @throws \Throwable
     */
    protected function getOrganizationFormComponent(): Select
    {
        return Select::make('organization_id')
            ->label('Organization')
            ->options(
                Organization::where('is_active', true)
                    ->get()
                    ->filter(function (Organization $organization): bool {
                        $settings = $organization->settings ?? [];

                        return ! isset($settings['allow_registration']) || $settings['allow_registration'] !== false;
                    })
                    ->pluck('name', 'id')
                    ->toArray()
            )
            ->searchable()
            ->placeholder('Select an organization')
            ->required()
            ->helperText('Choose the organization you want to join.');
    }

    public function content(Schema $schema): Schema
    {
        return $schema
            ->components([
                RenderHook::make(PanelsRenderHook::AUTH_REGISTER_FORM_BEFORE),
                $this->getFormContentComponent(),
                RenderHook::make(PanelsRenderHook::AUTH_REGISTER_FORM_AFTER),
                Html::make($this->renderSocialButtons('Sign up with')),
            ]);
    }
}
