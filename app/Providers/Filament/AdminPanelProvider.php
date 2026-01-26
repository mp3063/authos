<?php

namespace App\Providers\Filament;

use Filament\Http\Middleware\Authenticate;
use Filament\Http\Middleware\AuthenticateSession;
use Filament\Http\Middleware\DisableBladeIconComponents;
use Filament\Http\Middleware\DispatchServingFilamentEvent;
use Filament\Navigation\NavigationGroup;
use Filament\Panel;
use Filament\PanelProvider;
use Filament\Support\Colors\Color;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;

class AdminPanelProvider extends PanelProvider
{
    public function panel(Panel $panel): Panel
    {
        try {
            return $panel
                ->id('admin')
                ->path('admin')
                ->default()
                ->login(\App\Filament\Pages\Auth\Login::class)
                ->registration(\App\Filament\Pages\Auth\Register::class)
                ->passwordReset()
                ->profile()
                ->emailVerification()
                ->colors([
                    'primary' => Color::Blue,
                    'gray' => Color::Slate,
                    'success' => Color::Green,
                    'warning' => Color::Amber,
                    'danger' => Color::Red,
                    'info' => Color::Sky,
                ])
                ->brandName('AuthOS')
                ->viteTheme('resources/css/filament/admin/theme.css')
                ->pages([
                    \App\Filament\Pages\Dashboard::class,
                ])
                ->navigationGroups([
                    NavigationGroup::make()
                        ->label('Dashboard')
                        ->icon('heroicon-o-home')
                        ->collapsible(false),
                    NavigationGroup::make()
                        ->label('User Management')
                        ->icon('heroicon-o-users')
                        ->collapsible()
                        ->collapsed(),
                    NavigationGroup::make()
                        ->label('OAuth Management')
                        ->icon('heroicon-o-key')
                        ->collapsible()
                        ->collapsed(),
                    NavigationGroup::make()
                        ->label('Security & Monitoring')
                        ->icon('heroicon-o-shield-check')
                        ->collapsible()
                        ->collapsed(),
                    NavigationGroup::make()
                        ->label('Access Control')
                        ->icon('heroicon-o-lock-closed')
                        ->collapsible()
                        ->collapsed(),
                    NavigationGroup::make()
                        ->label('System')
                        ->icon('heroicon-o-cog-6-tooth')
                        ->collapsible()
                        ->collapsed(),
                ])
                ->middleware([
                    EncryptCookies::class,
                    AddQueuedCookiesToResponse::class,
                    StartSession::class,
                    AuthenticateSession::class,
                    ShareErrorsFromSession::class,
                    VerifyCsrfToken::class,
                    SubstituteBindings::class,
                    DisableBladeIconComponents::class,
                    DispatchServingFilamentEvent::class,
                ])
                ->authMiddleware([
                    Authenticate::class,
                ])
                ->plugins([
                    // MFA and security plugins will be added here
                ])
                ->discoverResources(in: app_path('Filament/Resources'), for: 'App\\Filament\\Resources')
                ->discoverPages(in: app_path('Filament/Pages'), for: 'App\\Filament\\Pages')
                ->discoverWidgets(in: app_path('Filament/Widgets'), for: 'App\\Filament\\Widgets');
        } catch (\Throwable $e) {
            \Log::error('AdminPanelProvider error: '.$e->getMessage());
            \Log::error('Stack trace: '.$e->getTraceAsString());
            throw $e;
        }
    }
}
