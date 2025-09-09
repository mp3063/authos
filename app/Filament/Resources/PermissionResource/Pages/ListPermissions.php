<?php

namespace App\Filament\Resources\PermissionResource\Pages;

use App\Filament\Resources\PermissionResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListPermissions extends ListRecords
{
    protected static string $resource = PermissionResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Permissions'),
            'user_management' => Tab::make('User Management')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('name', 'like', '%users%')),
            'application_management' => Tab::make('Application Management')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('name', 'like', '%applications%')),
            'system_permissions' => Tab::make('System Permissions')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('name', 'like', 'manage %')),
        ];
    }
}
