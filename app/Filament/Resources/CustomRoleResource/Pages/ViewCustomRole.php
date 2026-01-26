<?php

namespace App\Filament\Resources\CustomRoleResource\Pages;

use App\Filament\Resources\CustomRoleResource;
use App\Models\CustomRole;
use Filament\Actions;
use Filament\Infolists\Components\TextEntry;
use Filament\Resources\Pages\ViewRecord;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;

class ViewCustomRole extends ViewRecord
{
    protected static string $resource = CustomRoleResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\EditAction::make(),
            Actions\DeleteAction::make()
                ->hidden(fn (CustomRole $record): bool => $record->is_system),
        ];
    }

    public function infolist(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Role Details')
                    ->schema([
                        Grid::make(2)
                            ->schema([
                                TextEntry::make('name')
                                    ->label('Role Name')
                                    ->weight(FontWeight::Bold)
                                    ->copyable(),
                                TextEntry::make('display_name')
                                    ->label('Display Name'),
                                TextEntry::make('organization.name')
                                    ->label('Organization')
                                    ->badge(),
                                TextEntry::make('creator.name')
                                    ->label('Created By')
                                    ->placeholder('System'),
                                TextEntry::make('is_active')
                                    ->label('Status')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'Active' : 'Inactive')
                                    ->color(fn ($state) => $state ? 'success' : 'danger'),
                                TextEntry::make('is_system')
                                    ->label('Role Type')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'System' : 'User-Defined')
                                    ->color(fn ($state) => $state ? 'warning' : 'info'),
                                TextEntry::make('is_default')
                                    ->label('Default Role')
                                    ->badge()
                                    ->formatStateUsing(fn ($state) => $state ? 'Yes' : 'No')
                                    ->color(fn ($state) => $state ? 'success' : 'gray'),
                            ]),
                        TextEntry::make('description')
                            ->placeholder('No description provided')
                            ->columnSpanFull(),
                    ]),

                Section::make('Permissions')
                    ->schema(function () {
                        $entries = [];
                        $categories = CustomRole::getPermissionCategories();

                        foreach ($categories as $category => $permissions) {
                            $entries[] = TextEntry::make("permissions_{$this->normalizeKey($category)}")
                                ->label($category)
                                ->state(function (CustomRole $record) use ($permissions): string {
                                    $rolePermissions = $record->permissions ?? [];
                                    $matched = array_intersect($permissions, $rolePermissions);

                                    if (empty($matched)) {
                                        return 'None assigned';
                                    }

                                    return implode(', ', array_map(
                                        fn ($p) => ucfirst(str_replace('_', ' ', last(explode('.', $p)))),
                                        $matched,
                                    ));
                                })
                                ->badge()
                                ->separator(', ')
                                ->color(function (CustomRole $record) use ($permissions): string {
                                    $rolePermissions = $record->permissions ?? [];
                                    $matched = array_intersect($permissions, $rolePermissions);

                                    return empty($matched) ? 'gray' : 'success';
                                });
                        }

                        return $entries;
                    })
                    ->collapsible(),

                Section::make('Usage')
                    ->schema([
                        Grid::make(3)
                            ->schema([
                                TextEntry::make('users_count')
                                    ->label('Assigned Users')
                                    ->state(fn (CustomRole $record): int => $record->getUserCount())
                                    ->badge()
                                    ->color(fn ($state): string => $state > 0 ? 'success' : 'gray'),
                                TextEntry::make('permission_count')
                                    ->label('Total Permissions')
                                    ->state(fn (CustomRole $record): int => $record->getPermissionCount())
                                    ->badge()
                                    ->color('info'),
                                TextEntry::make('admin_status')
                                    ->label('Admin Role')
                                    ->state(fn (CustomRole $record): string => $record->isAdminRole() ? 'Yes' : 'No')
                                    ->badge()
                                    ->color(fn (CustomRole $record): string => $record->isAdminRole() ? 'danger' : 'gray'),
                            ]),
                    ]),

                Section::make('Timestamps')
                    ->schema([
                        Grid::make(3)
                            ->schema([
                                TextEntry::make('created_at')
                                    ->dateTime(),
                                TextEntry::make('updated_at')
                                    ->dateTime(),
                                TextEntry::make('deleted_at')
                                    ->dateTime()
                                    ->placeholder('Not deleted'),
                            ]),
                    ])
                    ->collapsible()
                    ->collapsed(),
            ]);
    }

    /**
     * Normalize a string to use as an array key / entry name.
     */
    private function normalizeKey(string $value): string
    {
        return str_replace([' ', '&', '-'], '_', strtolower($value));
    }
}
