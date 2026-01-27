<?php

namespace App\Filament\Resources\Invitations\Pages;

use App\Filament\Resources\Invitations\InvitationResource;
use App\Models\Organization;
use App\Services\InvitationService;
use Filament\Actions\Action;
use Filament\Actions\CreateAction;
use Filament\Forms\Components\FileUpload;
use Filament\Forms\Components\Select;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;

class ListInvitations extends ListRecords
{
    protected static string $resource = InvitationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
            Action::make('bulkCsvInvite')
                ->label('Bulk Invite (CSV)')
                ->icon('heroicon-o-arrow-up-tray')
                ->form([
                    Select::make('organization_id')
                        ->label('Organization')
                        ->options(Organization::pluck('name', 'id'))
                        ->required()
                        ->searchable(),
                    FileUpload::make('csv_file')
                        ->label('CSV File')
                        ->acceptedFileTypes(['text/csv', 'text/plain', 'application/vnd.ms-excel'])
                        ->helperText('CSV with columns: email, role (optional). One invitation per row.')
                        ->required()
                        ->disk('local')
                        ->directory('csv-imports')
                        ->visibility('private'),
                ])
                ->action(function (array $data, InvitationService $invitationService): void {
                    $path = storage_path('app/private/'.$data['csv_file']);

                    if (! file_exists($path)) {
                        Notification::make()
                            ->title('CSV file not found')
                            ->danger()
                            ->send();

                        return;
                    }

                    $handle = fopen($path, 'r');
                    if ($handle === false) {
                        Notification::make()
                            ->title('Failed to read CSV file')
                            ->danger()
                            ->send();

                        return;
                    }

                    $invitations = [];
                    $header = fgetcsv($handle);

                    while (($row = fgetcsv($handle)) !== false) {
                        if (empty($row[0])) {
                            continue;
                        }

                        $invitations[] = [
                            'email' => trim($row[0]),
                            'role' => isset($row[1]) ? trim($row[1]) : 'user',
                        ];
                    }

                    fclose($handle);
                    @unlink($path);

                    if (empty($invitations)) {
                        Notification::make()
                            ->title('No valid rows found in CSV')
                            ->warning()
                            ->send();

                        return;
                    }

                    $result = $invitationService->bulkInvite(
                        $data['organization_id'],
                        $invitations,
                        auth()->user()
                    );

                    $successCount = count($result['success'] ?? []);
                    $failCount = count($result['failed'] ?? []);

                    Notification::make()
                        ->title("Bulk invite complete: {$successCount} sent, {$failCount} failed")
                        ->success()
                        ->send();
                }),
        ];
    }
}
