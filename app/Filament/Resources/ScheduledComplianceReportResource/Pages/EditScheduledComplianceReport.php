<?php

namespace App\Filament\Resources\ScheduledComplianceReportResource\Pages;

use App\Filament\Resources\ScheduledComplianceReportResource;
use Filament\Actions\DeleteAction;
use Filament\Resources\Pages\EditRecord;

class EditScheduledComplianceReport extends EditRecord
{
    protected static string $resource = ScheduledComplianceReportResource::class;

    protected function getHeaderActions(): array
    {
        return [
            DeleteAction::make(),
        ];
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResource()::getUrl('index');
    }
}
