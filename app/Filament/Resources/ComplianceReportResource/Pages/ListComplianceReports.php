<?php

namespace App\Filament\Resources\ComplianceReportResource\Pages;

use App\Filament\Resources\ComplianceReportResource;
use App\Jobs\GenerateComplianceReportJob;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\User;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Forms\Components\Select;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;
use Throwable;

class ListComplianceReports extends ListRecords
{
    protected static string $resource = ComplianceReportResource::class;

    protected function getHeaderActions(): array
    {
        /** @var User|null $currentUser */
        $currentUser = Filament::auth()->user();
        $isSuperAdmin = $currentUser && $currentUser->isSuperAdmin();

        return [
            Action::make('generate')
                ->label('Generate Report')
                ->icon('heroicon-o-document-plus')
                ->color('primary')
                ->modalHeading('Generate Compliance Report')
                ->modalDescription('Generation runs synchronously and may take up to 60 seconds for large organizations.')
                ->modalSubmitActionLabel('Generate now')
                ->schema([
                    Select::make('report_type')
                        ->label('Report Type')
                        ->options([
                            ComplianceReport::TYPE_SOC2 => 'SOC 2',
                            ComplianceReport::TYPE_ISO27001 => 'ISO 27001',
                            ComplianceReport::TYPE_GDPR => 'GDPR',
                        ])
                        ->required(),

                    Select::make('organization_id')
                        ->label('Organization')
                        ->options(fn () => Organization::pluck('name', 'id')->toArray())
                        ->searchable()
                        ->required()
                        ->visible($isSuperAdmin)
                        ->default($currentUser?->organization_id),
                ])
                ->action(function (array $data) use ($currentUser, $isSuperAdmin): void {
                    $organizationId = $isSuperAdmin
                        ? (int) $data['organization_id']
                        : (int) $currentUser?->organization_id;

                    $organization = Organization::find($organizationId);
                    if (! $organization) {
                        Notification::make()
                            ->title('Organization not found')
                            ->danger()
                            ->send();

                        return;
                    }

                    try {
                        GenerateComplianceReportJob::dispatchSync(
                            $organization,
                            $data['report_type'],
                            [],
                            null,
                            null,
                            null,
                            $currentUser?->id,
                        );

                        Notification::make()
                            ->title('Compliance report generated')
                            ->body("{$data['report_type']} report ready for download.")
                            ->success()
                            ->send();
                    } catch (Throwable $e) {
                        Notification::make()
                            ->title('Report generation failed')
                            ->body($e->getMessage())
                            ->danger()
                            ->send();
                    }
                }),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Reports')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'completed' => Tab::make('Completed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', ComplianceReport::STATUS_COMPLETED))
                ->badge(fn () => static::getResource()::getEloquentQuery()
                    ->where('status', ComplianceReport::STATUS_COMPLETED)->count())
                ->badgeColor('success'),

            'generating' => Tab::make('Generating')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', ComplianceReport::STATUS_GENERATING))
                ->badge(fn () => static::getResource()::getEloquentQuery()
                    ->where('status', ComplianceReport::STATUS_GENERATING)->count())
                ->badgeColor('warning'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', ComplianceReport::STATUS_FAILED))
                ->badge(fn () => static::getResource()::getEloquentQuery()
                    ->where('status', ComplianceReport::STATUS_FAILED)->count())
                ->badgeColor('danger'),
        ];
    }
}
