<?php

namespace App\Filament\Resources\UserResource\RelationManagers;

use App\Filament\Concerns\ScopesToOrganization;
use App\Models\Application;
use App\Models\UserApplication;
use Filament\Actions\Action;
use Filament\Actions\AttachAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DetachAction;
use Filament\Actions\DetachBulkAction;
use Filament\Forms;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Gate;

class ApplicationsRelationManager extends RelationManager
{
    use ScopesToOrganization;

    protected static string $relationship = 'applications';

    protected static ?string $recordTitleAttribute = 'name';

    /**
     * @throws \Throwable
     */
    public function form(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Forms\Components\Select::make('application_id')
                    ->label('Application')
                    ->relationship('', 'name')
                    ->searchable()
                    ->preload()
                    ->required(),

                Forms\Components\KeyValue::make('metadata')
                    ->label('Application Metadata')
                    ->keyLabel('Key')
                    ->valueLabel('Value')
                    ->default([])
                    ->helperText('Additional metadata for this user-application relationship'),
            ]);
    }

    /**
     * @throws \Throwable
     */
    public function table(Table $table): Table
    {
        return $table
            ->recordTitleAttribute('name')
            ->columns(components: [
                TextColumn::make('name')
                    ->searchable()
                    ->sortable()
                    ->weight('bold'),

                TextColumn::make('organization.name')
                    ->label('Organization')
                    ->searchable()
                    ->sortable()
                    ->badge(),

                TextColumn::make('client_id')
                    ->label('Client ID')
                    ->limit(20)
                    ->tooltip(fn ($record) => $record->client_id),

                Tables\Columns\IconColumn::make('is_active')
                    ->boolean()
                    ->sortable()
                    ->label('Status'),

                TextColumn::make('pivot.login_count')
                    ->label('Logins')
                    ->alignCenter()
                    ->formatStateUsing(fn ($state) => $state ?? 0)
                    ->sortable(),

                TextColumn::make('pivot.last_login_at')
                    ->label('Last Login')
                    ->dateTime()
                    ->sortable()
                    ->placeholder('Never'),

                TextColumn::make('pivot.created_at')
                    ->label('Connected')
                    ->dateTime()
                    ->sortable(),
            ])
            ->filters(filters: [
                SelectFilter::make('organization')
                    ->relationship('organization', 'name')
                    ->preload(),

                TernaryFilter::make('is_active')
                    ->label('Status')
                    ->boolean()
                    ->trueLabel('Active only')
                    ->falseLabel('Inactive only')
                    ->native(false),

                Filter::make('has_logged_in')
                    ->query(
                        fn (Builder $query): Builder => $query->whereNotNull('user_applications.last_login_at')
                    )
                    ->label('Has Logged In'),
            ])
            ->headerActions([
                AttachAction::make()
                    ->authorize(fn (): bool => Gate::allows('update', $this->getOwnerRecord()) && Gate::allows('create', UserApplication::class))
                    ->preloadRecordSelect()
                    ->recordSelectOptionsQuery(fn (Builder $query) => static::scopeToOrganization($query))
                    ->schema(fn (AttachAction $action): array => [
                        $action->getRecordSelect(),
                        Forms\Components\KeyValue::make('metadata')
                            ->label('Application Metadata')
                            ->keyLabel('Key')
                            ->valueLabel('Value')
                            ->default([]),
                    ]),
            ])
            ->recordActions([
                DetachAction::make()
                    ->authorize(fn (Application $record): bool => Gate::allows('update', $this->getOwnerRecord()) && Gate::allows('delete', $this->userApplicationFor($record)))
                    ->requiresConfirmation()
                    ->modalDescription('This will remove access to this application for the user.'),

                Action::make('view_logs')
                    ->label('View Logs')
                    ->icon('heroicon-o-eye')
                    ->url(fn ($record) => route('filament.admin.resources.authentication-logs.index', [
                        'tableFilters[user_id][value]' => $this->getOwnerRecord()->id,
                        'tableFilters[application_id][value]' => $record->id,
                    ]))
                    ->openUrlInNewTab(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DetachBulkAction::make()
                        ->authorize(fn (): bool => Gate::allows('update', $this->getOwnerRecord()) && Gate::allows('deleteAny', UserApplication::class))
                        ->authorizeIndividualRecords(fn (Application $record) => Gate::inspect('delete', $this->userApplicationFor($record)))
                        ->requiresConfirmation(),
                ]),
            ])
            ->defaultSort('user_applications.last_login_at', 'desc');
    }

    private function userApplicationFor(Application $application): UserApplication
    {
        return (new UserApplication)->forceFill(['user_id' => $this->getOwnerRecord()->getKey(), 'application_id' => $application->getKey()]);
    }
}
