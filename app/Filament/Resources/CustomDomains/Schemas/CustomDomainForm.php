<?php

namespace App\Filament\Resources\CustomDomains\Schemas;

use Filament\Actions\Action;
use Filament\Forms\Components\Placeholder;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class CustomDomainForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->schema([
                Section::make('Domain Configuration')->schema([
                    Grid::make(2)->schema([
                        Select::make('organization_id')
                            ->relationship('organization', 'name')
                            ->required()
                            ->searchable()
                            ->preload()
                            ->disabled(fn ($context) => $context === 'edit')
                            ->helperText('Organization cannot be changed after creation'),

                        TextInput::make('domain')
                            ->required()
                            ->maxLength(255)
                            ->unique(ignoreRecord: true)
                            ->placeholder('app.example.com')
                            ->helperText('Enter the custom domain for this organization')
                            ->disabled(fn ($context) => $context === 'edit')
                            ->suffixAction(
                                Action::make('copy_domain')
                                    ->icon('heroicon-o-clipboard')
                                    ->action(fn () => null)
                                    ->visible(fn ($context) => $context === 'edit')
                            ),
                    ]),

                    Toggle::make('is_active')
                        ->label('Enable Domain')
                        ->default(false)
                        ->helperText('Enable this domain after verification is complete')
                        ->disabled(fn ($record) => ! $record?->isVerified()),
                ]),

                Section::make('DNS Verification')
                    ->description('Configure DNS records to verify domain ownership')
                    ->schema([
                        Placeholder::make('verification_code')
                            ->label('Verification Code')
                            ->content(fn ($record) => $record?->verification_code ?? 'Will be generated after creation')
                            ->visible(fn ($context) => $context === 'edit'),

                        Placeholder::make('dns_instructions')
                            ->label('DNS Configuration Instructions')
                            ->content(function ($record) {
                                if (! $record) {
                                    return 'DNS instructions will appear after domain creation';
                                }

                                $records = $record->getVerificationDnsRecords();
                                $instructions = "Add these DNS records to verify your domain:\n\n";

                                foreach ($records as $dnsRecord) {
                                    $instructions .= "Type: {$dnsRecord['type']}\n";
                                    $instructions .= "Host/Name: {$dnsRecord['name']}\n";
                                    $instructions .= "Value: {$dnsRecord['value']}\n";
                                    $instructions .= "TTL: {$dnsRecord['ttl']} seconds\n\n";
                                }

                                $instructions .= "After adding these records, click 'Verify Domain' to complete verification.";

                                return $instructions;
                            })
                            ->visible(fn ($context) => $context === 'edit'),

                        Placeholder::make('verification_status')
                            ->label('Verification Status')
                            ->content(fn ($record) => $record?->verified_at
                                ? '✓ Verified on '.$record->verified_at->format('M d, Y H:i')
                                : '⏳ Pending verification - Add DNS records above')
                            ->visible(fn ($context) => $context === 'edit'),
                    ])
                    ->visible(fn ($context) => $context === 'edit'),

                Section::make('SSL Certificate')
                    ->description('SSL certificate information (automatically managed)')
                    ->schema([
                        Placeholder::make('ssl_info')
                            ->label('SSL Certificate Status')
                            ->content(fn ($record) => $record?->ssl_certificate
                                ? 'SSL Certificate installed and active'
                                : 'SSL Certificate will be provisioned after verification')
                            ->visible(fn ($context) => $context === 'edit'),
                    ])
                    ->visible(fn ($context) => $context === 'edit')
                    ->collapsible()
                    ->collapsed(),
            ]);
    }
}
