<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Schedule::command('invitations:cleanup-expired')
    ->daily()
    ->withoutOverlapping()
    ->onOneServer()
    ->runInBackground();

Schedule::command('compliance:dispatch-scheduled')
    ->everyMinute()
    ->withoutOverlapping()
    ->onOneServer();

Schedule::command('compliance:enforce-retention')
    ->dailyAt('03:00')
    ->onOneServer();

Schedule::command('compliance:cleanup-expired-reports')
    ->dailyAt('03:30')
    ->onOneServer();
