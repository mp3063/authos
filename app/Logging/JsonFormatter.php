<?php

namespace App\Logging;

use Monolog\Formatter\JsonFormatter as MonologJsonFormatter;

class JsonFormatter
{
    /**
     * Customize the given logger instance.
     */
    public function __invoke($logger): void
    {
        foreach ($logger->getHandlers() as $handler) {
            $handler->setFormatter(new MonologJsonFormatter(
                dateFormat: 'Y-m-d H:i:s.u'
            ));
        }
    }
}
