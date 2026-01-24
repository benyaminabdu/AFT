<?php

    use App\Controllers\AppController;

    $app->get('/', AppController::class.':index')->setName('index');

    $app->get('/acceptor', AppController::class.':acceptor')->setName('acceptor');

    $app->post('/token', AppController::class.':transientToken')->setName('transientToken');

    $app->get('/errorPage', AppController::class.':errorPage')->setName('errorPage');

?>