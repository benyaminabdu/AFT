<?php

    use App\Controllers\AppController;

    $app->get('/', AppController::class.':index')->setName('index');

    $app->get('/acceptor', AppController::class.':acceptor')->setName('acceptor');

    $app->post('/token', AppController::class.':transientToken')->setName('transientToken');

    $app->post('/authentication', AppController::class.':authentication')->setName('authentication');

    $app->get('/postChallenge', AppController::class.':postChallenge')->setName('postChallenge');

    $app->post('/success', AppController::class.':success')->setName('success');

    $app->get('/errorPage', AppController::class.':errorPage')->setName('errorPage');

?>