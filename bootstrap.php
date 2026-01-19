<?php

    session_start();

    error_reporting(1);

    require './vendor/autoload.php';

    // Load environment variables
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();

    $app =  new \Slim\App([
        'settings' => [
            'displayErrorDetails' => filter_var($_ENV['APP_DEBUG'] ?? true, FILTER_VALIDATE_BOOLEAN),
        ],
    ]);

    $container = $app->getContainer();

    $container['view'] = function ($container) {
        $view = new \Slim\Views\Twig(__DIR__.'/views',[
            'cache' => false
        ]);

        $basePath = rtrim(str_ireplace('index.php','',$container['request']->getUri()->getBasePath()),'/');
        $view->addExtension(new Slim\Views\TwigExtension($container['router'],$basePath));
        
        // Add base_url function
        $view->getEnvironment()->addFunction(new \Twig\TwigFunction('base_url', function() use ($container) {
            $uri = $container['request']->getUri();
            return $uri->getScheme() . '://' . $uri->getHost() . ($uri->getPort() ? ':' . $uri->getPort() : '') . rtrim($uri->getBasePath(), '/');
        }));

        return $view;
    };

    $container['notFoundHandler'] = function ($container) {
        return function ($request, $response) use ($container) {
            return $container['view']->render($response, 'notFound.html');
        };
    };

    $container['db'] = function(){
        $host = $_ENV['DB_HOST'];
        $dbname = $_ENV['DB_NAME'];
        $username = $_ENV['DB_USER'];
        $password = $_ENV['DB_PASS'];
        return new PDO("mysql:host={$host};dbname={$dbname}", $username, $password);
    };

    $container['flash'] = function(){
        return new \Slim\Flash\Messages;
    };

    require './router.php';
    
?>