<?php

    namespace App\Controllers;
    use App\Functions\Cybersource;

    class AppController extends Controller {

        public function index($request, $response, $args){
            return $this->c->view->render($response, 'index.html');
        }

        public function acceptor($request, $response, $args){
            
            $amount = $request->getParam('amount');
            $reference = $request->getParam('reference');

            $cybersource = new Cybersource();
            $captureContext = $cybersource->getCaptureContext();

            if($captureContext['status'] == 'success'){
                echo json_encode($captureContext);
            }
            else {
                $errorMessage = isset($captureContext['message']) ? $captureContext['message'] : 'Failed to get capture context';
                $this->c->flash->addMessage('error', $errorMessage);
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }

        }


        public function errorPage($request, $response, $args){

            $messages = $this->c->flash->getMessages();
            $errorMessage = '';

            if (isset($messages['error']) && !empty($messages['error'])) {
                $errorMessage = is_array($messages['error']) ? $messages['error'][0] : $messages['error'];
            }

            $data = [
                'errorMessage' => $errorMessage
            ];

            return $this->c->view->render($response, 'errorPage.html', $data);
        }

    }

?>