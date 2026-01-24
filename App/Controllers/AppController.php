<?php

    namespace App\Controllers;
    use App\Functions\Cybersource;
    use Firebase\JWT\JWT;

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
                
                $clientLibrary = $captureContext['captureContext']['ctx'][0]['data']['clientLibrary'];
                $clientLibraryIntegrity = $captureContext['captureContext']['ctx'][0]['data']['clientLibraryIntegrity'];
                $jwtToken = $captureContext['jwtToken']; // Original JWT token string for Flex SDK

                return $this->c->view->render($response,'acceptor.html', [
                    'captureContext' => $jwtToken, // Pass JWT token string to Flex SDK
                    'amount' => $amount, 
                    'reference' => $reference,
                    'clientLibrary' => $clientLibrary,
                    'clientLibraryIntegrity' => $clientLibraryIntegrity
                ]);
            }
            else {
                $this->c->flash->addMessage('error', $captureContext['message']);
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }

        }


        public function transientToken($request, $response, $args){
            
            $amount = $request->getParam('amount');
            $reference = $request->getParam('reference');
            $flexResponse = $request->getParam('flexresponse');
            
            if (empty($flexResponse)) {
                $this->c->flash->addMessage('error', 'Missing flex response token');
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }
            
            $flexData = json_decode($flexResponse, true);
            
            $jwtToken = null;
            if (is_array($flexData) && isset($flexData['key'])) {
                $jwtToken = $flexData['key'];
            } elseif (is_string($flexResponse) && strpos($flexResponse, '.') !== false && count(explode('.', $flexResponse)) === 3) {
                $jwtToken = $flexResponse;
            }
            
            if (empty($jwtToken)) {
                $this->c->flash->addMessage('error', 'Invalid flex response format');
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }
            
            $jwtParts = explode('.', $jwtToken);
            if (count($jwtParts) !== 3) {
                $this->c->flash->addMessage('error', 'Invalid JWT token format');
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }
            
            $payload = $jwtParts[1];
            $payload = str_replace(['-', '_'], ['+', '/'], $payload);
            $payload = str_pad($payload, strlen($payload) % 4, '=', STR_PAD_RIGHT);
            $decodedPayload = json_decode(base64_decode($payload), true);
            
            if ($decodedPayload === null) {
                $this->c->flash->addMessage('error', 'Failed to decode JWT payload');
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }
            
            $jti = isset($decodedPayload['jti']) ? $decodedPayload['jti'] : null;
            $maskedValue = isset($decodedPayload['content']['paymentInformation']['card']['number']['maskedValue']) 
                ? $decodedPayload['content']['paymentInformation']['card']['number']['maskedValue'] 
                : null;
            $expirationMonth = isset($decodedPayload['content']['paymentInformation']['card']['expirationMonth']['value']) 
                ? $decodedPayload['content']['paymentInformation']['card']['expirationMonth']['value'] 
                : null;
            $expirationYear = isset($decodedPayload['content']['paymentInformation']['card']['expirationYear']['value']) 
                ? $decodedPayload['content']['paymentInformation']['card']['expirationYear']['value'] 
                : null;
            
            echo "<h1>Token Processed Successfully</h1>";
            echo "<p><strong>Amount:</strong> " . htmlspecialchars($amount) . "</p>";
            echo "<p><strong>Reference:</strong> " . htmlspecialchars($reference) . "</p>";
            echo "<p><strong>JTI:</strong> " . htmlspecialchars($jti) . "</p>";
            echo "<p><strong>Masked Card Number:</strong> " . htmlspecialchars($maskedValue) . "</p>";
            echo "<p><strong>Expiration Month:</strong> " . htmlspecialchars($expirationMonth) . "</p>";
            echo "<p><strong>Expiration Year:</strong> " . htmlspecialchars($expirationYear) . "</p>";
            
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