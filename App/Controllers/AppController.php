<?php

    namespace App\Controllers;
    use App\Functions\Cybersource;
    use Firebase\JWT\JWT;

    class AppController extends Controller {

        public function index($request, $response, $args){
            return $this->c->view->render($response, 'index.html');
        }

        public function acceptor($request, $response, $args){
            
            if(
                !empty($request->getParam('amount')) &&
                !empty($request->getParam('reference')) &&
                !empty($request->getParam('recipientAccountNumber')) &&
                !empty($request->getParam('recipientFirstName')) &&
                !empty($request->getParam('recipientLastName'))
            ){

            }
            else {
                $this->c->flash->addMessage('error', "Not enough Information passed");
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }

            $amount = $request->getParam('amount');
            $reference = $request->getParam('reference');
            $recipientAccountNumber = $request->getParam('recipientAccountNumber');
            $recipientFirstName = $request->getParam('recipientFirstName');
            $recipientLastName = $request->getParam('recipientLastName');

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
                    'recipientInformation' => array(
                        'accountNumber' => $recipientAccountNumber,
                        'firstName' => $recipientFirstName,
                        'lastName' => $recipientLastName,
                    ),
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
            $firstName = $request->getParam('firstName');
            $lastName = $request->getParam('lastName');
            $reference = $request->getParam('reference');
            $recipientAccountNumber = $request->getParam('recipientAccountNumber');
            $recipientFirstName = $request->getParam('recipientFirstName');
            $recipientLastName = $request->getParam('recipientLastName');
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
            
            $amount = htmlspecialchars($amount);
            $firstName = htmlspecialchars($firstName);
            $lastName = htmlspecialchars($lastName);
            $reference = htmlspecialchars($reference);
            $jti = htmlspecialchars($jti);
            $maskedValue = htmlspecialchars($maskedValue);
            $expirationMonth = htmlspecialchars($expirationMonth);
            $expirationYear = htmlspecialchars($expirationYear);
            
            $cybersource = new Cybersource();
            $PASetup = $cybersource->PASetup($amount, $reference, $jti, $maskedValue, $expirationMonth, $expirationYear);

            if($PASetup['status'] == 'success'){
                $res = $PASetup['response'];

                $accessToken = $res['consumerAuthenticationInformation']['accessToken'] ?? null;
                $deviceDataCollectionUrl = $res['consumerAuthenticationInformation']['deviceDataCollectionUrl'] ?? null;
                $referenceId = $res['consumerAuthenticationInformation']['referenceId'] ?? null;

                $data = [
                    'amount' => $amount,
                    'firstName' => $firstName,
                    'lastName' => $lastName,
                    'reference' => $reference,
                    'recipientInformation' => array(
                        'accountNumber' => $recipientAccountNumber,
                        'firstName' => $recipientFirstName,
                        'lastName' => $recipientLastName,
                    ),
                    'jti' => $jti,
                    'maskedValue' => $maskedValue,
                    'expirationMonth' => $expirationMonth,
                    'expirationYear' => $expirationYear,
                    'accessToken' => $accessToken,
                    'deviceDataCollectionUrl' => $deviceDataCollectionUrl,
                    'referenceId' => $referenceId,
                ];

                return $this->c->view->render($response, 'dataCollection.html', $data);
            }
            else {
                $this->c->flash->addMessage('error', $PASetup['message' . "PA Setup Failed"]);
                return $response->withRedirect($this->c->router->pathFor('errorPage'));
            }
            
        }

        public function authentication($request, $response, $args){

            $sessionId = $request->getParam('sessionId');
            $firstName = $request->getParam('firstName');
            $lastName = $request->getParam('lastName');
            $amount = $request->getParam('amount');
            $reference = $request->getParam('reference');
            $recipientAccountNumber = $request->getParam('recipientAccountNumber');
            $recipientFirstName = $request->getParam('recipientFirstName');
            $recipientLastName = $request->getParam('recipientLastName');
            $jti = $request->getParam('jti');
            $maskedValue = $request->getParam('maskedValue');
            $expirationMonth = $request->getParam('expirationMonth');
            $expirationYear = $request->getParam('expirationYear');
            $referenceId = $request->getParam('referenceId');
            $accessToken = $request->getParam('accessToken');
            $deviceDataCollectionUrl = $request->getParam('deviceDataCollectionUrl');

            $deviceInfo = [
                'httpAcceptBrowserValue' => $request->getParam('httpAcceptBrowserValue'),
                'httpAcceptContent' => $request->getParam('httpAcceptContent'),
                'httpBrowserEmail' => $request->getParam('httpBrowserEmail'),
                'httpBrowserLanguage' => $request->getParam('httpBrowserLanguage'),
                'httpBrowserJavaEnabled' => $request->getParam('httpBrowserJavaEnabled'),
                'httpBrowserJavaScriptEnabled' => $request->getParam('httpBrowserJavaScriptEnabled'),
                'httpBrowserColorDepth' => $request->getParam('httpBrowserColorDepth'),
                'httpBrowserScreenHeight' => $request->getParam('httpBrowserScreenHeight'),
                'httpBrowserScreenWidth' => $request->getParam('httpBrowserScreenWidth'),
                'httpBrowserTimeDifference' => $request->getParam('httpBrowserTimeDifference'),
                'userAgentBrowserValue' => $request->getParam('userAgentBrowserValue'),
            ];

            $cybersource = new Cybersource();
            $authentication =  $cybersource->authentication($sessionId, $firstName, $lastName, $amount, $reference, $recipientAccountNumber, $recipientFirstName, $recipientLastName, $jti, $maskedValue, $expirationMonth, $expirationYear, $referenceId, $accessToken, $deviceDataCollectionUrl, $deviceInfo);
           
            if($authentication['response']['status'] == 'AUTHORIZED'){
                $responseData = $authentication['response'];
                $data = [
                    'id' => $responseData['id'] ?? null,
                    'brandName' => $responseData['paymentAccountInformation']['card']['brandName'] ?? null,
                    'sessionId' => $sessionId,
                    'firstName' => $firstName,
                    'lastName' => $lastName,
                    'amount' => $amount,
                    'reference' => $reference,
                    'recipientAccountNumber' => $recipientAccountNumber,
                    'recipientFirstName' => $recipientFirstName,
                    'recipientLastName' => $recipientLastName,
                    'jti' => $jti,
                    'maskedValue' => $maskedValue,
                    'expirationMonth' => $expirationMonth,
                    'expirationYear' => $expirationYear,
                    'referenceId' => $referenceId,
                    'accessToken' => $accessToken,
                    'deviceDataCollectionUrl' => $deviceDataCollectionUrl,
                ];

                return $this->c->view->render($response, 'successRedirector.html', $data);
            }
            else if($authentication['response']['status'] == 'PENDING_AUTHENTICATION'){
                echo "Pending Authentication, Authentication is still pending";
            }
            else {
                echo $authentication['response']['status'];
                echo "<br> Failed Charge Attempt";
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