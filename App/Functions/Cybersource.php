<?php

    namespace App\Functions;

    use GuzzleHttp\Client;
    use GuzzleHttp\Exception\RequestException;

    class Cybersource {
    
        public function getCaptureContext(){
            
            $url = 'https://apitest.cybersource.com/microform/v2/sessions';

            $payload = json_encode([
                "targetOrigins" => [
                    "http://localhost"
                ],
                "clientVersion" => "v2",
                "allowedCardNetworks" => ["VISA", "MASTERCARD"],
                "allowedPaymentTypes" => ["CARD"]
            ], JSON_UNESCAPED_SLASHES);

            $merchantId = trim($_ENV['CYBERSOURCE_MERCHANT_ID']);
            $keyId = trim($_ENV['CYBERSOURCE_API_KEY']);
            $secretKey = trim($_ENV['CYBERSOURCE_SHARED_SECRET']);

            $resource = "/microform/v2/sessions";
            $method = "post";
            $host = "apitest.cybersource.com";
            $date = gmdate("D, d M Y H:i:s") . " GMT";
            $digest = "SHA-256=" . base64_encode(hash("sha256", $payload, true));

            $signatureString = "host: $host\n";
            $signatureString .= "date: $date\n";
            $signatureString .= "request-target: $method $resource\n";
            $signatureString .= "digest: $digest\n";
            $signatureString .= "v-c-merchant-id: $merchantId";

            $decodedSecret = base64_decode($secretKey);

            $signature = base64_encode(
                hash_hmac("sha256", $signatureString, $decodedSecret, true)
            );
            
            $signatureHeader = 'keyid="' . $keyId . '",algorithm="HmacSHA256",headers="host date request-target digest v-c-merchant-id",signature="' . $signature . '"';

            $client = new Client();

            try {
                $response = $client->post($url, [
                    'headers' => [
                        "Content-Type" => "application/json",
                        "Accept" => "application/json",
                        "Host" => $host,
                        "Date" => $date,
                        "Digest" => $digest,
                        "v-c-merchant-id" => $merchantId,
                        "Signature" => $signatureHeader
                    ],
                    'body' => $payload
                ]);

                $httpCode = $response->getStatusCode();
                $responseBody = $response->getBody()->getContents();
                
                $decodedResponse = json_decode($responseBody, true);
                
                if (is_array($decodedResponse) && isset($decodedResponse['key'])) {
                    $jwtToken = $decodedResponse['key'];
                } elseif (is_string($decodedResponse) && !empty($decodedResponse)) {
                    $jwtToken = $decodedResponse;
                } else {
                    $jwtToken = $responseBody;
                }
                
                $jwtParts = explode('.', $jwtToken);
                if (count($jwtParts) === 3) {
                    $payload = $jwtParts[1];
                    $payload = str_replace(['-', '_'], ['+', '/'], $payload);
                    $payload = str_pad($payload, strlen($payload) % 4, '=', STR_PAD_RIGHT);
                    $decodedPayload = json_decode(base64_decode($payload), true);
                    
                    if ($decodedPayload !== null) {
                        $data = array(
                            'status' => 'success',
                            'captureContext' => $decodedPayload,
                            'jwtToken' => $jwtToken
                        );
                    } else {
                        $data = array(
                            'status' => 'error',
                            'message' => 'Failed to decode JWT payload'
                        );
                    }
                } else {
                    $data = array(
                        'status' => 'error',
                        'message' => 'Invalid JWT token format received'
                    );
                }

                return $data;
            } catch (RequestException $e) {
                $errorMessage = $e->getMessage();
                
                if ($e->hasResponse()) {
                    $response = $e->getResponse();
                    $httpCode = $response->getStatusCode();
                    $responseBody = $response->getBody()->getContents();
                    
                    $decodedBody = json_decode($responseBody, true);
                    
                    if (is_string($decodedBody) && !empty($decodedBody)) {
                        $decodedBody = json_decode($decodedBody, true);
                    }
                    if ($decodedBody !== null) {
                        if (isset($decodedBody['response']['rmsg'])) {
                            $errorMessage = $decodedBody['response']['rmsg'];
                        }
                        elseif (isset($decodedBody['rmsg'])) {
                            $errorMessage = $decodedBody['rmsg'];
                        }
                        elseif (isset($decodedBody['message'])) {
                            $errorMessage = $decodedBody['message'];
                        }
                        elseif (isset($decodedBody['error'])) {
                            $errorMessage = $decodedBody['error'];
                        }
                        else {
                            $errorMessage = $responseBody;
                        }
                    } elseif (!empty($responseBody)) {
                        $errorMessage = $responseBody;
                    } else {
                        $errorMessage = "HTTP Error $httpCode: " . $errorMessage;
                    }
                }
                
                $data = array(
                    'status' => 'error',
                    'message' => $errorMessage
                );
                return $data;
            }
        }


        public function PASetup($amount, $reference, $jti, $maskedValue, $expirationMonth, $expirationYear){
            
            $url = 'https://apitest.cybersource.com/risk/v1/authentication-setups';

            $payload = json_encode([
                "clientReferenceInformation" => [
                    "code" => $reference,
                    "partner" => [
                        "developerId" => "7891234",
                        "solutionId" => "89012345"
                    ]
                ],
                "tokenInformation" => [
                    "jti" => $jti
                ]
            ], JSON_UNESCAPED_SLASHES);

            $merchantId = trim($_ENV['CYBERSOURCE_MERCHANT_ID']);
            $keyId = trim($_ENV['CYBERSOURCE_API_KEY']);
            $secretKey = trim($_ENV['CYBERSOURCE_SHARED_SECRET']);

            $resource = "/risk/v1/authentication-setups";
            $method = "post";
            $host = "apitest.cybersource.com";
            $date = gmdate("D, d M Y H:i:s") . " GMT";
            $digest = "SHA-256=" . base64_encode(hash("sha256", $payload, true));

            $signatureString = "host: $host\n";
            $signatureString .= "v-c-date: $date\n";
            $signatureString .= "request-target: $method $resource\n";
            $signatureString .= "digest: $digest\n";
            $signatureString .= "v-c-merchant-id: $merchantId";

            $decodedSecret = base64_decode($secretKey);

            $signature = base64_encode(
                hash_hmac("sha256", $signatureString, $decodedSecret, true)
            );
            
            $signatureHeader = 'keyid="' . $keyId . '", algorithm="HmacSHA256", headers="host v-c-date request-target digest v-c-merchant-id", signature="' . $signature . '"';
            
            $client = new Client();

            try {
                $response = $client->post($url, [
                    'headers' => [
                        "Content-Type" => "application/json",
                        "Host" => $host,
                        "v-c-date" => $date,
                        "Digest" => $digest,
                        "v-c-merchant-id" => $merchantId,
                        "Signature" => $signatureHeader
                    ],
                    'body' => $payload
                ]);

                $httpCode = $response->getStatusCode();
                $responseBody = $response->getBody()->getContents();
                
                $decodedResponse = json_decode($responseBody, true);
                
                if ($decodedResponse !== null) {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $decodedResponse
                    );
                } else {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $responseBody
                    );
                }

                return $data;
            } 
            catch (RequestException $e) {
                $errorMessage = $e->getMessage();
                
                if ($e->hasResponse()) {
                    $response = $e->getResponse();
                    $httpCode = $response->getStatusCode();
                    $responseBody = $response->getBody()->getContents();
                    
                    $decodedBody = json_decode($responseBody, true);
                    
                    if (is_string($decodedBody) && !empty($decodedBody)) {
                        $decodedBody = json_decode($decodedBody, true);
                    }
                    if ($decodedBody !== null) {
                        if (isset($decodedBody['response']['rmsg'])) {
                            $errorMessage = $decodedBody['response']['rmsg'];
                        }
                        elseif (isset($decodedBody['rmsg'])) {
                            $errorMessage = $decodedBody['rmsg'];
                        }
                        elseif (isset($decodedBody['message'])) {
                            $errorMessage = $decodedBody['message'];
                        }
                        elseif (isset($decodedBody['error'])) {
                            $errorMessage = $decodedBody['error'];
                        }
                        else {
                            $errorMessage = $responseBody;
                        }
                    } elseif (!empty($responseBody)) {
                        $errorMessage = $responseBody;
                    } else {
                        $errorMessage = "HTTP Error $httpCode: " . $errorMessage;
                    }
                }
                
                $data = array(
                    'status' => 'error',
                    'message' => $errorMessage
                );
                return $data;
            }
        }


        public function authentication($sessionId, $firstName, $lastName, $amount, $reference, $recipientAccountNumber, $recipientFirstName, $recipientLastName, $jti, $maskedValue, $expirationMonth, $expirationYear, $referenceId, $accessToken, $deviceDataCollectionUrl, $deviceInfo = []){

            $url = 'https://apitest.cybersource.com/pts/v2/payments';

            $get = function($key, $serverKey = null) use ($deviceInfo) {
                if (isset($deviceInfo[$key]) && $deviceInfo[$key] !== '') {
                    return $deviceInfo[$key];
                }
                if ($serverKey !== null && !empty($_SERVER[$serverKey])) {
                    return $_SERVER[$serverKey];
                }
                return '';
            };
            $getBool = function($key, $default = false) use ($deviceInfo) {
                if (!isset($deviceInfo[$key])) return $default;
                $v = $deviceInfo[$key];
                if (is_bool($v)) return $v;
                return in_array(strtolower((string)$v), ['1', 'true', 'yes'], true);
            };

            $payload = json_encode([
                'clientReferenceInformation' => [
                    'code' => $reference
                ],
                'processingInformation' => [
                    'actionList' => ['CONSUMER_AUTHENTICATION'],
                    'capture' => true,
                    'commerceIndicator' => 'internet',
                    'authorizationOptions' => [
                        'initiator' => [
                            'type' => 'customer',
                            'storedCredentialUsed' => false
                        ],
                        'aftIndicator' => true
                    ]
                ],
                'orderInformation' => [
                    'billTo' => [
                        'firstName' => $firstName,
                        'lastName' => $lastName,
                        'address1' => '1295 Charleston Road',
                        'locality' => 'Mountain View',
                        'administrativeArea' => 'CA',
                        'postalCode' => '94043',
                        'country' => 'US',
                        'email' => 'null@cybersource.com',
                    ],
                    'amountDetails' => [
                        'totalAmount' => $amount,
                        'currency' => 'USD',
                    ]
                ],
                'senderInformation' => [
                    'firstName' => $firstName,
                    'lastName' => $lastName,
                    'address1' => '1295 Charleston Road',
                    'locality' => 'Mountain View',
                    'administrativeArea' => 'CA',
                    'postalCode' => '94043',
                    'country' => 'US',
                ],
                'recipientInformation' => [
                    'accountId' => $recipientAccountNumber,
                    'firstName' => $recipientFirstName,
                    'lastName' => $recipientLastName,
                ],
                'deviceInformation' => [
                    'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '',
                    'fingerprintSessionId' => $sessionId ?: ('3f6d2df2-0701-4d6f-984c-b9b6e5c933f0'),
                    'httpAcceptBrowserValue' => $get('httpAcceptBrowserValue', 'HTTP_ACCEPT'),
                    'httpAcceptContent' => $get('httpAcceptContent', 'HTTP_ACCEPT'),
                    'httpBrowserEmail' => $get('httpBrowserEmail'),
                    'httpBrowserLanguage' => $get('httpBrowserLanguage', 'HTTP_ACCEPT_LANGUAGE'),
                    'httpBrowserJavaEnabled' => $getBool('httpBrowserJavaEnabled', false),
                    'httpBrowserJavaScriptEnabled' => $getBool('httpBrowserJavaScriptEnabled', true),
                    'httpBrowserColorDepth' => $get('httpBrowserColorDepth'),
                    'httpBrowserScreenHeight' => $get('httpBrowserScreenHeight'),
                    'httpBrowserScreenWidth' => $get('httpBrowserScreenWidth'),
                    'httpBrowserTimeDifference' => $get('httpBrowserTimeDifference'),
                    'userAgentBrowserValue' => $get('userAgentBrowserValue', 'HTTP_USER_AGENT')
                ],
                'consumerAuthenticationInformation' => [
                    'deviceChannel' => 'Browser',
                    'returnUrl' => 'https://webhook.site/24128ace-5af5-4cb9-a240-7b31c1dcacb1',
                    'referenceId' => '3f6d2df2-0701-4d6f-984c-b9b6e5c933f0'
                ],
                'merchantDefinedInformation' => [
                    [
                        'key' => 'MDD1',
                        'value' => 'Test'
                    ]
                ],
                'tokenInformation' => [
                    'jti' => $jti
                ],
                'acquirerInformation' => [
                    'merchantId' => 'aby_0001'
                ]
            ], JSON_UNESCAPED_SLASHES);

            $merchantId = trim($_ENV['CYBERSOURCE_MERCHANT_ID']);
            $keyId = trim($_ENV['CYBERSOURCE_API_KEY']);
            $secretKey = trim($_ENV['CYBERSOURCE_SHARED_SECRET']);

            $resource = "/pts/v2/payments";
            $method = "post";
            $host = "apitest.cybersource.com";
            $date = gmdate("D, d M Y H:i:s") . " GMT";
            $digest = "SHA-256=" . base64_encode(hash("sha256", $payload, true));

            $signatureString = "host: $host\n";
            $signatureString .= "v-c-date: $date\n";
            $signatureString .= "request-target: $method $resource\n";
            $signatureString .= "digest: $digest\n";
            $signatureString .= "v-c-merchant-id: $merchantId";

            $decodedSecret = base64_decode($secretKey);

            $signature = base64_encode(
                hash_hmac("sha256", $signatureString, $decodedSecret, true)
            );

            $signatureHeader = 'keyid="' . $keyId . '", algorithm="HmacSHA256", headers="host v-c-date request-target digest v-c-merchant-id", signature="' . $signature . '"';

            $client = new Client();

            try {
                $response = $client->post($url, [
                    'headers' => [
                        "Content-Type" => "application/json",
                        "Host" => $host,
                        "v-c-date" => $date,
                        "Digest" => $digest,
                        "v-c-merchant-id" => $merchantId,
                        "Signature" => $signatureHeader
                    ],
                    'body' => $payload
                ]);

                $httpCode = $response->getStatusCode();
                $responseBody = $response->getBody()->getContents();

                $decodedResponse = json_decode($responseBody, true);

                if ($decodedResponse !== null) {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $decodedResponse
                    );
                } else {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $responseBody
                    );
                }

                return $data;
            } catch (RequestException $e) {
                $errorMessage = $e->getMessage();

                if ($e->hasResponse()) {
                    $response = $e->getResponse();
                    $httpCode = $response->getStatusCode();
                    $responseBody = $response->getBody()->getContents();

                    $decodedBody = json_decode($responseBody, true);

                    echo json_encode($decodedBody);
                    die();

                    if (is_string($decodedBody) && !empty($decodedBody)) {
                        $decodedBody = json_decode($decodedBody, true);
                    }
                    if ($decodedBody !== null) {
                        if (isset($decodedBody['response']['rmsg'])) {
                            $errorMessage = $decodedBody['response']['rmsg'];
                        } elseif (isset($decodedBody['rmsg'])) {
                            $errorMessage = $decodedBody['rmsg'];
                        } elseif (isset($decodedBody['message'])) {
                            $errorMessage = $decodedBody['message'];
                        } elseif (isset($decodedBody['error'])) {
                            $errorMessage = $decodedBody['error'];
                        } else {
                            $errorMessage = $responseBody;
                        }
                    } elseif (!empty($responseBody)) {
                        $errorMessage = $responseBody;
                    } else {
                        $errorMessage = "HTTP Error $httpCode: " . $errorMessage;
                    }
                }

                $data = array(
                    'status' => 'error',
                    'message' => $errorMessage
                );
                return $data;
            }
        }


        public function postAuthentication($transactionID, $sessionId, $firstName, $lastName, $amount, $reference, $recipientAccountNumber, $recipientFirstName, $recipientLastName, $jti, $maskedValue, $expirationMonth, $expirationYear, $referenceId, $accessToken, $deviceDataCollectionUrl, $deviceInfo = []){

            $url = 'https://apitest.cybersource.com/pts/v2/payments';

            $get = function($key, $serverKey = null) use ($deviceInfo) {
                if (isset($deviceInfo[$key]) && $deviceInfo[$key] !== '') {
                    return $deviceInfo[$key];
                }
                if ($serverKey !== null && !empty($_SERVER[$serverKey])) {
                    return $_SERVER[$serverKey];
                }
                return '';
            };
            $getBool = function($key, $default = false) use ($deviceInfo) {
                if (!isset($deviceInfo[$key])) return $default;
                $v = $deviceInfo[$key];
                if (is_bool($v)) return $v;
                return in_array(strtolower((string)$v), ['1', 'true', 'yes'], true);
            };

            $payload = json_encode([
                'clientReferenceInformation' => [
                    'code' => $reference
                ],
                'processingInformation' => [
                    'actionList' => ['VALIDATE_CONSUMER_AUTHENTICATION'],
                    'capture' => true,
                    'commerceIndicator' => 'internet',
                    'authorizationOptions' => [
                        'initiator' => [
                            'type' => 'customer',
                            'storedCredentialUsed' => false
                        ],
                        'aftIndicator' => true
                    ]
                ],
                'orderInformation' => [
                    'billTo' => [
                        'firstName' => $firstName,
                        'lastName' => $lastName,
                        'address1' => '1295 Charleston Road',
                        'locality' => 'Mountain View',
                        'administrativeArea' => 'CA',
                        'postalCode' => '94043',
                        'country' => 'US',
                        'email' => 'null@cybersource.com',
                    ],
                    'amountDetails' => [
                        'totalAmount' => $amount,
                        'currency' => 'USD',
                    ]
                ],
                'senderInformation' => [
                    'firstName' => $firstName,
                    'lastName' => $lastName,
                    'address1' => '1295 Charleston Road',
                    'locality' => 'Mountain View',
                    'administrativeArea' => 'CA',
                    'postalCode' => '94043',
                    'country' => 'US',
                ],
                'recipientInformation' => [
                    'accountId' => $recipientAccountNumber,
                    'firstName' => $recipientFirstName,
                    'lastName' => $recipientLastName,
                ],
                'deviceInformation' => [
                    'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '',
                    'fingerprintSessionId' => $sessionId ?: ('3f6d2df2-0701-4d6f-984c-b9b6e5c933f0'),
                    'httpAcceptBrowserValue' => $get('httpAcceptBrowserValue', 'HTTP_ACCEPT'),
                    'httpAcceptContent' => $get('httpAcceptContent', 'HTTP_ACCEPT'),
                    'httpBrowserEmail' => $get('httpBrowserEmail'),
                    'httpBrowserLanguage' => $get('httpBrowserLanguage', 'HTTP_ACCEPT_LANGUAGE'),
                    'httpBrowserJavaEnabled' => $getBool('httpBrowserJavaEnabled', false),
                    'httpBrowserJavaScriptEnabled' => $getBool('httpBrowserJavaScriptEnabled', true),
                    'httpBrowserColorDepth' => $get('httpBrowserColorDepth'),
                    'httpBrowserScreenHeight' => $get('httpBrowserScreenHeight'),
                    'httpBrowserScreenWidth' => $get('httpBrowserScreenWidth'),
                    'httpBrowserTimeDifference' => $get('httpBrowserTimeDifference'),
                    'userAgentBrowserValue' => $get('userAgentBrowserValue', 'HTTP_USER_AGENT')
                ],
                'consumerAuthenticationInformation' => [
                    'authenticationTransactionId' => $transactionID
                ],
                'merchantDefinedInformation' => [
                    [
                        'key' => 'MDD1',
                        'value' => 'Test'
                    ]
                ],
                'tokenInformation' => [
                    'jti' => $jti
                ],
                'acquirerInformation' => [
                    'merchantId' => 'aby_0001'
                ]
            ], JSON_UNESCAPED_SLASHES);
            

            $merchantId = trim($_ENV['CYBERSOURCE_MERCHANT_ID']);
            $keyId = trim($_ENV['CYBERSOURCE_API_KEY']);
            $secretKey = trim($_ENV['CYBERSOURCE_SHARED_SECRET']);

            $resource = "/pts/v2/payments";
            $method = "post";
            $host = "apitest.cybersource.com";
            $date = gmdate("D, d M Y H:i:s") . " GMT";
            $digest = "SHA-256=" . base64_encode(hash("sha256", $payload, true));

            $signatureString = "host: $host\n";
            $signatureString .= "v-c-date: $date\n";
            $signatureString .= "request-target: $method $resource\n";
            $signatureString .= "digest: $digest\n";
            $signatureString .= "v-c-merchant-id: $merchantId";

            $decodedSecret = base64_decode($secretKey);

            $signature = base64_encode(
                hash_hmac("sha256", $signatureString, $decodedSecret, true)
            );

            $signatureHeader = 'keyid="' . $keyId . '", algorithm="HmacSHA256", headers="host v-c-date request-target digest v-c-merchant-id", signature="' . $signature . '"';

            $client = new Client();

            try {
                $response = $client->post($url, [
                    'headers' => [
                        "Content-Type" => "application/json",
                        "Host" => $host,
                        "v-c-date" => $date,
                        "Digest" => $digest,
                        "v-c-merchant-id" => $merchantId,
                        "Signature" => $signatureHeader
                    ],
                    'body' => $payload
                ]);

                $httpCode = $response->getStatusCode();
                $responseBody = $response->getBody()->getContents();

                $decodedResponse = json_decode($responseBody, true);

                if ($decodedResponse !== null) {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $decodedResponse
                    );
                } else {
                    $data = array(
                        'status' => 'success',
                        'httpCode' => $httpCode,
                        'response' => $responseBody
                    );
                }

                return $data;
            } catch (RequestException $e) {
                $errorMessage = $e->getMessage();

                if ($e->hasResponse()) {
                    $response = $e->getResponse();
                    $httpCode = $response->getStatusCode();
                    $responseBody = $response->getBody()->getContents();

                    $decodedBody = json_decode($responseBody, true);

                    echo json_encode($decodedBody);
                    die();

                    if (is_string($decodedBody) && !empty($decodedBody)) {
                        $decodedBody = json_decode($decodedBody, true);
                    }
                    if ($decodedBody !== null) {
                        if (isset($decodedBody['response']['rmsg'])) {
                            $errorMessage = $decodedBody['response']['rmsg'];
                        } elseif (isset($decodedBody['rmsg'])) {
                            $errorMessage = $decodedBody['rmsg'];
                        } elseif (isset($decodedBody['message'])) {
                            $errorMessage = $decodedBody['message'];
                        } elseif (isset($decodedBody['error'])) {
                            $errorMessage = $decodedBody['error'];
                        } else {
                            $errorMessage = $responseBody;
                        }
                    } elseif (!empty($responseBody)) {
                        $errorMessage = $responseBody;
                    } else {
                        $errorMessage = "HTTP Error $httpCode: " . $errorMessage;
                    }
                }

                $data = array(
                    'status' => 'error',
                    'message' => $errorMessage
                );
                return $data;
            }

        }

    }

?>