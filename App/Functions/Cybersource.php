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
            ]);

            $merchantId = $_ENV['CYBERSOURCE_MERCHANT_ID'];
            $keyId = $_ENV['CYBERSOURCE_API_KEY'];
            $secretKey = $_ENV['CYBERSOURCE_SHARED_SECRET'];

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
    
    }

?>