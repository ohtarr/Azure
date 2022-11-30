<?php

namespace Ohtarr\Azure;

use Ohtarr\Azure\Azure;
use Ohtarr\Azure\AzureTenant;
use \Firebase\JWT\JWT;

class AzureApp extends Azure
{
    private $client_id;
    private $client_secret;
    private $token;
    
    public function __construct($tenant_id, $client_id, $client_secret)
    {
        $this->tenant = new AzureTenant($tenant_id);
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
    }

    public function getRawToken($scope = 'https://graph.microsoft.com/.default')
    {
        $guzzleparams = [
            'verb'      =>  'post',
            'url'       =>  $this->tenant->tokenEndpoint,
            'params'    =>  [
                'headers'   =>  [
                    'Content-Type'  => 'application/x-www-form-urlencoded',
                    'Accept'        => 'application/json',
                ],
                'form_params' => [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->client_id,
                    'client_secret' => $this->client_secret,
                    'scope' => $scope,
                ],
            ]
        ];
        $response = $this->guzzle($guzzleparams);
        return $response;
    }

    public function getToken($scope = 'https://graph.microsoft.com/.default')
    {
        $response = $this->getRawToken($scope);
        return $response['access_token'];
    }

/*     public function getUserById($id, $token = null)
    {
        if(!$token)
        {
            $token = $this->getToken();
        }
        $guzzleparams = [
            'verb'      =>  'get',
            'url'       =>  "https://graph.microsoft.com/v1.0/users/" . $id,
            'params'    =>  [
                'headers'   =>  [
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer ' . $token, 
                 ],
            ]
        ];
        $response = $this->guzzle($guzzleparams);

        return $response;
    } */

/*     public function getUsersByUsername($username, $token = null)
    {
        if(!$token)
        {
            $token = $this->getToken();
        }
        $query = [
            '$filter'   =>  'startswith(userPrincipalName,' . "'" . $username . "'" . ')',
            //'$filter'   =>  'eq(userPrincipalName,' . "'" . $username . "'" . ')',
        ];
        $guzzleparams = [
            'verb'      =>  'get',
            'url'       =>  "https://graph.microsoft.com/v1.0/users/",
            'params'    =>  [
                'headers'   =>  [
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer ' . $token, 
                 ],
                 'query'    =>  $query,
            ]
        ];

        $response = $this->guzzle($guzzleparams);

        return $response['value'];
    } */

/*     public function getUserGroupsById($id, $token = null)
    {
        if(!$token)
        {
            $token = $this->getToken();
        }

        $guzzleparams = [
            'verb'      =>  'get',
            'url'       =>  'https://graph.microsoft.com/v1.0/users/' . $id . '/transitiveMemberOf',
            'params'    =>  [
                'headers'   =>  [
                    'Content-Type'  => 'application/json',
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer ' . $token, 
                 ]
            ]
        ];

        $response = $this->guzzle($guzzleparams);
        $return = $response['value'];
        while(isset($response['@odata.nextLink']))
        {
            $guzzleparams['url'] = $response['@odata.nextLink'];
            $response = $this->guzzle($guzzleparams);
            $return = array_merge($return, $response['value']);            
        }
        return $return;
    } */

    public function unpackJwt($jwt)
    {
        // I had to add this custom error handling to deal with a very dumb client
        $tokenparts = explode('.', $jwt);
        if (count($tokenparts) != 3) {
            throw new \Exception('Token format is not valid for JWT: '.$jwt);
        }

        // This was the original function...
        list($headb64, $bodyb64, $cryptob64) = explode('.', $jwt);
        $parsedtoken = [
            'header'    => json_decode(JWT::urlsafeB64Decode($headb64), true),
            'payload'   => json_decode(JWT::urlsafeB64Decode($bodyb64), true),
            'signature' => $cryptob64,
        ];

        return $parsedtoken;
    }

    // this checks the app token, validates it, returns decoded signed data
    public function validateRSAToken($accessToken)
    {
        // Unpack our jwt to verify it is correctly formed
        $token = $this->unpackJwt($accessToken);

        // app tokens must be signed in RSA
        if (! isset($token['header']['alg']) || $token['header']['alg'] != 'RS256') {
            throw new \Exception('Token is not using the correct signing algorithm RS256 '.$accessToken);
        }
        // app tokens are RSA signed with a key ID in the header of the token
        if (! isset($token['header']['kid'])) {
            throw new \Exception('Token with unknown RSA key id can not be validated '.$accessToken);
        }
        // Make sure the key id is known to our azure ad information
        $kid = $token['header']['kid'];
        if (! isset($this->tenant->signingKeys[$kid])) {
            throw new \Exception('Token signed with unknown KID '.$kid);
        }
        // get the x509 encoded cert body
        $x5c = $this->tenant->signingKeys[$kid]['x5c'];
        // if this is an array use the first entry
        if (is_array($x5c)) {
            $x5c = reset($x5c);
        }
        // Get the X509 certificate for the selected key id
        $certificate = '-----BEGIN CERTIFICATE-----'.PHP_EOL
                     .$x5c.PHP_EOL
                     .'-----END CERTIFICATE-----';
        // Perform the verification and get the verified payload results
        $payload = JWT::decode($accessToken, $certificate, ['RS256']);

        return $payload;
    }

    public function validateUserToken($token)
    {
        if(!$token)
        {
            throw new \Exception('Token not found!');
        }

        $validated = $this->validateRSAToken($token);

        // Token AUD must match our client id.
        if($validated->aud != $this->client_id)
        {
            throw new \Exception('Token is not valid for this application! (aud)');
        }
        /*
        $date = new \DateTime();
        $now = $date->getTimestamp();

        // Token AUD must match our client id.
        if($validated->nbf > $now)
        {
            throw new \Exception('This token is not valid yet! (nbf)');
        }

        if($validated->exp <= $now)
        {
            throw new \Exception('This token is expired! (exp)');
        }
        /**/
        return $validated;
    }

}