<?php

namespace Ohtarr\Azure;

use Ohtarr\Azure\Azure;

class AzureTenant extends Azure
{
    // Tenant name something.onmicrosoft.com
    public $tenantName = '';
    // Tenant ID xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    public $tenantId = '';    
    // Azure AD base url to use
    public $baseUrl = 'https://login.microsoftonline.com';
    // Azure AD version
    public $version = 'v2.0';
    // .well-known/openid-config
    public $wellKnownOpenIdConfig = '.well-known/openid-configuration';
    // Contents of the openid config assoc array parsed from json
    public $openIdConfig = [];
    // AAD authorization endpoint
    public $authorizationEndpoint = '';
    // AAD token endpoint
    public $tokenEndpoint = '';
    // AAD logout endpoint
    public $endSessionEndpoint = '';
    // Array of RSA token signing keys indexed by KeyID
    public $signingKeys = [];

    public function __construct($tenantnameorid = 'common')
    {
        $this->discoverTenant($tenantnameorid);
        $this->getTenantInfo();
    }

    public function discoverTenant($tenantnameorid)
    {
        $urls = [
            $this->buildOpenIdConfigUrl($tenantnameorid),
            $this->buildOpenIdConfigUrl($tenantnameorid.".onmicrosoft.com"),
        ];

        foreach($urls as $url)
        {
            try {
                $response = $this->guzzle(['url' => $url]);
            } catch(\Exception $e) {
                continue;
            }
            if(!isset($response['error']))
            {
                if($response['token_endpoint'])
                {

                    if(preg_match("/".$tenantnameorid."/",$response['token_endpoint']))
                    {
                        $this->tenantId =  $tenantnameorid;
                        break;
                    } 
                    if(preg_match("/.onmicrosoft.com/",$tenantnameorid)) 
                    {
                        $this->tenantName = $tenantnameorid;
                        $this->tenantId = rtrim(ltrim($response['token_endpoint'],$this->baseUrl.'/'),'/oauth2/v2.0/token');                    
                        break;
                    } else {
                        $this->tenantName = $tenantnameorid.".onmicrosoft.com";
                        $this->tenantId = $this->tenantId = rtrim(ltrim($response['token_endpoint'],$this->baseUrl.'/'),'/oauth2/v2.0/token');
                    }
                }
            }
        }
        return $this->tenantId;
    }

    public function buildOpenIdConfigUrl($tenantnameorid)
    {
        return $this->baseUrl.'/'
                .$tenantnameorid.'/'
                .$this->version.'/'
                .$this->wellKnownOpenIdConfig;
    }

    public function buildAdminConsentUrl($clientId, $redirectUri)
    {
        return $this->baseUrl.'/'
             .$this->tenantId.'/'
             .'adminconsent'
             .'?client_id='.$clientId
             .'&redirect_uri='.$redirectUri;
    }

    public function downloadOpenIdConfig()
    {
        $response = $this->guzzle(['url' => $this->buildOpenIdConfigUrl($this->tenantId)]);
        return $response;
    }

    public function downloadSigningKeys()
    {
        $response = $this->guzzle(['url' => $this->openIdConfig['jwks_uri']]);
        $keyRing = $response['keys'];
        // Loop through the keys and build us an index by kid
        foreach ($keyRing as $key) {
            $keys[$key['kid']] = $key;
            //$this->signingKeys[$key['kid']] = $key;
        }
        return $keys;
    }

    public function getTenantInfo()
    {
        $this->openIdConfig = $this->downloadOpenIdConfig();
        $this->signingKeys = $this->downloadSigningKeys();
        $this->authorizationEndpoint = $this->openIdConfig['authorization_endpoint'];
        $this->tokenEndpoint = $this->openIdConfig['token_endpoint'];
        $this->endSessionEndpoint = $this->openIdConfig['end_session_endpoint'];
    }

    public function newApp($clientid,$clientsecret,$scope = 'https://graph.microsoft.com/.default')
    {
        return new AzureApp($this->tenantId,$clientid,$clientsecret,$scope);
    }

}
