<?php

namespace Ohtarr\Azure;

use \GuzzleHttp\Client;
use Ohtarr\Azure\Tenant;

class Azure
{
    public static function guzzle(array $guzzleparams)
    {
        $options = [];
        $params = [];
        $verb = 'get';
        $url = '';
        if(isset($guzzleparams['options']))
        {
            $options = $guzzleparams['options'];
        }
        if(isset($guzzleparams['params']))
        {
            $params = $guzzleparams['params'];
        }
        if(isset($guzzleparams['verb']))
        {
            $verb = $guzzleparams['verb'];
        }
        if(isset($guzzleparams['url']))
        {
            $url = $guzzleparams['url'];
        }

        $client = new Client($options);
        $apiRequest = $client->request($verb, $url, $params);
        $response = $apiRequest->getBody()->getContents();
        $array = json_decode($response,true);
        return $array;
    }

}
