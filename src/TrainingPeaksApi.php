<?php

namespace Stefnielandt;

class TrainingPeaksApi
{
    const PRODUCTION_URL = 'trainingpeaks.com';
    const SANDBOX_URL = 'sandbox.trainingpeaks.com';

    const ACCESS_TOKEN_MINIMUM_VALIDITY = 3600;

    public $lastRequest;
    public $lastRequestData;
    public $lastRequestInfo;

    protected $responseHeaders = array();

    protected $apiUrl;
    protected $authUrl;
    protected $clientId;
    protected $clientSecret;

    private $accessToken;
    private $refreshToken;
    private $expiresAt;

    public function __construct($clientId = 1, $clientSecret = '', $production = false)
    {
        $base_url = $production ? self::PRODUCTION_URL : self::SANDBOX_URL;
        $this->clientId     = $clientId;
        $this->clientSecret = $clientSecret;
        $this->apiUrl       = 'https://api.' . $base_url . '/v1/';
        $this->authUrl      = 'https://oauth.' . $base_url . '/oauth/';
    }

    public function getResponseHeaders()
    {
        return $this->responseHeaders;
    }

    public function getResponseHeader($header)
    {
        if (! isset($this->responseHeaders[$header])) {
            throw new \InvalidArgumentException('Header does not exist');
        }

        return $this->responseHeaders[$header];
    }

    protected function parseGet($url, $query)
    {
        $append = strpos($url, '?') === false ? '?' : '&';

        return $url . $append . http_build_query($query);
    }

    protected function parseResponse($response)
    {
        return json_decode($response);
    }

    protected function request($url, $parameters = array(), $request = false)
    {
        $this->lastRequest = $url;
        $this->lastRequestData = $parameters;
        $this->responseHeaders = array();

        if (strpos($url, '/oauth/token') === false && $this->isTokenRefreshNeeded()) {
            throw new \RuntimeException('TrainingPeaks access token needs to be refreshed');
        }

        $curl = curl_init($url);

        $curlOptions = array(
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_REFERER        => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADERFUNCTION => array($this, 'parseHeader'),
        );

        if (! empty($parameters) || ! empty($request)) {
            if (! empty($request)) {
                $curlOptions[ CURLOPT_CUSTOMREQUEST ] = $request;
                $parameters = http_build_query($parameters);
            } else {
                $curlOptions[ CURLOPT_POST ] = true;
            }

            $curlOptions[ CURLOPT_POSTFIELDS ] = $parameters;
        }

        curl_setopt_array($curl, $curlOptions);

        $response = curl_exec($curl);
        $error    = curl_error($curl);

        $this->lastRequestInfo = curl_getinfo($curl);

        curl_close($curl);

        if (! empty($error)) {
            throw new \Exception($error);
        }

        return $this->parseResponse($response);
    }

    public function authenticationUrl($redirect, $scope = null)
    {
        $parameters = array(
            'client_id'       => $this->clientId,
            'redirect_uri'    => $redirect,
            'response_type'   => 'code',
        );

        if (! is_null($scope)) {
            $parameters['scope'] = $scope;
        }

        return $this->parseGet(
            $this->authUrl . 'authorize',
            $parameters
        );
    }

    public function tokenExchange($code)
    {
        $parameters = array(
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code'          => $code,
            'grant_type'    => 'authorization_code'
        );

        return $this->request(
            $this->authUrl . 'token',
            $parameters
        );
    }

    public function tokenExchangeRefresh()
    {
        if (! isset($this->refreshToken)) {
            return null;
        }
        $parameters = array(
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $this->refreshToken,
            'grant_type'    => 'refresh_token'
        );

        return $this->request(
            $this->authUrl . 'token',
            $parameters
        );
    }

    public function deauthorize()
    {
        return $this->request(
            $this->authUrl . 'deauthorize',
            $this->generateParameters(array())
        );
    }

    public function setAccessToken($token, $refreshToken = null, $expiresAt = null)
    {
        if (isset($refreshToken)) {
            $this->refreshToken = $refreshToken;
        }
        if (isset($expiresAt)) {
            $this->expiresAt = $expiresAt;
            if ($this->isTokenRefreshNeeded()) {
                throw new \RuntimeException('TrainingPeaks access token needs to be refreshed');
            }
        }

        return $this->accessToken = $token;
    }


    protected function generateParameters($parameters)
    {
        return array_merge(
            $parameters,
            array( 'access_token' => $this->accessToken )
        );
    }

    protected function parseHeader($curl, $headerLine)
    {
        $size    = strlen($headerLine);
        $trimmed = trim($headerLine);

        // skip empty line(s)
        if (empty($trimmed)) {
            return $size;
        }

        // skip first header line (HTTP status code)
        if (strpos($trimmed, 'HTTP/') === 0) {
            return $size;
        }

        $parts = explode(':', $headerLine);
        $key   = array_shift($parts);
        $value = implode(':', $parts);

        $this->responseHeaders[$key] = trim($value);

        return $size;
    }

    protected function getAbsoluteUrl($request)
    {
        $request = ltrim($request);

        if (strpos($request, 'http') === 0) {
            return $request;
        }

        return $this->apiUrl . $request;
    }

    public function get($request, $parameters = array())
    {
        $parameters = $this->generateParameters($parameters);
        $requestUrl = $this->parseGet($this->getAbsoluteUrl($request), $parameters);

        return $this->request($requestUrl);
    }

    public function put($request, $parameters = array())
    {
        return $this->request(
            $this->getAbsoluteUrl($request),
            $this->generateParameters($parameters),
            'PUT'
        );
    }

    public function post($request, $parameters = array())
    {
        return $this->request(
            $this->getAbsoluteUrl($request),
            $this->generateParameters($parameters)
        );
    }

    public function delete($request, $parameters = array())
    {
        return $this->request(
            $this->getAbsoluteUrl($request),
            $this->generateParameters($parameters),
            'DELETE'
        );
    }

    public function isTokenRefreshNeeded()
    {
        if (empty($this->expiresAt)) {
            return false;
        }

        return $this->expiresAt - time() < self::ACCESS_TOKEN_MINIMUM_VALIDITY;
    }
}