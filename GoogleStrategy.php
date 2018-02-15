<?php
/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.GoogleStrategy
 * @license      MIT License
 */

/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 * 
 * @package			Opauth.Google
 */
class GoogleStrategy extends OpauthStrategy{
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('client_id', 'client_secret');
	
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'state', 'access_type', 'approval_prompt');
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
		'scope' => 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
	);
	
	/**
	 * Auth request
	 */
	public function request(){
		$url = 'https://accounts.google.com/o/oauth2/auth';
		$params = array(
			'client_id' => $this->strategy['client_id'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			'response_type' => 'code',
			'scope' => $this->strategy['scope']
		);

		foreach ($this->optionals as $key){
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}
		
		$this->clientGet($url, $params);
	}

    /**
     * @param $url
     * @param $data
     * @param array $options
     * @param null $responseHeaders
     * @return mixed
     */
    public static function serverPost($url, $data, $options = array(), &$responseHeaders = null)
    {
        if (!is_array($options)) {
            $options = array();
        }

        $query = http_build_query($data, '', '&');

        $stream = array('http' => array(
            'method' => 'POST',
            'header' => "Content-type: application/x-www-form-urlencoded",
            'content' => $query
        ));

        $stream = self::arrayReplaceRecursive($stream, $options);

        return self::httpRequest($url, $stream, $responseHeaders);
    }

    /**
     * @param $url
     * @param null $options
     * @param null $responseHeaders
     * @return mixed
     */
    public static function httpRequest($url, $options = null, &$responseHeaders = null)
    {
        $context = null;
        if (!empty($options) && is_array($options)) {
            if (empty($options['http']['header'])) {
                $options['http']['header'] = "User-Agent: opauth";
            } else {
                $options['http']['header'] .= "\r\nUser-Agent: opauth";
            }
        } else {
            $options = array('http' => array('header' => 'User-Agent: opauth'));
        }

        $curl = curl_init();
        if ($options['http']['method'] == 'POST') {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $options['http']['content']);
        }
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_POST, ($options['http']['method'] == 'POST') ? 1 : 0);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HEADER, 0);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
                'Content-type: application/x-www-form-urlencoded',
                'User-Agent: opauth',
                'Content-Length: ' . strlen($options['http']['content'])
            )
        );

        curl_setopt($curl, CURLOPT_TIMEOUT, 5);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);

        $content = curl_exec($curl);

        return $content;
    }
	
	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback() {
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
            if (function_exists('getRawRequestData')) {
                $code = getRawRequestData('code');
            } else {
                $code = $_GET['code'];
            }

            $url = 'https://accounts.google.com/o/oauth2/token';
            $params = array(
                'code' => $code,
                'client_id' => $this->strategy['client_id'],
                'client_secret' => $this->strategy['client_secret'],
                'redirect_uri' => $this->strategy['redirect_uri'],
                'grant_type' => 'authorization_code'
            );
            $options = isset($this->strategy['context_options']) ? $this->strategy['context_options'] : null;
            $response = $this->serverPost($url, $params, $options, $headers);

            $results = json_decode($response);

            if (!empty($results) && !empty($results->access_token)) {
                $userinfo = $this->userinfo($results->access_token);

                $this->auth = array(
                    'uid' => $userinfo['id'],
                    'info' => array(),
                    'credentials' => array(
                        'token' => $results->access_token,
                        'expires' => date('c', time() + $results->expires_in)
                    ),
                    'raw' => $userinfo
                );

                if (!empty($results->refresh_token)) {
                    $this->auth['credentials']['refresh_token'] = $results->refresh_token;
                }

                $this->mapProfile($userinfo, 'name', 'info.name');
                $this->mapProfile($userinfo, 'email', 'info.email');
                $this->mapProfile($userinfo, 'given_name', 'info.first_name');
                $this->mapProfile($userinfo, 'family_name', 'info.last_name');
                $this->mapProfile($userinfo, 'picture', 'info.image');

                $this->callback();
            } else {
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $headers
                    )
                );

                $this->errorCallback($error);
            }
        } else {
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );

            $this->errorCallback($error);
        }
	}
	
	/**
	 * Queries Google API for user info
	 *
	 * @param string $access_token 
	 * @return array Parsed JSON results
	 */
	private function userinfo($access_token){
		$options = isset($this->strategy['context_options']) ? $this->strategy['context_options'] : null;
		
		$userinfo = $this->serverGet('https://www.googleapis.com/oauth2/v1/userinfo', array('access_token' => $access_token), $options, $headers);
		if (!empty($userinfo)){
			return $this->recursiveGetObjectVars(json_decode($userinfo));
		}
		else{
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query for user information',
				'raw' => array(
					'response' => $userinfo,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
		}
	}
}
