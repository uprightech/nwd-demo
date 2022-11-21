<?php

namespace App\Libraries;

use App\Models\RopcClientException;
use App\Models\RopcClientResponse;

class RopcClient
{
    const GRANT_TYPE_PARAMETER = 'grant_type';
    const SCOPE_PARAMETER = 'scope';
    const CLIENT_ID_PARAMETER = 'client_id';
    const CLIENT_SECRET_PARAMETER = 'client_secret';
    const USERNAME_PARAMETER = 'username';
    const PASSWORD_PARAMETER = 'password';

    // authentication methods 
    // for the sake of expediency , we will only support basic authentication 
    const AUTHENTICATION_NONE  = 0;
    const AUTHENTICATION_BASIC = 1;

    const RESOURCE_OWNER_PASSWORD_GRANT_TYPE = 'password';

    const AUTH_RESULT_HTTP_HEADER = 'X-NWD-AUTHN';

    const STATUS_HTTP_ATTR = "status";
    const ERROR_CODE_HTTP_ATTR  = "error_code";
    const SESSION_ID_HTTP_ATTR  = "session_id";
    const PHONE_NUMBER_HTTP_ATTR  = "phone_number";

    private $endpoint;
    private $clientid;
    private $clientsecret;
    private $parameters;
    private $authmethod;
    private $curlhandle;
    private $secure;
    private $connlog;
    private $headers;
    
    public function __construct($endpoint)
    {
        $this->endpoint = $endpoint;
        $this->parameters = [];
        $this->clientid = false;
        $this->clientsecret = false;
        $this->authmethod = self::AUTHENTICATION_NONE;
        $this->curlhandle = false;
        $this->secure = true;
        $this->connlog = false;
        $this->headers = [];
    }

    public function setClientCredentials($clientId, $clientsecret)
    {
        $this->clientid = $clientId;
        $this->clientsecret = $clientsecret;
    }

    public function setUserCredentials($username, $password)
    {
        $this->parameters[self::USERNAME_PARAMETER] = $username;
        $this->parameters[self::PASSWORD_PARAMETER] = $password;
    }

    public function setExtraParameter($paramname, $paramvalue)
    {
        $this->parameters[$paramname] = $paramvalue;
    }

    public function setExtraParameters($params)
    {
        foreach($params as $key => $value) 
        {
            $this->parameters[$key] = $value;
        }
    }

    public function setAuthenticationMethod($authmethod) 
    {
        $this->authmethod = $authmethod;
    }

    public function setSecure($secure)
    {
        $this->secure = $secure;
    }

    public function enableDebug($enabled, $debugfile=null) 
    {
        if($this->connlog)
            @fclose($this->connlog);
        
        $this->connlog = false;
        if($enabled)
            $this->connlog = @fopen($debugfile,"w+");

    }

    public function execute()
    {
        if($this->curlhandle)
            curl_close($this->curlhandle);
        
        $this->curlhandle = curl_init();
        if($this->curlhandle == false)
            throw new RopcClientException('Could not initialize curl handle');
        
        curl_setopt($this->curlhandle,CURLOPT_URL,$this->endpoint);
        curl_setopt($this->curlhandle,CURLOPT_POST,true);
        curl_setopt($this->curlhandle,CURLOPT_RETURNTRANSFER,true);
        
        curl_setopt($this->curlhandle,CURLOPT_SSL_VERIFYPEER,$this->secure);
        curl_setopt($this->curlhandle,CURLOPT_SSL_VERIFYSTATUS,$this->secure);
        curl_setopt($this->curlhandle,CURLOPT_SSL_VERIFYHOST,($this->secure?2:0));
        //set this so we can extract the headers too 
        curl_setopt($this->curlhandle,CURLOPT_HEADER,true);
        
        if($this->connlog != false) 
        {
            curl_setopt($this->curlhandle,CURLOPT_VERBOSE,true);
            curl_setopt($this->curlhandle,CURLOPT_STDERR,$this->connlog);
        }
        
        $this->setupHttpPostData();
        $this->setupAuthentication();

        $ret = curl_exec($this->curlhandle);
        if($ret === false) 
        {
            throw new RopcClientException("Http client request failed.". curl_error($this->curlhandle),curl_errno($this->curlhandle));
        }
        
        $header_size = curl_getinfo($this->curlhandle,CURLINFO_HEADER_SIZE);
        $headers_str = substr($ret,0,$header_size);
        $this->parseHeaders($headers_str);
        $body = substr($ret,$header_size);
        
        return $this->buildResponseObject($body);
    }
    
    public function getHttpResponseCode()
    {
        if($this->curlhandle == false)
            return -1;
        
        return curl_getinfo($this->curlhandle,CURLINFO_HTTP_CODE);
    }

    public function getHttpHeaders()
    {
        return $this->headers;
    }

    public function close()
    {
        if($this->connlog)
            @fclose($this->connlog);
        
        if($this->curlhandle)
            curl_close($this->curlhandle);
    }

    private function setupHttpPostData() 
    {
        $postdata = "";
        
        if($this->authmethod == self::AUTHENTICATION_BASIC)
        {
            $postdata .= self::CLIENT_ID_PARAMETER .'=' .urlencode($this->clientid);
        }
        else
        {
            $postdata .= self::CLIENT_ID_PARAMETER .'=' .urlencode($this->clientid);
            $postdata .="&";
            $postdata .= self::CLIENT_SECRET_PARAMETER . '=' . urlencode($this->clientsecret);
        }

        $postdata .= "&";
        $postdata .= self::GRANT_TYPE_PARAMETER . '=' . self::RESOURCE_OWNER_PASSWORD_GRANT_TYPE; 

        foreach($this->parameters as $paramname => $paramvalue)
        {
            $postdata .= "&";
            $postdata .= $paramname."=".urlencode($paramvalue);
        }
        
        curl_setopt($this->curlhandle,CURLOPT_POSTFIELDS,$postdata);
    }

    private function setupAuthentication()
    {
        if($this->authmethod == self::AUTHENTICATION_BASIC)
        {
            curl_setopt($this->curlhandle,CURLOPT_HTTPAUTH,CURLAUTH_BASIC);

            $userpassword = ':';
            if($this->clientid !== false && $this->clientsecret !== false)
                $userpassword = $this->clientid .':'.$this->clientsecret;
            
            curl_setopt($this->curlhandle,CURLOPT_USERPWD,$userpassword);
        }
    }

    private function parseHeaders($header_str)
    {
        $headers_as_array = explode("\r\n",$header_str);
        $this->headers = [];
        $status_header = array_shift($headers_as_array);
        foreach($headers_as_array as $header_line)
        {
            if(false !== ($matches = explode(':',$header_line,2)))
            {
                if(isset($matches[0]) && isset($matches[1]))
                    $this->headers["{$matches[0]}"] = trim($matches[1]);
            }
        }
    }

    private function getHttpHeaderValue($header)
    {
        if(isset($this->headers[$header]))
            return $this->headers[$header];
        
        return null;
    }

    private function buildResponseObject($body)
    {
        $response = new RopcClientResponse();

        $response->httpcode = curl_getinfo($this->curlhandle,CURLINFO_HTTP_CODE);
        $response->body = $body;

        $authn_result_value = null;
        
        if(isset($this->headers[self::AUTH_RESULT_HTTP_HEADER]))
            $authn_result_value = trim($this->headers[self::AUTH_RESULT_HTTP_HEADER]);
        
        if($authn_result_value == null) 
        {
            return $response;
        }

        $authn_result_attrs = explode(";",$authn_result_value);
        foreach($authn_result_attrs as $auth_result_attr)
        {
            $kv = explode("=",$auth_result_attr);
            
            if(strcasecmp(trim($kv[0]),self::STATUS_HTTP_ATTR)==0)
            {
                $response->setAuthStatusFromString(trim($kv[1]));
            }
            else if(strcasecmp(trim($kv[0]),self::ERROR_CODE_HTTP_ATTR)==0)
            {
                $response->errorcode = (int) trim($kv[1]);
            }
            else if(strcasecmp(trim($kv[0]),self::SESSION_ID_HTTP_ATTR)==0)
            {
                $response->sessionid = trim($kv[1]);
            }
            else if(strcasecmp(trim($kv[0]),self::PHONE_NUMBER_HTTP_ATTR)==0)
            {
                $response->phonenumber = trim($kv[1]);
            }
        }
        return $response;
    }
}
