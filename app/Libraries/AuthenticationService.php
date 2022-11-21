<?php 

namespace App\Libraries;

class AuthenticationService
{
    const AUTH_STATUS_UNAUTHENTICATED = 0;
    const AUTH_STATUS_AUTHENTICATED = 1;

    const AUTH_STATUS_KEY = '__authstatus';
    const USER_KEY = '__user';
    const ACCESS_TOKEN_KEY = '__access_token';

    public function __construct()
    {
        $session = session();
        if($session->get(self::AUTH_STATUS_KEY) == null) {
            
            $session->set(self::AUTH_STATUS_KEY,self::AUTH_STATUS_UNAUTHENTICATED);
        }
    }

    public function isLoggedIn()
    {
        $session = session();
        $auth_status = $session->get(self::AUTH_STATUS_KEY);
        if($auth_status ==  self::AUTH_STATUS_AUTHENTICATED)
            return true;
        
        return false;
    }

    public function login()
    {
        $session = session();
        $session->set(self::AUTH_STATUS_KEY,self::AUTH_STATUS_AUTHENTICATED);
    }

    public function logout()
    {
        $session = session();
        $session->remove(self::AUTH_STATUS_KEY);
        $session->remove(self::USER_KEY);
        $session->remove(self::ACCESS_TOKEN_KEY);
    }

    public function getUser()
    {
        $session = session();
        return $session->get(self::USER_KEY);
    }

    public function setUser($user)
    {
        $session = session();
        if($user != null)
            $session->set(self::USER_KEY,$user);
        else
            $session->remove(self::USER_KEY);
    }

    public function setAccessToken($accesstoken)
    {
        $session = session();
        $session->set(self::ACCESS_TOKEN_KEY,$accesstoken);
    }

    public function getAccessToken()
    {
        $session = session();
        return $session->get(self::ACCESS_TOKEN_KEY);
    }
}