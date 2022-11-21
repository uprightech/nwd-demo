<?php

namespace App\Controllers;

use App\Models\RopcClientException;
use App\Models\RopcClientResponse;
use App\Models\User;
use App\Libraries\RopcClient;

class Login extends BaseController 
{
    const ENDPOINT_ENV_KEY = 'gamatech.demo.tokenEndpoint';
    const CLIENT_ID_ENV_KEY = 'gamatech.demo.clientId';
    const CLIENT_SECRET_ENV_KEY = 'gamatech.demo.clientSecret';
    const SECURE_CONNECTION_ENV_KEY = 'gamatech.demo.secureConnection';
    const CONNDEBUG_ENABLED_ENV_KEY = 'gamatech.demo.debugEnabled';
    const LOGFILE_ENV_KEY  = 'gamatech.demo.logFile';

    const STEP_ONE = 1;
    const STEP_TWO = 2;
    const STEP_THREE = 3;

    const STEP_SESSION_PARAM = '__step';
    const REMOTE_SESSION_ID_SESSION_PARAM = '__session_id';

    const HTTP_STATUS_OK = 200;
    const HTTP_STATUS_UNAUTHORIZED = 401;

    public function index() 
    {

        if($this->getCurrentStep() == self::STEP_ONE)
        {
            return $this->handleStepOneAuth();
        }
        else if($this->getCurrentStep() == self::STEP_TWO)
        {
            return $this->handleStepTwoAuth();
        }
        else if($this->getCurrentStep() == self::STEP_THREE)
        {
            return $this->handleStepThreeAuth();
        }
    }

    private function handleStepOneAuth()
    {
        $request = service('request');
        $session = service('session');
        $auth = service('auth');
        $data = [];
        $data['step'] = $this->getCurrentStep();
        $data['session'] = $session;
        
        if(strcmp($request->getMethod(),'post') == 0)
        {
            $username = $_POST['username'];
            $password = '';
            $clientparams = [self::STEP_SESSION_PARAM=>$this->getCurrentStep()];
            $client = $this->createRopcClient($username,$password,$clientparams);
            try 
            {
                $response = $client->execute();
                if($response->httpcode == self::HTTP_STATUS_OK)
                {
                    // this is strange , but handle it by immediately authenticating the user 
                    $auth->login();
                    $auth->setUser(new User($username));
                    return redirect()->to(url_to('Home::index'));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusError())
                {
                    $data['auth_error'] = $response->error_string();
                    log_message('debug','Authentication Failed. Response: '.print_r($response,true));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusProceed())
                {
                    $phone  = $response->phonenumber;
                    $first_char_in_phone_number = substr($phone,0,1);
                    if(strcmp($first_char_in_phone_number,'+')!=0)
                    {
                        $phone = "+" . $phone;
                    }
                    $user = new User($username,$phone);
                    $auth->setUser($user);
                    $data['user'] = $user;
                    $this->setCurrentStep(self::STEP_TWO);
                    $data['step'] = $this->getCurrentStep();
                    $this->setRemoteSessionId($response->sessionid);
                }
                else
                {
                    $data['auth_error'] = 'Unknown Error';
                    log_message('debug','Authentication Failed. Response: '.print_r($response,true));
                }
            }
            catch(RopcClientException $e)
            {
                log_message('debug','Authentication Failed. '. $e->getMessage());
                $data['auth_error'] = $e->getMessage();
            }
        }

        return view('login',$data);
    }

    private function handleStepTwoAuth()
    {
        $request = service('request');
        $session = service('session');
        $auth = service('auth');
        $data = [];
        $data['step'] = $this->getCurrentStep();
        $data['user'] = $auth->getUser();
        $data['session'] = $session;
        
        if(strcmp($request->getMethod(),'post') == 0)
        {
            $username = $auth->getUser()->getUsername();
            $otp = $_POST['otp'];
            $clientparams = [
                self::STEP_SESSION_PARAM => $this->getCurrentStep(),
                self::REMOTE_SESSION_ID_SESSION_PARAM => $this->getRemoteSessionId()
            ];

            $client = $this->createRopcClient($username,$otp,$clientparams);
            try
            {
                $response = $client->execute();
                if($response->httpcode == self::HTTP_STATUS_OK)
                {
                    //still strange, even at step 2.
                    $auth->login();
                    return redirect()->to(url_to('Home::index'));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusError())
                {
                    if($response->errorcode == RopcClientResponse::ERROR_CODE_SESSION_NOT_FOUND
                       || $response->errorcode == RopcClientResponse::ERROR_CODE_INVALID_SESSION)
                    {
                        $this->resetAuthentication($session);
                        $session->setFlashdata('auth_error',$response->error_string());
                        return redirect()->to(url_to('Login::index'));
                    }
                    
                    $data['auth_error'] = $response->error_string();
                    log_message('debug','Authentication Failed. Response : '.print_r($response,true));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusProceed())
                {
                    $this->setCurrentStep(self::STEP_THREE);
                    $data['step'] = $this->getCurrentStep();
                }
                else 
                {
                    $data['auth_error'] = 'Unknown Error';
                    log_message('debug','Authentication Failed. Response: '.print_r($response,true));
                }
            }
            catch(RopcClientException $e)
            {
                log_message('debug','Authentication Failed. '.$e->getMessage());
                $data['auth_error'] = $e->getMessage();
            }
        }

        return view('login',$data);
    }

    private function handleStepThreeAuth()
    {
        $request = service('request');
        $session = service('session');
        $auth = service('auth');
        $data = [];
        $data['step'] = $this->getCurrentStep();
        $data['user'] = $auth->getUser();
        $data['session'] = $session;

        if(strcmp($request->getMethod(),'post') == 0)
        {
            $username = $auth->getUser()->getUsername();
            $password = $_POST['password'];
            $clientparams = [
                self::STEP_SESSION_PARAM => $this->getCurrentStep(),
                self::REMOTE_SESSION_ID_SESSION_PARAM => $this->getRemoteSessionId()
            ];
            $client = $this->createRopcClient($username,$password,$clientparams);
            try
            {
                $response = $client->execute();
                if($response->httpcode == self::HTTP_STATUS_OK)
                {
                    //finally we're authenticated 
                    //save the access token , but we will not parse it for the purpose of expediency
                    $auth->setAccessToken($response->body);
                    $auth->login(); // authentication complete
                    //redirect to index page
                    return redirect()->to(url_to('Home::index'));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusError())
                {
                    if($response->errorcode == RopcClientResponse::ERROR_CODE_SESSION_NOT_FOUND 
                       || $response->errorcode == RopcClientResponse::ERROR_CODE_INVALID_SESSION)
                    {
                        $this->resetAuthentication($session);
                        $session->setFlashdata('auth_error',$response->error_string());
                        return redirect()->to(url_to('Login::index'));
                    }
                    $data['auth_error'] = $response->error_string();
                    log_message('debug','Authentication Failed. Response: '.print_r($response,true));
                }
                else if($response->httpcode == self::HTTP_STATUS_UNAUTHORIZED && $response->isAuthStatusProceed())
                {
                    // It should not be possible to get here. 
                    //We just circle back to step 1 , but for sure , no auth will be done
                    $this->setCurrentStep(self::STEP_ONE);
                    $data['step'] = $this->getCurrentStep();
                }
                else
                {
                    $data['auth_error'] = 'Unknown Error';
                    log_message('debug','Authentication Failed. Response: '.print_r($response,true));
                }
            }
            catch(RopcClientException $e)
            {
                log_message('debug','Authentication Failed. '.$e->getMessage());
                $data['auth_error'] = $e->getMessage();
            }
        }
        return view('login',$data);
    }

    private function getCurrentStep()
    {
        $session = session();
        $step = $session->get(self::STEP_SESSION_PARAM);
        if($step == null)
        {
            $step = self::STEP_ONE;
        }

        $session->set(self::STEP_SESSION_PARAM,$step);
        return $step;
    }

    private function setCurrentStep($step)
    {
        $session = session();
        $session->set(self::STEP_SESSION_PARAM,$step);
    }

    private function setRemoteSessionId($sessionid)
    {
        $session = session();
        $session->set(self::REMOTE_SESSION_ID_SESSION_PARAM,$sessionid);
    }

    private function getRemoteSessionId()
    {
        $session = session();
        return $session->get(self::REMOTE_SESSION_ID_SESSION_PARAM);
    }

    private function resetAuthentication($session)
    {
        $this->setCurrentStep(self::STEP_ONE);
        $session->setUser(null);
        $session->remove(self::REMOTE_SESSION_ID_SESSION_PARAM);
    }

    private function createRopcClient($username,$password,$extraparameters = null)
    {
        $endpoint = env(self::ENDPOINT_ENV_KEY);
        $clientid = env(self::CLIENT_ID_ENV_KEY);
        $clientSecret = env(self::CLIENT_SECRET_ENV_KEY);
        $secureConnection = env(self::SECURE_CONNECTION_ENV_KEY);
        $debugEnabled = env(self::CONNDEBUG_ENABLED_ENV_KEY);
        $logfile  = env(self::LOGFILE_ENV_KEY);

        $client = new RopcClient($endpoint);
        $client->setClientCredentials($clientid,$clientSecret);
        $client->setAuthenticationMethod(RopcClient::AUTHENTICATION_BASIC);
        $client->setSecure($secureConnection);
        $client->setUserCredentials($username,$password);
        if($extraparameters != null && is_array($extraparameters))
            $client->setExtraParameters($extraparameters);
        
        if($debugEnabled && $logfile != null && strlen($logfile)!=0)
        {
            $client->enableDebug($debugEnabled,$logfile);
        }
        
        return $client;
    }
}