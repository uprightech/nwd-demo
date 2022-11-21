<?php

namespace App\Models;

class RopcClientResponse
{
    const AUTH_STATUS_PROCEED = 0;
    const AUTH_STATUS_ERROR   = 1;
    const AUTH_STATUS_UNKNOWN = -1;

    const ERROR_CODE_NO_ERROR = 0;
    const ERROR_CODE_GENERIC_ERROR = 10001;
    const ERROR_CODE_USER_NOT_FOUND = 10002;
    const ERROR_CODE_PHONE_NUMBER_NOT_FOUND = 10003;
    const ERROR_CODE_FAILED_TO_SEND_OTP_CODE = 10004;
    const ERROR_CODE_OTP_CODE_MISMATCH = 10005;
    const ERROR_CODE_SESSION_NOT_FOUND = 10006;
    const ERROR_CODE_INVALID_SESSION = 10007;
    const ERROR_CODE_INVALID_USERPASS = 10008;

    private static $error_code_map = [
        self::ERROR_CODE_NO_ERROR     => 'No Error',
        self::ERROR_CODE_GENERIC_ERROR => 'Generic Error',
        self::ERROR_CODE_USER_NOT_FOUND => 'User not found',
        self::ERROR_CODE_PHONE_NUMBER_NOT_FOUND => 'Phone number not found',
        self::ERROR_CODE_FAILED_TO_SEND_OTP_CODE => 'Failed to send OTP code',
        self::ERROR_CODE_OTP_CODE_MISMATCH => 'OTP Code Mismatch',
        self::ERROR_CODE_SESSION_NOT_FOUND => 'Session not found',
        self::ERROR_CODE_INVALID_SESSION => 'Invalid session provided',
        self::ERROR_CODE_INVALID_USERPASS => 'Invalid username/password'
    ];

    public $httpcode;
    public $authstatus;
    public $sessionid;
    public $phonenumber;
    public $errorcode;
    public $body;

    public function __construct()
    {
        $this->httpcode = -1;
        $this->authstatus = self::AUTH_STATUS_UNKNOWN;
        $this->sessionid = '';
        $this->phonenumber = '';
        $this->errorcode = 0;
        $this->body = '';
    }

    public function setAuthStatusFromString($authstatus)
    {
        if(strcasecmp($authstatus,"proceed") == 0)
            $this->authstatus = self::AUTH_STATUS_PROCEED;
        else if(strcasecmp($authstatus,"error") == 0) 
            $this->authstatus = self::AUTH_STATUS_ERROR;
        else
            $this->authstatus = self::AUTH_STATUS_UNKNOWN;
    }

    public function error_string()
    {
        return self::$error_code_map[$this->errorcode];
    }

    public function isAuthStatusProceed()
    {
        return $this->authstatus == self::AUTH_STATUS_PROCEED;
    }

    public function isAuthStatusError()
    {
        return $this->authstatus == self::AUTH_STATUS_ERROR;
    }

    public function isAuthStatusUnknown()
    {
        return $this->authstatus == self::AUTH_STATUS_UNKNOWN;
    }
}