<?php 

namespace App\Models;

class User
{
    private $username;
    private $phoneNumber;

    public function __construct($username=null, $phoneNumber=null)
    {
        $this->username = $username;
        $this->phoneNumber = $phoneNumber;
    }

    public function setUsername($username)
    {
        $this->username = $username;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function setPhoneNumber($phoneNumber)
    {
        $this->phoneNumber = $phoneNumber;
    }

    public function getPhoneNumber()
    {
        return $this->phoneNumber;
    }
}