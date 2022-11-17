<?php

namespace App\Controllers;

class Login extends BaseController 
{
    public function index() 
    {
        return view('username_login');
    }
}