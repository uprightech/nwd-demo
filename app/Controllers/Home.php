<?php

namespace App\Controllers;

use App\Libraries\RopcClient;
use App\Models\RopcClientException;

class Home extends BaseController
{
    public function index()
    {
        $auth = service('auth');
        return view('dashboard',['user'=>$auth->getUser()->getUsername()]);
    }

    public function logout()
    {
        $auth = service('auth');
        $session = session();
        $session->remove('__step');
        $session->remove('__session_id');
        $auth->logout();
        return redirect()->to(url_to('Login::index'));
    }
}
