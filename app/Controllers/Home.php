<?php

namespace App\Controllers;

use App\Libraries\RopcClient;
use App\Models\RopcClientException;

class Home extends BaseController
{
    public function index()
    {
        return view('dashboard');
    }

    public function test()
    {
        $client = new RopcClient('https://flex-server.local/jans-auth/restv1/token');
        $client->setClientCredentials('cdbdb926-a55b-4d53-b914-ee4ebae8a11b','yhGmyY2ugTAxegt');
        $client->setUserCredentials('admin','Programming@1989');
        $client->setSecure(false);
        $client->setAuthenticationMethod(RopcClient::AUTHENTICATION_BASIC);
        echo $client->execute();
    }
}
