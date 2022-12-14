<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>SB Admin 2 - Login</title>

    <!-- Custom fonts for this template-->
    <link href="vendor/fontawesome-free/css/all.min.css" rel="stylesheet" type="text/css">
    <link
        href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i"
        rel="stylesheet">

    <!-- Custom styles for this template-->
    <link href="css/sb-admin-2.min.css" rel="stylesheet">
    
    <style type="text/css">
    	.bg-login-image {
  	  background: url("img/Science_login-599541171.webp");
   	  background-position: center;
          background-size: cover;
        }
    </style>
</head>

<body class="bg-gradient-primary">

    <div class="container">

        <!-- Outer Row -->
        <div class="row justify-content-center">

            <div class="col-xl-10 col-lg-12 col-md-9">

                <div class="card o-hidden border-0 shadow-lg my-5">
                    <div class="card-body p-0">
                        <!-- Nested Row within Card Body -->
                        <div class="row">
                            <div class="col-lg-6 d-none d-lg-block bg-login-image"></div>
                            <div class="col-lg-6">
                                <div class="p-5">
                                    <div class="text-center">
                                        <h1 class="h4 text-gray-900 mb-4">Gamatech Demo Login</h1>
                                    </div>

                                    <?php if(isset($auth_error)): ?>
                                    <div class="text-center">
                                        <h1 class="h4 text-red-900 mb-4">Auth Failed. <?php echo $auth_error; ?></h1>
                                    </div>
                                    <?php endif; ?>

                                    <?php if($session->getFlashData('auth_error') != null): ?>
                                    <div class="text-center">
                                        <h1 class="h4 text-red-900 mb-4">Auth Failed. <?php echo $session->getFlashData('auth_error'); ?></h1>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php if ($step == \App\Controllers\Login::STEP_ONE): ?>
                                    <!-- username login form -->
                                    <form class="user" method="POST" action="<?php echo site_url('login');?>">
                                      <div class="form-group">
                                        <input type="text" class="form-control form-control-user" name="username" placeholder="Username or Email"/>
                                      </div>
                                      <hr/>
                                      <button type="submit" class="btn btn-primary btn-user btn-block">Next</button>
                                    </form>
                                    <!-- end username login form -->
                                    <?php endif; ?>
                                    
                                    <?php if ($step == \App\Controllers\Login::STEP_TWO): ?>
                                    <!-- otp login form -->
                                    <form class="user" method="POST">
                                      
                                      <div class="text-center">
                                        <h1 class="h4 text-gray-900 mb-4">An OTP code was sent to <?php echo $user->getPhoneNumber();?></h1>
                                      </div>

                                      <div class="form-group">
                                        <input type="text" class="form-control form-control-user" 
                                            name="username" disabled="disabled" value="<?php echo $user->getUsername();?>"/>
                                      </div>

                                      <div class="form-group">
                                         <input type="text" class="form-control form-control-user" name="otp" placeholder="Enter OTP code"/>
                                      </div>

                                      <button type="submit" class="btn btn-primary btn-user btn-block">Next</button>
                                    </form>
                                    <!-- end otp login form -->
                                    <?php endif; ?>
                                    
                                    <?php if ($step == \App\Controllers\Login::STEP_THREE): ?>
                                    <!-- password login form -->
                                    <form class="user" method="POST">
                                      
                                      <div class="form-group">
                                        <input type="text" class="form-control form-control-user" 
                                            name="username" disabled="disabled" value="<?php echo $user->getUsername();?>"/>
                                      </div>

                                      <div class="form-group">
                                         <input type="password" class="form-control form-control-user" name="password" placeholder="Enter Password"/>
                                      </div>

                                      <button type="submit" class="btn btn-primary btn-user btn-block">Complete Authentication</button>
                                    </form>
                                    <!-- end password login form -->
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>

        </div>

    </div>

    <!-- Bootstrap core JavaScript-->
    <script src="vendor/jquery/jquery.min.js"></script>
    <script src="vendor/bootstrap/js/bootstrap.bundle.min.js"></script>

    <!-- Core plugin JavaScript-->
    <script src="vendor/jquery-easing/jquery.easing.min.js"></script>

    <!-- Custom scripts for all pages-->
    <script src="js/sb-admin-2.min.js"></script>

</body>

</html>
