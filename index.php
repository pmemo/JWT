<?php

require 'JWT.php';

// set secret key
JWT::secret('9023asdaskl10kdoasdko012');

// create token

$jwt = new JWT();
$jwt->alg('HS256'); // set algorithm (default is HS256)
$jwt->expire(3600); // set expiration time
//$jwt->expire(strtotime('+1 week')); // other example of usage
$jwt->payload([
  'userId' => 31221
]); 
$token = $jwt->encode(); // generate JWT token

// verifcation
$jwt = new JWT($token); // load JWT token

// verify token
if($jwt->verify()) {
  echo 'Token is valid and no expired!' ;
} else {
  echo 'Token is not valid or expired!'; 
}

// decoding
print_r($jwt->decode()); // shows payload array
echo $jwt->decode('userId'); // shows userId value
