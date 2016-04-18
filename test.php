<?php

include 'password.php';

// I am changing default password policy
$passwordPolicy = array('specialCharsCount' => 3, 'minimumPasswordLength' => 12);

$password = new password( $passwordPolicy );

// checking password
$isPasswordOk = $password->check('Th1$I$myPrd!');
if (!$isPasswordOk) {
	echo "Your password is incorrect.<br/>";
} else {
	echo "Your password is correct.<br/>";
}
// checking password strength
$password->checkStrength('Th1$I$myPrd!', 'info');
echo "Your password strength points: " . $password->getStrengthPoints()."<br/>";
echo "Your password strength info: " . $password->getStrengthInfo()."<br/>";

// generating new password
echo "Your new password: " . $password->generate() ."<br/>";
