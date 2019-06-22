# Password generator and checker

This class can generate or check passwords with certain rules.

It can generate a password based on rules that determine which characters it can contain.

Currently it can verify if the password contains a given number of lower case letters, upper case letters, digits, special characters and a minimum length.

The class can also take a given password and verify if it matches the requested rules and check a password strength.

### Usage example
```php
<?php

 use Beeflow\Passwd\Passwd;

 // I am changing default password policy
 $passwordPolicy = array('specialCharsCount' => 3, 'minimumPasswordLength' => 12);

 $password = new Passwd( $passwordPolicy );

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
```