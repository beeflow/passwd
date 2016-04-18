<?php
/**
 * GNU General Public License (Version 2, June 1991)
 *
 * This program is free software; you can redistribute
 * it and/or modify it under the terms of the GNU
 * General Public License as published by the Free
 * Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */
namespace Beeflow\Passwd;

/**
 * Password generator with password policy
 *
 * @author Rafal Przetakowski <rafal.p@beeflow.co.uk>
 */
class Passwd
{
    /**
     * How meny lower chars
     *
     * @var integer
     */
    private $lowerCharsCount = 2;

    /**
     * How meny upper chars
     *
     * @var integer
     */
    private $upperCharsCount = 2;

    /**
     * How meny special chars
     *
     * @var integer
     */
    private $specialCharsCount = 2;

    /**
     * Haw meny numbers
     *
     * @var integer
     */
    private $numbersCount = 2;

    /**
     *
     * @var integer
     */
    private $minimumPasswordLength = 8;

    /**
     *
     * @var string
     */
    private $upperChars = '/[A-Z]/';

    /**
     *
     * @var string
     */
    private $lowerChars = '/[a-z]/';

    /**
     * Whatever you mean by 'special char'
     *
     * @var string
     */
    private $specialChars = '/[!@#$%^&*()\-_=+{};:,<.>]/';

    /**
     * Numbers - space in range is required for srange function
     *
     * @var string
     */
    private $numbers = '/[0-5 6-9]/';  //numbers

    /**
     * Chars to generate passwords
     *
     * @var string
     */
    private $passwordChars = '';

    /**
     * Password strength points - max 4 point
     *
     * @var integer
     */
    private $passwordStrengthPoints = 0;

    /**
     * Password strenght info
     *
     * @var array
     */
    private $passwordStrengthInfo = array('Very Weak', 'Very Weak', 'Weak', 'Good', 'Strong', 'Very Strong');

    /**
     * Construct - you may set your own password policy
     *
     * @param array $passwordPolicy - array(lowerCharsCount => 2, upperCharsCount => 2, specialCharsCount => 2,
     *                              numbersCount => 2, minimumPasswordLength => 2)
     */
    public function __construct(array $passwordPolicy = array())
    {
        $this->setPolicy($passwordPolicy);
        $this->setPasswordCharts();
    }

    /**
     * Sets password policy
     *
     * @param array $passwordPolicy
     * @return $this
     */
    public function setPolicy(array $passwordPolicy)
    {
        $myPasswordPolicy = array('lowerCharsCount', 'upperCharsCount', 'specialCharsCount', 'numbersCount', 'minimumPasswordLength');
        foreach ($passwordPolicy as $policyKey => $policyValue) {
            if (in_array($policyKey, $myPasswordPolicy)) {
                $this->$policyKey = $policyValue;
            }
        }
        $this->setPasswordCharts();

        return $this;
    }

    /**
     * Sets characters for password
     *
     * @return $this
     */
    private function setPasswordCharts()
    {
        $passwordCharts = '';
        if (0 < $this->specialCharsCount) {
            $passwordCharts .= str_replace('/[', '', str_replace(']/', '', $this->specialChars));
        }
        if (0 < $this->numbersCount) {
            $passwordCharts .= implode('', $this->srange($this->numbers));
        }
        if (0 < $this->lowerCharsCount) {
            $passwordCharts .= implode('', $this->srange($this->lowerChars));
        }
        if (0 < $this->upperCharsCount) {
            $passwordCharts .= implode('', $this->srange($this->upperChars));
        }
        $this->passwordChars = $passwordCharts;

        return $this;
    }

    /**
     * @author manuel@levante.de
     * @param string $range
     * @return array
     */
    private function srange($range)
    {
        $n = array();
        $a = array();
        preg_match_all("/([0-9a-zA-Z]{1,2})-([0-9a-zA-Z]{0,2})/", $range, $a);

        foreach ($a[1] as $k => $v) {
            $n = array_merge($n, range($v, (empty($a[2][$k]) ? $v : $a[2][$k])));
        }

        return ($n);
    }

    /**
     * Generate password
     *
     * @return string password
     */
    public function generate()
    {
        $randomPassword = "";
        $minimumPasswordLength = $this->getMinimumPasswordLength();

        for ($i = 0; $i <= $minimumPasswordLength; $i++) {
            $randomPassword .= substr($this->passwordChars, rand(0, strlen($this->passwordChars) - 1), 1);
        }
        if ($this->check($randomPassword)) {
            return $randomPassword;
        } else {
            return $this->generate();
        }
    }

    /**
     *
     * @return integer
     */
    private function getMinimumPasswordLength()
    {
        $passwordPolicyCharsCount = $this->lowerCharsCount + $this->numbersCount + $this->specialCharsCount + $this->upperCharsCount;
        if ($passwordPolicyCharsCount > $this->minimumPasswordLength) {
            return $passwordPolicyCharsCount;
        } else {
            return $this->minimumPasswordLength;
        }
    }

    /**
     * Check your password
     *
     * @param string $password
     * @return boolean
     */
    public function check($password)
    {
        return (
            $this->isPasswordLengthOK($password)
            && $this->areUpperCharsOK($password)
            && $this->areLowerCharsOK($password)
            && $this->areSpecialCharsOK($password)
            && $this->areNumbersOK($password)
        );
    }

    /**
     *
     * @param string $password
     * @return boolean
     */
    private function isPasswordLengthOK($password)
    {
        $passwordLength = strlen($password);
        $minimumLength = $this->getMinimumPasswordLength();
        if ($passwordLength < $minimumLength) {
            return false;
        }

        return true;
    }

    /**
     *
     * @param strubg $password
     * @return boolean
     */
    private function areUpperCharsOK($password)
    {
        $o = array();
        $upperChars = str_replace(' ', '', $this->upperChars);
        $charsCount = preg_match_all($upperChars, $password, $o);
        if ($charsCount < $this->upperCharsCount) {
            return false;
        }

        return true;
    }

    /**
     *
     * @param string $password
     * @return boolean
     */
    private function areLowerCharsOK($password)
    {
        $o = array();
        $lowerChars = str_replace(' ', '', $this->lowerChars);
        $charsCount = preg_match_all($lowerChars, $password, $o);
        if ($charsCount < $this->lowerCharsCount) {
            return false;
        }

        return true;
    }

    /**
     *
     * @param string $password
     * @return boolean
     */
    private function areSpecialCharsOK($password)
    {
        $o = array();
        $specialChars = str_replace(' ', '', $this->specialChars);
        $charsCount = preg_match_all($specialChars, $password, $o);
        if ($charsCount < $this->specialCharsCount) {
            return false;
        }

        return true;
    }

    /**
     *
     * @param string $password
     * @return boolean
     */
    private function areNumbersOK($password)
    {
        $o = array();
        $numbers = str_replace(' ', '', $this->numbers);
        $charsCount = preg_match_all($numbers, $password, $o);
        if ($charsCount < $this->numbersCount) {
            return false;
        }

        return true;
    }

    /**
     *
     * @return integer
     */
    public function getStrengthPoints()
    {
        return $this->passwordStrengthPoints;
    }

    /**
     *
     * @return string
     */
    public function getStrengthInfo()
    {
        return $this->passwordStrengthInfo[$this->passwordStrengthPoints];
    }

    /**
     *
     * @param string $password
     *
     * @return $this
     */
    public function checkStrength($password)
    {
        $this->passwordStrengthPoints = 0;

        if ($this->areUpperCharsOK($password)) {
            $this->passwordStrengthPoints++;
        }
        if ($this->areLowerCharsOK($password)) {
            $this->passwordStrengthPoints++;
        }
        if ($this->areSpecialCharsOK($password)) {
            $this->passwordStrengthPoints++;
        }
        if ($this->areNumbersOK($password)) {
            $this->passwordStrengthPoints++;
        }
        if ($this->isPasswordLengthOK($password)) {
            $this->passwordStrengthPoints++;
        }

        return $this;
    }

}