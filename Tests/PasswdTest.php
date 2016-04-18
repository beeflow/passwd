<?php

namespace Beeflow\Passwd\Tests;

use Beeflow\Passwd\Passwd;

/**
 * @author Rafal Przetakowski <rafal.p@beeflow.co.uk>
 */
class PasswdTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Passwd
     */
    private $passwd;


    public function setUp()
    {
        $this->passwd = new Passwd();
    }

    /**
     * Test if method returns correct range
     */
    public function testSrange()
    {
        $expected = '01234789';
        $actual = $this->invokeMethod('srange', array('/[0-4 7-9]/'));
        $this->assertEquals($expected, implode('', $actual));
    }

    /**
     * Call protected/private method of a class.
     *
     * @param object &$object    Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array $parameters  Array of parameters to pass into method.
     *
     * @return mixed Method return.
     */
    private function invokeMethod($methodName, array $parameters = [])
    {
        $reflection = new \ReflectionClass(get_class($this->passwd));
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method->invokeArgs($this->passwd, $parameters);
    }

    /**
     * Test default minimum password length
     */
    public function testGetDefaultMinimumPasswordLength()
    {
        $expected = 8;
        $actual = $this->invokeMethod('getMinimumPasswordLength');
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test minimum password length after changing password policy
     */
    public function testGetDifferentMinimumPasswordLength()
    {
        $expected = 10;
        $this->passwd->setPolicy(array('numbersCount' => 4));
        $actual = $this->invokeMethod('getMinimumPasswordLength');
        $this->assertEquals($expected, $actual);
    }

    public function testPasswordLength()
    {
        $this->assertTrue($this->invokeMethod('isPasswordLengthOK', array('12345678')));
        $this->assertFalse($this->invokeMethod('isPasswordLengthOK', array('1234567')));
    }


    public function testUpperChars()
    {
        $this->assertTrue($this->invokeMethod('areUpperCharsOK', array('1234AS7')));
        $this->assertFalse($this->invokeMethod('areUpperCharsOK', array('1234aS7')));
    }

    public function testLowerChars()
    {
        $this->assertTrue($this->invokeMethod('areLowerCharsOK', array('1234as7')));
        $this->assertFalse($this->invokeMethod('areLowerCharsOK', array('1234aS7')));
    }

    public function testSpecialChars()
    {
        $this->assertTrue($this->invokeMethod('areSpecialCharsOK', array('1!.4as7')));
        $this->assertFalse($this->invokeMethod('areSpecialCharsOK', array('12!4aS7')));
    }

    public function testCheckStrength()
    {
        $this->assertEquals(5, $this->passwd->checkStrength('e$53.ER6f')->getStrengthPoints());
        $this->assertFalse(5 == $this->passwd->checkStrength('e$53ER6f')->getStrengthPoints());
        $this->assertEquals(4, $this->passwd->checkStrength('e$53ER6f')->getStrengthPoints());

        $this->assertEquals('Very Weak', $this->passwd->checkStrength('e$3E')->getStrengthInfo());
        $this->assertEquals('Weak', $this->passwd->checkStrength('e$s3E2')->getStrengthInfo());
        $this->assertEquals('Good', $this->passwd->checkStrength('e$s3E222')->getStrengthInfo());
        $this->assertEquals('Strong', $this->passwd->checkStrength('E$s3E..2')->getStrengthInfo());
        $this->assertEquals('Very Strong', $this->passwd->checkStrength('e$s3E.2G')->getStrengthInfo());
        
    }

    public function testPasswordCheck()
    {
        $this->assertTrue($this->passwd->check('e$s3E.2G'));
        $this->assertFalse($this->passwd->check('e$3E'));
    }

    public function testGenerate()
    {
        $password = $this->passwd->generate();
        $this->assertEquals(5, $this->passwd->checkStrength($password)->getStrengthPoints());
    }
}
