<?php

namespace Beeflow\Passwd\Tests;

use Beeflow\Passwd\Passwd;
use PHPUnit\Framework\TestCase;

/**
 * @author Rafal Przetakowski <rafal.p@beeflow.co.uk>
 */
class PasswdTest extends TestCase
{
    /**
     * @var Passwd
     */
    private $passwd;

    public function setUp(): void
    {
        $this->passwd = new Passwd();
    }

    /**
     * Test if method returns correct range
     * @throws \ReflectionException
     */
    public function testSrange(): void
    {
        $expected = '01234789';
        $actual = $this->invokeMethod('srange', ['/[0-4 7-9]/']);
        $this->assertEquals($expected, implode('', $actual));
    }

    /**
     * Call protected/private method of a class.
     *
     * @param string $methodName Method name to call
     * @param array  $parameters Array of parameters to pass into method.
     *
     * @return mixed Method return.
     * @throws \ReflectionException
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
     * @throws \ReflectionException
     */
    public function testGetDefaultMinimumPasswordLength(): void
    {
        $expected = 8;
        $actual = $this->invokeMethod('getMinimumPasswordLength');
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test minimum password length after changing password policy
     * @throws \ReflectionException
     */
    public function testGetDifferentMinimumPasswordLength(): void
    {
        $expected = 10;
        $this->passwd->setPolicy(['numbersCount' => 4]);
        $actual = $this->invokeMethod('getMinimumPasswordLength');
        $this->assertEquals($expected, $actual);
    }

    /**
     * @throws \ReflectionException
     */
    public function testPasswordLength(): void
    {
        $this->assertTrue($this->invokeMethod('isPasswordLengthOK', ['12345678']));
        $this->assertFalse($this->invokeMethod('isPasswordLengthOK', ['1234567']));
    }

    /**
     * @throws \ReflectionException
     */
    public function testUpperChars(): void
    {
        $this->assertTrue($this->invokeMethod('areUpperCharsOK', ['1234AS7']));
        $this->assertFalse($this->invokeMethod('areUpperCharsOK', ['1234aS7']));
    }

    /**
     * @throws \ReflectionException
     */
    public function testLowerChars(): void
    {
        $this->assertTrue($this->invokeMethod('areLowerCharsOK', ['1234as7']));
        $this->assertFalse($this->invokeMethod('areLowerCharsOK', ['1234aS7']));
    }

    /**
     * @throws \ReflectionException
     */
    public function testSpecialChars(): void
    {
        $this->assertTrue($this->invokeMethod('areSpecialCharsOK', ['1!.4as7']));
        $this->assertFalse($this->invokeMethod('areSpecialCharsOK', ['12!4aS7']));
    }

    public function testCheckStrength(): void
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

    public function testPasswordCheck(): void
    {
        $this->assertTrue($this->passwd->check('e$s3E.2G'));
        $this->assertFalse($this->passwd->check('e$3E'));
    }

    public function testGenerate(): void
    {
        $password = $this->passwd->generate();
        $this->assertEquals(5, $this->passwd->checkStrength($password)->getStrengthPoints());
    }
}
