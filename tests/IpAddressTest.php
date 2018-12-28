<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use Pollus\HttpClientFingerprint\Models\IpAddress;
use Pollus\HttpClientFingerprint\Exceptions\IpAddressException;

final class IpAddressTest extends TestCase
{
    ///////////////////////////////////////////////////////////////////////////
    // IVP4
    ///////////////////////////////////////////////////////////////////////////
    
    public function testValidIPv4Address() : void
    {   
        $this->assertSame(true, (new IpAddress("127.0.0.1"))->isIPv4());
        $this->assertSame(true, (new IpAddress("188.125.254.2"))->isIPv4());
        $this->assertSame(true, (new IpAddress("255.255.255.255"))->isIPv4());
        $this->assertSame(true, (new IpAddress("1.0.0.0"))->isIPv4());
        $this->assertSame(false, (new IpAddress("::1"))->isIPv4());
    }
    
    public function testInvalidOutOfRangeIpv4Address()
    {
        $this->expectException(IpAddressException::class);
        new IpAddress("256.0.0.1");
    }
    
    public function testInvalidIPv4Address()
    {
        $this->expectException(IpAddressException::class);
        new IpAddress("192.168.254.0/32");
    }
    
    public function testPrivateRangeIPv4Address()
    {
        $this->assertSame(true, (new IpAddress("192.168.0.1"))->inPrivateRange());
        $this->assertSame(true, (new IpAddress("10.0.0.1"))->inPrivateRange());
        $this->assertSame(false, (new IpAddress("198.254.2.3"))->inPrivateRange());
    }
    
    public function testReservedRangeIPv4Address()
    {
        $this->assertSame(false, (new IpAddress("192.168.0.1"))->inReservedRange());
        $this->assertSame(true, (new IpAddress("127.0.0.1"))->inReservedRange());
        $this->assertSame(true, (new IpAddress("0.0.0.0"))->inReservedRange());
        $this->assertSame(true, (new IpAddress("255.255.255.255"))->inReservedRange());
    }
    
    ///////////////////////////////////////////////////////////////////////////
    // IVP6
    ///////////////////////////////////////////////////////////////////////////
    
    public function testValidIPv6Address() : void
    {   
        $this->assertSame(true, (new IpAddress("1a15:ca10:8ce5:1b9b:6818:2700:68aa:c860"))->isIPv6());
        $this->assertSame(true, (new IpAddress("d353:fb4:bf3e:916f:a86f:ed1e:8f14:272e"))->isIPv6());
        $this->assertSame(true, (new IpAddress("10a9:af90:f3b1:2259:4660:e581:f74e:3712"))->isIPv6());
        $this->assertSame(true, (new IpAddress("54f0:0:0:2743:66fe:51ad:a7f:a025"))->isIPv6());
        $this->assertSame(true, (new IpAddress("54f0::2743:66fe:51ad:a7f:a025"))->isIPv6());
        $this->assertSame(true, (new IpAddress("::1"))->isIPv6());
        $this->assertSame(false, (new IpAddress("127.0.0.1"))->isIPv6());
        $this->assertSame(false, (new IpAddress("199.99.99.99"))->isIPv6());
        
    }
    
    public function testInvalidOutOfRangeIpv6Address()
    {
        $this->expectException(IpAddressException::class);
        new IpAddress("54g0::2743:66fe:51ad:a7f:a025");
    }
    
    public function testInvalidIPv6Address()
    {
        $this->expectException(IpAddressException::class);
        new IpAddress("::1/32");
    }
    
    public function testPrivateRangeIPv6Address()
    {
        $this->assertSame(true, (new IpAddress("fc::1"))->inPrivateRange());
        $this->assertSame(true, (new IpAddress("fd::1"))->inPrivateRange());
        
    }
    
    public function testReservedRangeIPv6Address()
    {
        $this->assertSame(true, (new IpAddress("::1"))->inReservedRange());
        $this->assertSame(false, (new IpAddress("54f0::2743:66fe:51ad:a7f:a025"))->inReservedRange());
    }
}