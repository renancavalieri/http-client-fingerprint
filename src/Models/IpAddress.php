<?php declare(strict_types=1);

/**
 * Http Client Fingerprint
 * @license https://opensource.org/licenses/MIT MIT
 * @author Renan Cavalieri <renan@tecdicas.com>
 */

namespace Pollus\HttpClientFingerprint\Models;

use Pollus\HttpClientFingerprint\Exceptions\IpAddressException;

class IpAddress 
{    
    protected $ip;
    
    /**
     * The supplied value should be a valid IPv4 or IPv6 address.
     * @param string $ip
     * @throws IpAddressException if the supplied value is invalid
     */
    public function __construct(string $ip) 
    {
        $this->ip = $ip;
        
        if ($this->isValidAddress() === false)
        {
            throw new IpAddressException("The supplied value is not an IP address");
        }
    }
    
    /**
     * Returns TRUE if the supplied value is an IPV6 address
     * 
     * @return bool
     */
    public function isIPv6() : bool
    {
        if (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        {
            return true;
        }
        return false;
    }
    
    /**
     * Returns TRUE if the supplied value is an IPV4 address
     * 
     * @return bool
     */
    public function isIPv4() : bool
    {
        if (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
        {
            return true;
        }
        return false;
    }
    
    /**
     * Returns true to the following private IPv4 ranges: 
     *      10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
     * 
     * Returns true for all the IPv6 addresses starting with FD or FC.
     * 
     * @return bool
     */
    public function inPrivateRange() : bool
    {
        if (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE))
        {
            return false;
        }
        return true;
    }
    
    /**
     * Returns TRUE to the following reserved IPv4 ranges:
     *      0.0.0.0/8, 169.254.0.0/16, 127.0.0.0/8 and 240.0.0.0/4.
     * 
     * Returns TRUE to the following reserved IPv6 ranges: 
     *      ::1/128, ::/128, ::ffff:0:0/96 and fe80::/10.
     * 
     * @return bool
     */
    public function inReservedRange() : bool
    {
        if (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE))
        {
            return false;
        }
        return true;
    }

    /**
     * @return string
     */
    public function __toString() : string
    {
        return $this->ip;
    }

    /**
     * Get the stored IP address
     *     
     * @return string
     */
    public function toString() : string
    {
        return $this->ip;
    }
        
    /**
     * Check if address is IPV6 or IVP4, returns FALSE if both fail.
     * @return bool
     */
    protected function isValidAddress() : bool
    {
        if ($this->isIPv4() === false && $this->isIPv6() === false)
        {
            return false;
        }
        return true;
    }
}
