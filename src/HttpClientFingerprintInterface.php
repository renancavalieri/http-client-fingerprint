<?php declare(strict_types=1);

/**
 * Http Client Fingerprint
 * @license https://opensource.org/licenses/MIT MIT
 * @author Renan Cavalieri <renan@tecdicas.com>
 */

namespace Pollus\HttpClientFingerprint;

use Pollus\HttpClientFingerprint\Exceptions\SessionIdException;
use Pollus\HttpClientFingerprint\Exceptions\UserAgentException;
use Pollus\HttpClientFingerprint\Models\IpAddress;

interface HttpClientFingerprintInterface
{
    /**
     * Gets the IpAddress
     * 
     * @return string
     * @throws IpAddressException
     */
    public function getIpAddress() : IpAddress;
        
    /**
     * Gets the userAgent
     * 
     * @param int $max_lenght
     * @throws UserAgentException when the userAgent is empty
     * @return string
     */
    public function getUserAgent(int $max_lenght = 1024) : string;
    
    /**
     * Gets the Session ID
     * 
     * @return string
     * @throws SessionIdException when the session isn't active
     */
    public function getSessionId() : string;
}
