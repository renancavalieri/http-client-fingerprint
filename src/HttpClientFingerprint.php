<?php declare(strict_types=1);

/**
 * Http Client Fingerprint
 * @license https://opensource.org/licenses/MIT MIT
 * @author Renan Cavalieri <renan@tecdicas.com>
 */

namespace Pollus\HttpClientFingerprint;

use Pollus\HttpClientFingerprint\Models\IpAddress;
use Pollus\HttpClientFingerprint\Exceptions\IpAddressException;
use Pollus\HttpClientFingerprint\Exceptions\UserAgentException;
use Pollus\HttpClientFingerprint\Exceptions\SessionIdException;
use Pollus\HttpClientFingerprint\HttpClientFingerprintInterface;

/**
 * This class is only a helper to get the remote IP Address, UserAgent and 
 * Session ID.
 * 
 * It doesn't parse the User Agent string, nor check proxies on remote Ip Address.
 * 
 * Also it does provides a very basic IP validation using internal PHP function "filter_var"
 */
class HttpClientFingerprint implements HttpClientFingerprintInterface
{
    /**
     * @var array
     */
    protected $instances = array();
            
    
    /**
     * Gets the IpAddress
     * 
     * @return string
     * @throws IpAddressException
     */
    public function getIpAddress() : IpAddress
    {
        if (($this->instances["ipaddress"] ?? false) === false)
        {
            $ip_value = trim(filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_STRING));
            $this->instances["ipaddress"] = new IpAddress($ip_value);
        }
        return $this->instances["ipaddress"];
    }
    
    /**
     * Get the userAgent
     * 
     * @param int $max_lenght
     * @throws UserAgentException when the userAgent is empty
     * @return string
     */
    public function getUserAgent(int $max_lenght = 1024) : string
    {
        $userAgent = substr(trim(filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_STRING)), 0, $max_lenght);
        
        if ($userAgent === "")
        {
            throw new UserAgentException("The client doesn't sent a valid user agent");
        }
    }
    
    /**
     * Gets the Session ID
     * 
     * @return string
     * @throws SessionIdException when the session aren't active
     */
    public function getSessionId() : string
    {
        if (session_status() !== PHP_SESSION_ACTIVE)
        {
            throw new SessionIdException("Session wasn't started");
        }
        return session_id();
    }
}
