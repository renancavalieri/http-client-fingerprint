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
     * Always return "127.0.0.1" if rant on CLI
     * 
     * @return string
     * @throws IpAddressException
     */
    public function getIpAddress() : IpAddress
    {
        if (($this->instances["ipaddress"] ?? false) === false)
        {
            if ($this->isCli())
            {
                $this->instances["ipaddress"] = new IpAddress("127.0.0.1");
            }
            else
            {
                $ip_value = trim(filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_STRING));
                $this->instances["ipaddress"] = new IpAddress($ip_value);
            }
        }
        return $this->instances["ipaddress"];
    }
    
    /**
     * Get the userAgent
     * 
     * Always returns "PHP CONSOLE CLIENT" on cli
     * 
     * @param int $max_lenght
     * @throws UserAgentException when the userAgent is empty
     * @return string
     */
    public function getUserAgent(int $max_lenght = 1024) : string
    {
        if ($this->isCli())
        {
            $userAgent = substr(trim(filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_STRING)), 0, $max_lenght);
            if ($userAgent === "")
            {
                throw new UserAgentException("The client doesn't sent a valid user agent");
            }
        }
        else
        {
            return "PHP CONSOLE CLIENT";
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
    
    /**
     * @return bool
     */
    protected function isCli() : bool
    {
        return (php_sapi_name() === 'cli' || php_sapi_name() === 'cli-server');
    }
}
