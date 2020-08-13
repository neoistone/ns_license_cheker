<?php
/**
 * Neoistone Blog License verfication
 * @class connecters
 * @package  Neoistone
 * @author   Neoistone Devteam <devsupport@neoistone.com>
 */
class connecters {

    private static function getDomain(){
        $pieces = parse_url($_SERVER['HTTP_HOST']);
        $domain = isset($pieces['host']) ? $pieces['host'] : '';
        if(preg_match('/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i', $domain, $regs)){
            return $regs['domain'];
        }
        return FALSE;
    }
    /**
     * this function help you getting server ip address
     */
    private static function server_ip(){
        $ch = curl_init('https://cpanel.net/showip.cgi');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return curl_exec($ch);
        curl_close($ch);
    }
    protected static $domain = DOMAIN_NAME;
    /**
     *  @param auth_id 
     * @return boolean or string
     */

    private static function isSiteAvailible($url){
        // Check, if a valid url is provided
        if(!filter_var($url, FILTER_VALIDATE_URL)){
            return false;
        }
    
        // Initialize cURL
        $curlInit = curl_init($url);
        
        // Set options
        curl_setopt($curlInit,CURLOPT_CONNECTTIMEOUT,10);
        curl_setopt($curlInit,CURLOPT_HEADER,true);
        curl_setopt($curlInit,CURLOPT_NOBODY,true);
        curl_setopt($curlInit,CURLOPT_RETURNTRANSFER,true);
    
        // Get response
        $response = curl_exec($curlInit);
        
        // Close a cURL session
        curl_close($curlInit);
    
        return $response?true:false;
    }
    private static function connect_server($licensekey, $localkey='',$api_url) {
        // Must match what is specified in the MD5 Hash Verification field
        // of the licensing product that will be used with this check.
        $licensing_secret_key = 'neoistoe_blog_go';
        $localkeydays = 15;
        $allowcheckfaildays = 5;
    
        $check_token = time() . md5(mt_rand(100000000, mt_getrandmax()) . $licensekey);
        $checkdate = date("Ymd");
        $domain = self::getDomain();
        $usersip = self::server_ip();
        $dirpath = dirname(__FILE__);
        $localkeyvalid = false;
        if ($localkey) {
            $localkey = str_replace("\n", '', $localkey); # Remove the line breaks
            $localdata = substr($localkey, 0, strlen($localkey) - 32); # Extract License Data
            $md5hash = substr($localkey, strlen($localkey) - 32); # Extract MD5 Hash
            if ($md5hash == md5($localdata . $licensing_secret_key)) {
                $localdata = strrev($localdata); # Reverse the string
                $md5hash = substr($localdata, 0, 32); # Extract MD5 Hash
                $localdata = substr($localdata, 32); # Extract License Data
                $localdata = base64_decode($localdata);
                $localkeyresults = json_decode($localdata, true);
                $originalcheckdate = $localkeyresults['checkdate'];
                if ($md5hash == md5($originalcheckdate . $licensing_secret_key)) {
                    $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - $localkeydays, date("Y")));
                    if ($originalcheckdate > $localexpiry) {
                        $localkeyvalid = true;
                        $results = $localkeyresults;
                        $validdomains = explode(',', $results['validdomain']);
                        if (!in_array(self::getDomain(), $validdomains)) {
                            $localkeyvalid = false;
                            $localkeyresults['status'] = "Invalid";
                            $results = array();
                        }
                        $validips = explode(',', $results['validip']);
                        if (!in_array($usersip, $validips)) {
                            $localkeyvalid = false;
                            $localkeyresults['status'] = "Invalid";
                            $results = array();
                        }
                        $validdirs = explode(',', $results['validdirectory']);
                        if (!in_array($dirpath, $validdirs)) {
                            $localkeyvalid = false;
                            $localkeyresults['status'] = "Invalid";
                            $results = array();
                        }
                    }
                }
            }
        }
        if (!$localkeyvalid) {
            $responseCode = 0;
            $postfields = array(
                'licensekey' => $licensekey,
                'domain' => $domain,
                'ip' => $usersip,
                'dir' => $dirpath,
            );
            if ($check_token) $postfields['check_token'] = $check_token;
            $query_string = '';
            foreach ($postfields AS $k=>$v) {
                $query_string .= $k.'='.urlencode($v).'&';
            }
            if (function_exists('curl_exec')) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api_url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
                curl_setopt($ch, CURLOPT_TIMEOUT, 30);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $data = curl_exec($ch);
                $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
            } else {
                $responseCodePattern = '/^HTTP\/\d+\.\d+\s+(\d+)/';
                $fp = @fsockopen($api_url, 80, $errno, $errstr, 5);
                if ($fp) {
                    $newlinefeed = "\r\n";
                    $header = "POST ".$api_url . " HTTP/1.0" . $newlinefeed;
                    $header .= "Host: ".$api_url . $newlinefeed;
                    $header .= "Content-type: application/x-www-form-urlencoded" . $newlinefeed;
                    $header .= "Content-length: ".@strlen($query_string) . $newlinefeed;
                    $header .= "Connection: close" . $newlinefeed . $newlinefeed;
                    $header .= $query_string;
                    $data = $line = '';
                    @stream_set_timeout($fp, 20);
                    @fputs($fp, $header);
                    $status = @socket_get_status($fp);
                    while (!@feof($fp)&&$status) {
                        $line = @fgets($fp, 1024);
                        $patternMatches = array();
                        if (!$responseCode
                            && preg_match($responseCodePattern, trim($line), $patternMatches)
                        ) {
                            $responseCode = (empty($patternMatches[1])) ? 0 : $patternMatches[1];
                        }
                        $data .= $line;
                        $status = @socket_get_status($fp);
                    }
                    @fclose ($fp);
                }
            }
            if ($responseCode != 200) {
                $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - ($localkeydays + $allowcheckfaildays), date("Y")));
                if ($originalcheckdate > $localexpiry) {
                    $results = $localkeyresults;
                } else {
                    $results = array();
                    $results['status'] = "Invalid";
                    $results['description'] = "Remote Check Failed";
                    return $results;
                }
            } else {
                preg_match_all('/<(.*?)>([^<]+)<\/\\1>/i', $data, $matches);
                $results = array();
                foreach ($matches[1] AS $k=>$v) {
                    $results[$v] = $matches[2][$k];
                }
            }
            if (!is_array($results)) {
                die("Invalid License Server Response");
            }
            if ($results['md5hash']) {
                if ($results['md5hash'] != md5($licensing_secret_key . $check_token)) {
                    $results['status'] = "Invalid";
                    $results['description'] = "MD5 Checksum Verification Failed";
                    return $results;
                }
            }
            if ($results['status'] == "Active") {
                $results['checkdate'] = $checkdate;
                $data_encoded = json_encode($results);
                $data_encoded = base64_encode($data_encoded);
                $data_encoded = md5($checkdate . $licensing_secret_key) . $data_encoded;
                $data_encoded = strrev($data_encoded);
                $data_encoded = $data_encoded . md5($data_encoded . $licensing_secret_key);
                $data_encoded = wordwrap($data_encoded, 80, "\n", true);
                $write = fopen(STORAGE_PATH.'neoistone/localkey.text', "w");
                fwrite($write, $data_encoded);
                fclose($write);
            }
            $results['remotecheck'] = true;
        }
        unset($postfields,$data,$matches,$api_url,$licensing_secret_key,$checkdate,$usersip,$localkeydays,$allowcheckfaildays,$md5hash);
        return $results;
    }
    private static function license_check($licensekey,$localkey=''){
        $server1 = 'http://server1.license.neoistone.com/modules/servers/licensing/verify.php';
        $server2 = 'http://server2.license.neoistone.com/modules/servers/licensing/verify.php';

        if(self::isSiteAvailible($server1)){
            return self::connect_server($licensekey,$localkey,$server1);
        } elseif (self::isSiteAvailible($server2)) {
            return self::connect_server($licensekey,$localkey,$server2);
        } else {
            $fields_string = http_build_query(
                [
                    'app_id' => $licensekey,
                    'meassage' => 'connection failure wait 5-10 min open admin panel already bug send our devlopers',
                    'server_ip' => self::server_ip(),
                    'app_name' => APP_NAME,
                    'contct_mail' => MAIL_FROM_ADDRESS]);
            $ch = curl_init();
                  curl_setopt($ch,CURLOPT_URL, 'https://www.neoistone.com/send_devlopers.php');
                  curl_setopt($ch,CURLOPT_POST, true);
                  curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
                  curl_setopt($ch,CURLOPT_RETURNTRANSFER, true); 
                  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
                  curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                  curl_exec($ch);
                  curl_close($ch);
            return array('status' => 'connection failure wait 5-10 min open admin panel already bug send our devlopers');
        }
    }
    public static function license_verify(){
        if(!is_file(STORAGE_PATH.'neoistone/localkey.text.')){
            $results = self::license_check(license_id);
        } else {
            $localkeyfile = fopen(STORAGE_PATH.'neoistone/localkey.text.', "r");
            $localkey = fread($localkeyfile,filesize(STORAGE_PATH.'neoistone/localkey.text.'));
            fclose($localkeyfile);
            $results = self::license_check(license_id,$localkey);
        }
        // Interpret response
        if ($results["status"]=="Active") {
            return true;
        } else {
            return $results["status"];
        }
    }
}
header('X-Powered-By:  NEOISTONE');
header('ip_address: '.getenv('REMOTE_ADDR'));
if(!DEBBUG_MODE){
    error_reporting(0);
}
if(!is_dir(STORAGE_PATH.'neoistone')){
   mkdir(STORAGE_PATH.'neoistone');
}
$ns_license = connecters::license_verify();

?>
