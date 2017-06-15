<?php

/**
 * php，java，Aes加密解密，
 * @author  <esyy@qq.com>
**/

namespace wei\Model;
use Think\Model;
class AesModel extends Model {
	protected $autoCheckFields =false;
	
    private $iv = "################";//密钥偏移量IV，可自定义
    private $encryptKey = "################";//AESkey，可自定义
 
    /*public function __construct(){

    }*/
	//加密
    public function encrypt($encryptStr,$encryptKey='',$localIV='') {
        if(!$localIV)$localIV = $this->iv;
        if(!$encryptKey)$encryptKey = $this->encryptKey;
 
        //Open module
        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $localIV);
 
        //print "module = $module <br/>" ;
 
        mcrypt_generic_init($module, $encryptKey, $localIV);
 
        //Padding
        $block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $pad = $block - (strlen($encryptStr) % $block); //Compute how many characters need to pad
        $encryptStr .= str_repeat(chr($pad), $pad); // After pad, the str length must be equal to block or its integer multiples
 
        //encrypt
        $encrypted = mcrypt_generic($module, $encryptStr);
 
        //Close
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);
 
        //return base64_encode($encrypted);
        return strtoupper(bin2hex($encrypted));
 
    }
 
    //解密
    public function decrypt($encryptStr,$encryptKey='',$localIV='') {
        if(!$localIV)$localIV = $this->iv;
        if(!$encryptKey)$encryptKey = $this->encryptKey;
 
        //Open module
        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $localIV);
 
        //print "module = $module <br/>" ;
 
        mcrypt_generic_init($module, $encryptKey, $localIV);
 
        $encryptedData = $this->myhex2bin($encryptStr);
		
        $encryptedData = mdecrypt_generic($module, $encryptedData);
 
        return $encryptedData;
    }
	
	private function myhex2bin($data) {
		$len = strlen($data);
		return pack("H".$len,$data);
	}
}
