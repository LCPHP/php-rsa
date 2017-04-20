<?php
namespace niklaslu;
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2017/4/20
 * Time: 11:46
 *
 *
 * keyType file ：文件 str:直接传递字符串
 *
 *
 */
class Rsa
{
    // 私钥字符串
    protected $private_key_str = '';

    // 公钥字符串
    protected $public_key_str = '';

    // 私钥文件路径
    protected $private_key_path = '' ;

    // 公钥文件路径
    protected $public_key_path = '';

    protected $error = '';

    protected $keyType = 'file';

    public function __construct($config = null){

        if (isset($config['type'])){
            $this->keyType = $config['type'] ? $config['type'] : $this->keyType;
        }

        if ($this->keyType == 'file'){
            // 获取默认public key private key
            if (isset($config['public_key_path']) && isset($config['private_key_path'])){
                $this->public_key_path = $config['public_key_path'];
                $this->private_key_path = $config['private_key_path'];
            }else{
                $this->public_key_path = dirname(__FILE__) . '/key/rsa_public_key.pem';
                $this->private_key_path = dirname(__FILE__) . '/key/rsa_private_key.pem';
            }

            if ($this->private_key_path){
                $this->private_key_str = $this->getKeyStr($this->private_key_path);
            }
            if ($this->public_key_path){
                $this->public_key_str = $this->getKeyStr($this->public_key_path);
            }
        }elseif ($this->keyType == 'str'){
            $this->private_key_str = isset($config['private_key_str']) ? $config['private_key_str'] : $this->private_key_str;
            $this->public_key_str = isset($config['public_key_str']) ? $config['public_key_str'] : $this->public_key_str;
        }

        return $this;

    }

    public function setPublicKeyStr($publicKeyStr){

        $this->public_key_str = $publicKeyStr;
        return $this;
    }

    public function setPrivateKeyStr($privateKeyStr){

        $this->private_key_str = $privateKeyStr;
        return $this;
    }

    /**
     * 私钥加密
     * @param $data
     * @param string $encrypted
     * @return bool|string
     */
    public function encryptByPrivate($data , $encrypted = ''){

        $privateKey = $this->getPrivateKeyStr();

        if (!$privateKey){
            return false;
        }

        // data为数组的时候转成json
        if (!is_string($data)){
            $data = json_encode($data);
        }
        //私钥加密
        openssl_private_encrypt($data,$encrypted,$privateKey);

        //加密后的内容通常含有特殊字符，需要编码转换下，在网络间通过url传输时要注意base64编码是否是url安全的
        $encrypted = base64_encode($encrypted);

        return $encrypted;

    }

    /**
     * 公钥解密
     * @param $data
     * @param string $decrypted
     * @return bool|string
     */
    public function decryptByPublic($data , $decrypted = ''){

        $publicKey = $this->getPublicKeyStr();
        if (!$publicKey){
            return false;
        }

        $data = base64_decode($data);

        //私钥加密的内容通过公钥可用解密出来
        openssl_public_decrypt($data ,$decrypted, $publicKey);

        return $decrypted;

    }

    /**
     * 公钥加密
     * @param $data
     * @param string $encrypted
     * @return bool|string
     */
    public function encryptByPublic($data , $encrypted = ''){

        $publicKey = $this->getPublicKeyStr();
        if (!$publicKey){
            return false;
        }
        // data为数组的时候转成json
        if (!is_string($data)){
            $data = json_encode($data);
        }
        // 公钥加密
        openssl_public_encrypt($data , $encrypted , $publicKey);
        $encrypted = base64_encode($encrypted);

        return $encrypted;

    }

    /**
     * 私钥解密
     * @param $data
     * @param string $decrypted
     * @return bool|string
     */
    public function decryptByPrivate($data , $decrypted = ''){

        $privateKey = $this->getPrivateKeyStr();

        if (!$privateKey){
            return false;
        }

        $data = base64_decode($data);

        openssl_private_decrypt($data , $decrypted , $privateKey);

        return $decrypted;

    }

    /**
     * 通过文件获取key
     * @param $filePath
     * @return string
     */
    protected function getKeyStr($filePath){

        $str = file_get_contents($filePath);

        return $str;
    }

    /**
     * 获取private key
     * @return string
     */
    public function getPrivateKeyStr(){

        if ($this->private_key_str){
            $key = openssl_pkey_get_private($this->private_key_str);
            if ($key){
                return $key;
            }else {
                $this->error = '私钥不可用';
                return false;
            }
        }else{
            $this->error = '私钥不存在';
            return false;
        }

    }

    /**
     * 获取public key
     * @return string
     */
    public function getPublicKeyStr(){

        if ($this->public_key_str){
            $key = openssl_pkey_get_public($this->public_key_str);
            if ($key){
                return $key;
            }else {
                $this->error = '公钥不可用';
                return false;
            }
        }else{
            $this->error = '公钥不存在';
            return false;
        }

    }

    public function getError(){

        return $this->error;
    }


}