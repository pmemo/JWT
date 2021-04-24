<?php

class JWT {
    private static $secretKey;
    private $expiration;
    private $header;
    private $payload;
    private $algorithm;
    private $signature;

    static public function secret($key) {
        self::$secretKey = $key;
    }

    private static function base64UrlEncode($text) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }

    public function __construct($token = null) {
        if($token) $this->read($token);
        return $this;
    }

    private function read($token) {
        $tokenParts = explode('.', $token);

        $this->header = base64_decode($tokenParts[0]);
        $this->payload = base64_decode($tokenParts[1]);
        $this->signature = $tokenParts[2];
        $this->algorithm = $this->algorithm ?: 'HS256';
        $this->expiration = isset(json_decode($this->payload)->exp) ? json_decode($this->payload)->exp : false;
    }

    public function payload($data) {
        if($this->expiration) {
            $data['exp'] = $this->expiration;
        }

        $this->payload = json_encode($data);
        return $this;
    }

    public function alg($type) {
        $this->algorithm = $type;
        return $this;
    }

    public function expire($time) {
        $this->expiration = time() + $time;
        if($this->payload) {
            $data = json_decode($this->payload, true);
            $this->payload($data);
        }
        return $this;
    }

    public function encode() {
        $encodedHeader = self::base64UrlEncode(json_encode([
            'typ' => 'JWT',
            'alg' => $this->algorithm?:'HS256'
        ]));
        
        $encodedPayload = self::base64UrlEncode($this->payload);

        $signature = hash_hmac('sha256', $encodedHeader.'.'.$encodedPayload, self::$secretKey, true);
        $encodedSignature = self::base64UrlEncode($signature);

        return $encodedHeader.'.'.$encodedPayload.'.'.$encodedSignature;
    }

    public function verify() {
        if($this->expiration && time() > $this->expiration) return false;

        $encodedHeader = self::base64UrlEncode($this->header);
        $encodedPayload = self::base64UrlEncode($this->payload);
        $signature = hash_hmac('sha256', $encodedHeader.'.'.$encodedPayload, self::$secretKey, true);
        $encodedSignature = self::base64UrlEncode($signature);

        return ($this->signature === $encodedSignature);
    }

    public function decode($key = null) {
        $decodedData = json_decode($this->payload, true);
        
        if($key) {
            return isset($decodedData[$key]) ? $decodedData[$key] : null;
        } else {
            return $decodedData;
        }
    }
}
