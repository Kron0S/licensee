<?php

namespace Bart\Licensee;

use Claudusd\Cryptography\Signature\Implementation\SignatureSignPrivateKey;
use Claudusd\Cryptography\KeyGeneration\Implementation\KeyGenerationSHA512RSA4096Bits;


/**
 * This class implements simple methods for license creation and validation.
 * Usage example:
 * $data = array('licensee' => 'Company', 'version' => '1.0', 'valid_until' => time() + 60*60*24*7, 'key' => sha1(uniqid(true)));
 * $lic = new License();
 * $lic::createKeypair('/tmp/private.pem', '/tmp/public.pem');
 * $lic->createLicense($data, '/tmp/private.pem', '/tmp/license.lic');
 * $res = $lic->getDataAndValidateLicense('/tmp/license.lic', '/tmp/public.pem');
 * var_dump($res);
 *
 * @package Bart\Licensee
 */
class License {

	private $sspk, $data, $signature, $license;

	public function __construct() {
		$this->setSspk(new SignatureSignPrivateKey());
	}

	/**
	 * @param array       $data             Data to sign
	 * @param string      $private_key		Private key 
	 * @param bool|string $license_path     Path to file where created license_path should be stored or false for no license_path storing
	 * @return string License data in json format
	 */
	public function createLicense($data, $private_key, $license_path = false) {
		$this->setData(json_encode($data));
		$this->setSignature(base64_encode($this->getSspk()->sign($this->getData(), $private_key)));
		$license = json_encode(array('data'      => $this->getData(),
									 'signature' => $this->getSignature()));

		$this->setLicense($license);

		if ($license_path !== false) {
			$this->storeLicense($license_path);
		}

		return $license;
	}

	/**
	 * @param string $path Path to license_path file
	 * @return void
	 */
	public function storeLicense($path) {
		file_put_contents($path, $this->getLicense());
	}

	/**
	 * @param string $license    	license 
	 * @param string $public_key	public key
	 * @return bool
	 */
	public function validateLicense($license, $public_key) {
		$this->setLicense($license);
		$this->processLicense();

		return $this->getSspk()->verify($this->getData(), base64_decode($this->getSignature()), $public_key);
	}

	/**
	 * @param string $license    	license
	 * @param string $public_key 	public key
	 * @return bool|string Data when verified, false if not
	 */
	public function getDataAndValidateLicense($license, $public_key) {
		if ($this->validateLicense($license, $public_key)) {
			return $this->getData();
		}
		else {
			return false;
		}

	}

	/**
	 */
	public static function createKeypair() {
		$key = new KeyGenerationSHA512RSA4096Bits();
		
		return array($key->getPrivateKey(), $key->getPublicKey());
	}

	private function processLicense() {
		$this->setData(json_decode($this->getLicense())->data);
		$this->setSignature(json_decode($this->getLicense())->signature);
	}

	private function setLicense($license) {
		$this->license = $license;
	}

	private function getLicense() {
		return $this->license;
	}

	private function setData($data) {
		$this->data = $data;
	}

	private function getData() {
		return $this->data;
	}

	private function setSignature($signature) {
		$this->signature = $signature;
	}

	private function getSignature() {
		return $this->signature;
	}

	private function setSspk($sspk) {
		$this->sspk = $sspk;
	}

	private function getSspk() {
		return $this->sspk;
	}

}