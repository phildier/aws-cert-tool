<?php

namespace PhilDier\AwsCertTool;

use Aws\Iam\IamClient;

use InvalidArgumentException;

class Client {
	private $iam_client = null;
	private $aws_region = null;

	public function __construct(array $params = []) {
		if(array_key_exists('aws_region',$params) && !empty($params['aws_region'])) {
			$this->aws_region = $params['aws_region'];
		} else {
			$this->aws_region = "us-east-1";
		}

		if(array_key_exists('iam_client',$params) && $params['iam_client'] instanceof IamClient) {
			$this->iam_client = $params['iam_client'];
		} else {
			$this->iam_client = new IamClient([
				'region' => $this->aws_region,
				'version' => '2010-05-08'
			]);
		}
	}

	/**
	 * lists configured server certificates in iam
	 */
	public function list(array $params = []) {
		$ret = [];
		$response = $this->iam_client->ListServerCertificates($params);
		foreach($response['ServerCertificateMetadataList'] as $cert) {
			$ret[] = [
				'ServerCertificateName' => $cert['ServerCertificateName'],
				'Arn' => $cert['Arn'],
				'Expiration' => $cert['Expiration']
			];
		}
		return $ret;
	}

	/**
	 * adds a new server certificate to iam
	 *
	 * ([
     *   'CertificateBody' => '<string>', // REQUIRED
     *   'CertificateChain' => '<string>',
     *   'Path' => '<string>',
     *   'PrivateKey' => '<string>', // REQUIRED
     *   'ServerCertificateName' => '<string>', // REQUIRED
	 * ]);
	 */
	public function add(array $params = []) {
		$params['CertificateBody'] = $this->convertCertificate($params['CertificateBody']);
		$params['CertificateChain'] = $this->convertCertificate($params['CertificateChain']);
		return $this->iam_client->UploadServerCertificate($params);
	}

	/**
	 * removes a given certificate
	 */
	public function remove(array $params = []) {
		return $this->iam_client->DeleteServerCertificate($params);
	}

	/**
	 * does basic validation of the parameters before passing to 
	 * iam
	 */
	public function validate(array $params = []) {
		$cert = $this->convertCertificate($params['CertificateBody']);
		if(false === openssl_x509_parse($cert)) {
			throw new InvalidArgumentException("invalid certificate");
		}

		$inter = $this->convertCertificate($params['CertificateChain']);
		if(false === openssl_x509_parse($inter)) {
			throw new InvalidArgumentException("invalid intermediate");
		}

		if(false === openssl_get_privatekey($params['PrivateKey'])) {
			throw new InvalidArgumentException("invalid private key");
		}

		return true;
	}

	/**
	 * fetches the correct intermediate certificate for a given tls certificate
	 */
	public function fetchIntermediate($certificate) {
		$cert = openssl_x509_parse(
			$this->convertCertificate($certificate)
		);

		preg_match(
			"/.*URI:(?<uri>http[^\s]+).*/",
			$cert['extensions']['authorityInfoAccess'],
			$matches
		);

		return $this->convertCertificate(
			file_get_contents($matches['uri'])
		);
	}

	/**
	 * returns an unchanged pem certificate, or converts der to pem
	 * and returns the pem version
	 */
	private function convertCertificate($certificate_data) {
		if(false !== openssl_x509_parse($certificate_data)) {
			return $certificate_data;
		}
		$pem_cert = $this->der2pem($certificate_data);

		if(strstr($pem_cert, 'BEGIN CERTIFICATE')) {
			return $pem_cert;
		}

		throw new InvalidArgumentException('unknown certificate format');
	}

	/**
	 * converts der certificate to pem
	 */
	private function der2pem($der_data) {
		$pem = chunk_split(base64_encode($der_data), 64, "\n");
		$pem = "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
		return $pem;
	}
}
