<?php

require "vendor/autoload.php";

use PhilDier\AwsCertTool\Client;
use Aws\Iam\IamClient;

$cert = "/path/to/legit/test/cert.pem";
$inter = "/path/to/legit/test/inter.pem";
$key = "/path/to/legit/test/key.pem";
$aws_profile = "profile";

$client = new Client([
	'iam_client' => new IamClient([
		'region' => 'us-east-1',
		'version' => '2010-05-08',
		'profile' => $aws_profile
	])
]);

print_r($client->list());

var_dump($client->validate([
	'CertificateBody' => file_get_contents($inter)
]));

var_dump($client->validate([
	'CertificateBody' => file_get_contents($cert)
]));

echo $client->fetchIntermediate(
	file_get_contents($cert)
);
