/*
* *© Copyright 2021 Visa. All Rights Reserved.**
*
* NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of
* and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property
* rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
*
* By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).
* In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided
* through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED
* INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR
* CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply
* product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally
* do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims
* all liability for any such components, including continued availability and functionality. Benefits depend on implementation
* details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the
* described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,
* implementation and resources by you based on your business and operational details. Please refer to the specific
* API documentation for details on the requirements, eligibility and geographic availability.*
*
* This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,
* functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.
* The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,
* including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.
*
*
*  This sample code is licensed only for use in a non-production environment for sandbox testing. See the license for all terms of use.
*/

<?php

include_once __DIR__ . '/vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class SymmetricEncryptionUtils
{

    private JWEBuilder $jweBuilder;

    private JWEDecrypter $jweDecrypter;

    public function __construct()
    {
        // The key encryption algorithm manager with the RSA-OAEP-256 algorithm.
        $keyEncryptionAlgorithmManager = new AlgorithmManager([new A256GCMKW(),]);

        // The content encryption algorithm manager with the A128GCM algorithm.
        $contentEncryptionAlgorithmManager = new AlgorithmManager([new A256GCM(),]);

        // The compression method manager with the DEF (Deflate) method.
        $compressionMethodManager = new CompressionMethodManager([new Deflate(),]);

        // We instantiate our JWE Builder.
        $this->jweBuilder = new JWEBuilder($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);

        // We instantiate our JWE Decrypter.
        $this->jweDecrypter = new JWEDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);
    }

    /**
     * This method will encrypt the payload and create a JWE token using Shared Secret
     * @param $payload
     * @param $apiKey
     * @param $sharedSecret
     * @return string
     */
    public function encrypt($payload, $apiKey, $sharedSecret): string
    {
        // Our key.
        $jwk = $this->loadKey($sharedSecret);
        $milliseconds = round(microtime(true) * 1000);
        $jwe = $this->jweBuilder
            ->create()              // We want to create a new JWE
            ->withPayload($payload) // We set the payload
            ->withSharedProtectedHeader([
                'alg' => 'A256GCMKW',  // Key Encryption Algorithm
                'enc' => 'A256GCM',       // Content Encryption Algorithm
                'iat' => $milliseconds,   // Current Time Stamp in milliseconds
                'kid' => $apiKey
            ])
            ->addRecipient($jwk)    // We add a recipient (a shared key or public key).
            ->build();              // We build it

        $serializer = new CompactSerializer();
        return $serializer->serialize($jwe, 0);
    }

    /**
     * This method will decrypt the given JWE token using Shared Secret.
     * @param $jweToken
     * @param $sharedSecret
     * @return string|null
     */
    public function decrypt($jweToken, $sharedSecret): ?string
    {
        // Our key.
        $jwk = $this->loadKey($sharedSecret);

        $serializerManager = new JWESerializerManager([new CompactSerializer(),]);
        $jwe = $serializerManager->unserialize($jweToken);
        $success = $this->jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
        if ($success) {
            $jweLoader = new JWELoader(
                $serializerManager,
                $this->jweDecrypter,
                null
            );
            $jwe = $jweLoader->loadAndDecryptWithKey($jweToken, $jwk, $recipient);
            return $jwe->getPayload();
        } else {
            throw new RuntimeException('Error Decrypting JWE');
        }
    }

    /**
     * This method will sign a JWE using the shared secret and create a JWS
     * @param $jweToken
     * @param $signingKid
     * @param $signingSharedSecret
     * @return string
     */
    public function signJwe($jweToken, $signingKid, $signingSharedSecret): string
    {
        // Our key.
        $jwk = $this->loadKey($signingSharedSecret);

        $milliseconds = round(microtime(true) * 1000);
        $algorithmManager = new AlgorithmManager([new HS256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);

        $jwsHeaders = [
            'kid' => $signingKid,
            'cty' => 'JWE',
            'typ' => 'JOSE',
            'alg' => 'HS256',
            'iat' => $milliseconds,
            'exp' => $milliseconds + 3600
        ];

        $jws = $jwsBuilder
            ->create()
            ->withPayload($jweToken)
            ->addSignature($jwk, $jwsHeaders)
            ->build();

        $serializer = new \Jose\Component\Signature\Serializer\CompactSerializer();
        return $serializer->serialize($jws);
    }

    /**
     * This method verify a JWS using the signing shared secret
     * @param $jwsToken
     * @param $signingSharedSecret
     * @return bool true if successful else false
     */
    public function verifyJws($jwsToken, $signingSharedSecret): bool
    {
        // Our key.
        $jwk = $this->loadKey($signingSharedSecret);

        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([new HS256(),]);

        // We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier($algorithmManager);

        // The serializer manager. We only use the JWS Compact Serialization Mode.
        $serializerManager = new JWSSerializerManager([new \Jose\Component\Signature\Serializer\CompactSerializer(),]);

        // We try to load the token.
        $jws = $serializerManager->unserialize($jwsToken);

        return $jwsVerifier->verifyWithKey($jws, $jwk, 0);
    }

    private function loadKey($sharedSecret): JWK
    {
        $ssKey = hash('sha256', $sharedSecret);
        return new JWK([
            'kty' => 'oct',
            'k' => $ssKey
        ]);
    }
}