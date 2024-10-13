##License
**© Copyright 2018 - 2020 Visa. All Rights Reserved.**

*NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*

*By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*

*This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*

***This sample code is licensed only for use in a non-production environment for sandbox testing. See the license for all terms of use.***

### Prerequisites

VISA uses a number of open source projects to work properly. For the sample code we are using the below dependencies:

* PHP: (Version 8.0 or above)
* web-token/jwt-framework => v2.x

### Dependencies

Below are the project dependencies. Refer to the composer.json file

```sh
{
  "name": "visa/encryption-utils",
  "description": "JWE - Encryption & Decryption Utils",
  "type": "library",
  "require": {
    "ext-curl": "*",
    "ext-json": "*",
    "web-token/jwt-framework": "^v2.2"
  }
}
```

### Usage

You may need to adjust the code as per VISA specifications for the product/apis you are integrating.

- Symmetric Encryption / Decryption (API / Shared Secret)
```sh
   $apiKey = '<API_KEY>';
   $sharedSecret = '<SHARED_SECRET>';
   $payload = '<PAYLOAD>';
   
   //We instantiate our Symmetric Encryption Utils class.
   $symmetricEncryptor = new SymmetricEncryptionUtils();
   
   //Create the Jwe Token
   $jweToken = $symmetricEncryptor->encrypt($payload, $apiKey, $sharedSecret);
   
   //To Sign the JWE, you will need the signing kid and shared secret
   $signingKid = '<SIGNING_KID>';
   $signingSecret = '<SIGNING_SHARED_SECRET>';
   $jwsToken = $symmetricEncryptor->signJwe($jweToken, $signingKid, $signingSecret);
   
   //Verify a JWS using the signing shared secret
   $isVerified = $symmetricEncryptor->verifyJws($jwsToken, $signingSecret);
   
   //Decrypt the JWE using encrypting shared secret
   $decryptedPayload = $symmetricEncryptor->decrypt($jweToken, $sharedSecret);

```

- Asymmetric Encryption / Decryption (RSA PKI)
```sh   
   $kid = '<ENCRYPTING_KID>';
   $encryptionCertificatePath = '<ENCRYPTION_CERTIFICATE_PATH>>';
   $payload = '<PAYLOAD>';
   
   //We instantiate our Asymmetric Encryption Utils class.
   $asymmetricEncryptionUtils = new AsymmetricEncryptionUtils();
   
   //Create the Jwe Token
   $jweToken = $asymmetricEncryptionUtils->encrypt($payload, $kid, $encryptionCertificatePath);
   
   //To Sign the JWE, you will need the signing kid and encryption private key
   $signingPrivateKey = '<SIGNING_PRIVATE_KEY_PATH>';
   $signingKid = '<SIGNING_KID>';
   $jwsToken = $asymmetricEncryptionUtils->signJwe($jweToken, $signingKid, $signingPrivateKey);
   
   //Verify a JWS using the signing shared secret
   $signingCertificate = '<SIGNING_PUBLIC_CERTIFICATE_PATH>';
   $isVerified = $asymmetricEncryptionUtils->verifyJws($jwsToken, $signingCertificate)
   
   $encryptionPrivateKey = '<ENCRYPTING_PRIVATE_KEY_PATH>';
   $decryptedJwe = $asymmetricEncryptionUtils->decrypt($jweToken, $encryptionPrivateKey);
   
```

### Changelog
 - Version 1.0.0
    - Sample code for Symmetric & Asymmetric Encryption/Decryption using JWE & JWS
