<?php

namespace YaleREDCap\YaleREDCapAuthenticator;


require_once 'vendor/autoload.php';

use OneLogin\Saml2\Auth;

class YNHH_SAML_Authenticator
{
    private $auth;

    public function __construct(string $spEntityId, string $acsUrl)
    {
        $settings1 = [
            'strict' => true,
            'debug' => true,
            'sp' => [
                'entityId' => 'https://redcapynh.ynhh.org',
                'assertionConsumerService' => [
                    'url' => $acsUrl,
                ],
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            ],
            'idp' => [
                'entityId' => 'https://saml.example.com/entityid',
                'singleSignOnService' => [
                    'url' => 'https://mocksaml.com/api/saml/sso',
                ],
                'x509cert' => '-----BEGIN CERTIFICATE-----
                MIIC4jCCAcoCCQC33wnybT5QZDANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJV
                SzEPMA0GA1UECgwGQm94eUhRMRIwEAYDVQQDDAlNb2NrIFNBTUwwIBcNMjIwMjI4
                MjE0NjM4WhgPMzAyMTA3MDEyMTQ2MzhaMDIxCzAJBgNVBAYTAlVLMQ8wDQYDVQQK
                DAZCb3h5SFExEjAQBgNVBAMMCU1vY2sgU0FNTDCCASIwDQYJKoZIhvcNAQEBBQAD
                ggEPADCCAQoCggEBALGfYettMsct1T6tVUwTudNJH5Pnb9GGnkXi9Zw/e6x45DD0
                RuRONbFlJ2T4RjAE/uG+AjXxXQ8o2SZfb9+GgmCHuTJFNgHoZ1nFVXCmb/Hg8Hpd
                4vOAGXndixaReOiq3EH5XvpMjMkJ3+8+9VYMzMZOjkgQtAqO36eAFFfNKX7dTj3V
                pwLkvz6/KFCq8OAwY+AUi4eZm5J57D31GzjHwfjH9WTeX0MyndmnNB1qV75qQR3b
                2/W5sGHRv+9AarggJkF+ptUkXoLtVA51wcfYm6hILptpde5FQC8RWY1YrswBWAEZ
                NfyrR4JeSweElNHg4NVOs4TwGjOPwWGqzTfgTlECAwEAATANBgkqhkiG9w0BAQsF
                AAOCAQEAAYRlYflSXAWoZpFfwNiCQVE5d9zZ0DPzNdWhAybXcTyMf0z5mDf6FWBW
                5Gyoi9u3EMEDnzLcJNkwJAAc39Apa4I2/tml+Jy29dk8bTyX6m93ngmCgdLh5Za4
                khuU3AM3L63g7VexCuO7kwkjh/+LqdcIXsVGO6XDfu2QOs1Xpe9zIzLpwm/RNYeX
                UjbSj5ce/jekpAw7qyVVL4xOyh8AtUW1ek3wIw1MJvEgEPt0d16oshWJpoS1OT8L
                r/22SvYEo3EmSGdTVGgk3x3s+A0qWAqTcyjr7Q4s/GKYRFfomGwz0TZ4Iw1ZN99M
                m0eo2USlSRTVl7QHRTuiuSThHpLKQQ==
                -----END CERTIFICATE-----',
            ],
        ];
        $settings = [
            'strict' => true,
            'debug' => true,
            'sp' => [
                'entityId' =>  'https://redcapynh.ynhh.org',
                'assertionConsumerService' => [
                    'url' => $acsUrl,
                ],
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            ],
            'idp' => [
                'entityId' => 'http://sts2.ynhh.org/adfs/services/trust',
                'singleSignOnService' => [
                    'url' => 'https://sts2.ynhh.org/adfs/ls',
                ],
                'x509certMulti' => array(
                    'signing' => array (
                        0 => '-----BEGIN CERTIFICATE-----
                MIIC1jCCAb6gAwIBAgIQF17VGplRg75JlPOs1pwlfDANBgkqhkiG9w0BAQsFADAn
                MSUwIwYDVQQDExxBREZTIFNpZ25pbmcgLSBzdHMyLnluaGgub3JnMB4XDTIyMDYy
                NzE4NTgwMloXDTI3MDYyNjE4NTgwMlowJzElMCMGA1UEAxMcQURGUyBTaWduaW5n
                IC0gc3RzMi55bmhoLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
                AKcM0LzvG6xvw0TYUVwyTlwn0bvQ+RA1SYC3ZGhdogEfJIEe7pRzZCfXVIYZY82X
                tcC/sRua1XLCPXQUASBtk6xcWwEmwAlzuChQiLrtgRWtgv7wmgFSoIVPt9ItF/Oi
                dFsmnJa1zu1rjQPZhhy6Hb097a32llaU+dVICveUHaAhNL0Dh6m2MYOclx3IshQC
                Ijgw00uG4mIQxcYoKV/vM1luqNIUyPWACi6GMt5ZTu/6EltF+8Ai7BhRYshNNu8D
                WeC8JLApQvHSWRK+I4l2PxAgg6Jod7lOto5KwLEVSy5scBgg/YYH9FqLDvhPKFlG
                zTtUP0ml2rOCGOVKNF6nUA8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAC0Dy2N+e
                hag4adiIlowyupVyp+GCQWQdsfXFxsmz97txjqiRoaLcwrqVG5NXvAbmqlkDyODY
                Aq8Hcn7iiyndWC50lYh5sE8QaGmfZ9GJQTdNDSZ9tONpuvsab5UMbYzkeTVeU4UK
                AKp5sBMMZo7DoNWeiwtWP5SXV5NexWbkAD0otAQztJFSiSFw/Japw/R/dNmGVgZC
                9bhgTZLXIFIGir3rqw9XzEapw77Q6sM5xcP2E57OAZO5Evg8Xjp3PBHi/JE541xB
                seC1nVNgV0dmzV6bVXrR/JtaENtljdwiQXHhCRSDk45YLgBkP4BjADeZjDY6CBHt
                kmR2nLRDyK8bzg==    
                -----END CERTIFICATE-----',
                    ),
                    'encryption' => array (
                        0 => '-----BEGIN CERTIFICATE-----
                        MIIC3DCCAcSgAwIBAgIQOpOWm7xKdLNOx4lAVwInrTANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDEx9BREZTIEVuY3J5cHRpb24gLSBzdHMyLnluaGgub3JnMB4XDTIyMDYyNzE4NTgwMFoXDTI3MDYyNjE4NTgwMFowKjEoMCYGA1UEAxMfQURGUyBFbmNyeXB0aW9uIC0gc3RzMi55bmhoLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5xLtlbRXauO2dHcLDdXBzGuhnlaArHbtwOmUFQQj8DUkUnGK39OFm5ZVMlI9d0jiCraDUIRmKsYPmUycBnooajavbdIFMukGSkVGfVhxCpQxpTdPjFpJ7tbaNLJciAXY0HAiRERjQO9j2SHDInLdlOOtijvXMLecIy/W3SY88keaEPVKx7j+Q/4rEvF1v+FDZUz2u6GW6hmtZFvd76Ax4eMXHAzY/Q1vldpbTd+wckwitYnti9qPXErDuVDBjdvFcc3ycEIwjGtG70qZxGt+4MibntAPRgJv7fVlLxOHT+8Vl3wRznGk6EPdrd+NPQfDMe5KEc+PRaZeUfuD2sCKECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAgJ3VwmEBUVaKSoIe0mRj8bUhPoj3tpiUZdMH57iiinGnugb8h4Km4iZ9/cgb+hdw0gzwj+NU1aeOIBbJe9YBFCCaRTNafg+VQVxWyQbpAb816C1bXC/0a27mFqhYdKzi6JctFAYZp4hwga7DFpNtbyQXIax8ql5XGcdQ7+mh1RgW0Utz684y4lh16+hIoeDK66bGFYaWl7l0CZxSX0anIWJDPEjINjV1pIWYwDBxjt3iydKLJ46IsmB4tPsayuDi0qji8tHz4kdh9APvaGzqwWksSDoi99kMWKGrNz9I4kq4C5O9P5OEQL/Ze2F4kRDS9bSxsuOKEvuLAO+LEEN4kg==
                        -----END CERTIFICATE-----',
                    )
                    ),
            ],
        ];

        $this->auth = new Auth($settings);
    }

    public function login($returnTo = null, array $parameters = array(), $forceAuthn = false, $isPassive = false, $stay = false, $setNameIdPolicy = true, $nameIdValueReq = null)
    {
        return $this->auth->login($returnTo, $parameters, $forceAuthn, $isPassive, $stay, $setNameIdPolicy, $nameIdValueReq);
    }

    public function logout()
    {
        $this->auth->logout();
    }

    public function isAuthenticated()
    {
        return $this->auth->isAuthenticated();
    }

    public function getAttributes()
    {
        if ($this->isAuthenticated()) {
            return $this->auth->getAttributes();
        } else {
            return null;
        }
    }

    public function getLastError()
    {
        return $this->auth->getLastErrorReason();
    }
}

