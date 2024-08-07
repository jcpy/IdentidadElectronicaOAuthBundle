<?php
namespace Mitic\IdentidadElectronicaOAuthBundle\OAuth\ResourceOwner;

use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\GenericOAuth2ResourceOwner;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Mitic\IdentidadElectronicaOAuthBundle\JWT\HasSubject;

final class IdentidadElectronicaResourceOwner extends GenericOAuth2ResourceOwner
{
    public const TYPE = 'identidad_electronica';

    /**
     * {@inheritdoc}
     */
    protected array $paths = [
        'identifier' => 'sub'
    ];

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        if (!isset($accessToken['access_token'])) {
            throw new \InvalidArgumentException('Undefined index access_token');
        }

        $jwt = self::jwtDecode($accessToken['access_token']);
        $data = $jwt ? json_decode(base64_decode($jwt), true) : [];

        if (isset($data['exp'])) {
            $accessToken['expires'] = $data['exp'];
        }

        $response = $this->getUserResponse();
        $response->setData(json_encode($data));
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    private static function jwtDecode(string $idToken)
    {
        // from http://stackoverflow.com/a/28748285/624544
        [, $jwt] = explode('.', $idToken, 3);

        // if the token was urlencoded, do some fixes to ensure that it is valid base64 encoded
        $jwt = str_replace(['-', '_'], ['+', '/'], $jwt);

        // complete token if needed
        switch (\strlen($jwt) % 4) {
            case 0:
                break;
            case 2:
            case 3:
                $jwt .= '=';
                break;
            default:
                throw new \InvalidArgumentException('Invalid base64 format sent back');
        }

        return $jwt;
    }

    private function jwtTokenValidator(string $tokenString)
    {
        $config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($this->options['client_secret']));
        $token = $config->parser()->parse($tokenString);

        $constraints = [
            new IssuedBy($this->options['iss']),
            new PermittedFor($this->options['client_id']),
            new HasSubject(),
            new ValidAt(new SystemClock(new \DateTimeZone($this->options['timezone']))),
            new SignedWith($config->signer(), $config->signingKey())
        ];

        try {
            $config->validator()->assert($token, ...$constraints);
        } catch (\Lcobucci\JWT\Validation\RequiredConstraintsViolated $exception) {
            throw new AuthenticationException('Not a valid access token.');
        }
    }

    protected function getResponseContent(ResponseInterface $rawResponse): array
    {
        return ["access_token" => $rawResponse->getContent(false)];
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetTokenRequest($url, array $parameters = [])
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];
        $parameters['client_id'] = $this->options['client_id'];
        $parameters['client_secret'] = $this->options['client_secret'];
        $url .= "?" . http_build_query($parameters, '', '&');

        return $this->httpRequest($url, null, $headers, 'POST');
    }

    /**
     * @param mixed $response the 'parsed' content based on the response headers
     *
     * @throws AuthenticationException If an OAuth error occurred or no access token is found
     */
    protected function validateResponseContent($response)
    {
        if (empty($response['access_token'])) {
            throw new AuthenticationException('Not a valid access token.');
        }

        $this->jwtTokenValidator($response['access_token']);
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'infos_url' => '',
            'iss' => '',
            'timezone' => '',
        ]);
    }


}