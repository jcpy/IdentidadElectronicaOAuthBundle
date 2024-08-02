<?php
namespace Mitic\IdentidadElectronicaOAuthBundle\JWT;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

class HasSubject implements Constraint
{
    public function assert(Token $token): void
    {
        if (!$token->claims()->has('sub')) {
            throw new ConstraintViolation('Subject is not defined');
        }
    }
}