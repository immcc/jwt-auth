<?php
/**
 * Created by PhpStorm.
 * User: liyuzhao
 * Date: 2019-08-07
 * Time: 14:14
 */

namespace Immcc\JwtAuth\Traits;

use Hyperf\Utils\ApplicationContext;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Token;
use Immcc\JwtAuth\Exception\TokenValidException;

trait CommonTrait
{
    /**
     * @return Builder
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     */
    public function getBuilder()
    {
        $config = ApplicationContext::getContainer()->get(Configuration::class);
        assert($config instanceof Configuration);

        return $config->builder();
    }

    /**
     * @return Parser
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     */
    public function getParser(Decoder $decoder = null, ClaimFactory $claimFactory = null)
    {
        $config = ApplicationContext::getContainer()->get(Configuration::class);
        assert($config instanceof Configuration);

        return $config->parser();
    }

    /**
     * @return ValidationData
     * @see [[Lcobucci\JWT\ValidationData::__construct()]]
     */
    public function getValidationData($currentTime = null)
    {
        return new ValidationData($currentTime);
    }


    /**
     * 验证jwt token的data部分
     * @param Token $token token object
     * @return bool
     */
    public function validateToken(Token $token, $currentTime = null)
    {
        $data = $this->getValidationData($currentTime);
        return $token->validate($data);
    }

    /**
     * 验证 jwt token
     * @param Token $token token object
     * @return bool
     * @throws \Throwable
     */
    public function verifyToken(Token $token)
    {
        $alg = $token->getHeader('alg');
        if (empty($this->supportedAlgs[$alg])) {
            throw new TokenValidException('Algorithm not supported', 401);
        }
        /** @var Signer $signer */
        $signer = new $this->supportedAlgs[$alg];
        return $token->verify($signer, $this->getKey('public'));
    }

    public function __get($name)
    {
        return $this->$name;
    }
}
