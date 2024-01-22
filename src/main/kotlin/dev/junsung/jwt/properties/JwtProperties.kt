package dev.junsung.jwt.properties

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import dev.junsung.jwt.configurer.UsernamePasswordAuthenticationConverter
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import kotlin.time.Duration

@ConfigurationProperties("jwt")
data class JwtProperties(
    var encodedKey: String? = null,
    var timeToLive: String = "1h",
    var httpMethod: String = "POST",
    var tokenIssueUrl: String = "/auth/token",
    var usernameParameter: String = "username",
    var passwordParameter: String = "password",
    var tokenName: String = "token",
    var algorithm: String? = "ES512",
    var encryptionMethod: String? = null,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)

    fun timeToLive(): Long = Duration.parse(timeToLive).inWholeMilliseconds

    fun requestMatcher() = AntPathRequestMatcher(tokenIssueUrl, httpMethod)

    fun authenticationConverter() = UsernamePasswordAuthenticationConverter(usernameParameter, passwordParameter)

    fun jwk(): JWK = parseJwk() ?: generateJwk()

    fun algorithm(): Algorithm = (parseJwk()?.algorithm ?: Algorithm(algorithm)).toNamedAlgorithm()

    private fun parseJwk(): JWK? = encodedKey?.let { JWK.parse(Base64.from(it).decodeToString()) }

    private fun generateJwk(): JWK {
        val algorithm = algorithm()
        return when (KeyType.forAlgorithm(algorithm)) {
            KeyType.EC -> ECKeyGenerator(Curve.forJWSAlgorithm(JWSAlgorithm(algorithm.name)).first())
            KeyType.RSA -> RSAKeyGenerator(2048)
            KeyType.OCT -> OctetSequenceKeyGenerator(256)
            KeyType.OKP -> OctetKeyPairGenerator(Curve.forJWSAlgorithm(JWSAlgorithm(algorithm.name)).first())
            else -> throw IllegalStateException("${algorithm.name} couldn't be inferred")
        }.algorithm(algorithm)
            .keyIDFromThumbprint(true)
            .generate()
            .also { logger.info("Generated JWK: ${Base64.encode(it.toJSONString())}") }
    }

    companion object {
        fun Algorithm.toNamedAlgorithm(): Algorithm {
            return when (this.name) {
                JWSAlgorithm.HS256.name -> JWSAlgorithm.HS256
                JWSAlgorithm.HS384.name -> JWSAlgorithm.HS384
                JWSAlgorithm.HS512.name -> JWSAlgorithm.HS512
                JWSAlgorithm.RS256.name -> JWSAlgorithm.RS256
                JWSAlgorithm.RS384.name -> JWSAlgorithm.RS384
                JWSAlgorithm.RS512.name -> JWSAlgorithm.RS512
                JWSAlgorithm.ES256.name -> JWSAlgorithm.ES256
                JWSAlgorithm.ES256K.name -> JWSAlgorithm.ES256K
                JWSAlgorithm.ES384.name -> JWSAlgorithm.ES384
                JWSAlgorithm.ES512.name -> JWSAlgorithm.ES512
                JWSAlgorithm.PS256.name -> JWSAlgorithm.PS256
                JWSAlgorithm.PS384.name -> JWSAlgorithm.PS384
                JWSAlgorithm.PS512.name -> JWSAlgorithm.PS512
                JWSAlgorithm.EdDSA.name -> JWSAlgorithm.EdDSA
                JWEAlgorithm.RSA_OAEP_256.name -> JWEAlgorithm.RSA_OAEP_256
                JWEAlgorithm.RSA_OAEP_384.name -> JWEAlgorithm.RSA_OAEP_384
                JWEAlgorithm.RSA_OAEP_512.name -> JWEAlgorithm.RSA_OAEP_512
                JWEAlgorithm.A128KW.name -> JWEAlgorithm.A128KW
                JWEAlgorithm.A192KW.name -> JWEAlgorithm.A192KW
                JWEAlgorithm.A256KW.name -> JWEAlgorithm.A256KW
                JWEAlgorithm.DIR.name -> JWEAlgorithm.DIR
                JWEAlgorithm.ECDH_ES.name -> JWEAlgorithm.ECDH_ES
                JWEAlgorithm.ECDH_ES_A128KW.name -> JWEAlgorithm.ECDH_ES_A128KW
                JWEAlgorithm.ECDH_ES_A192KW.name -> JWEAlgorithm.ECDH_ES_A192KW
                JWEAlgorithm.ECDH_ES_A256KW.name -> JWEAlgorithm.ECDH_ES_A256KW
                JWEAlgorithm.ECDH_1PU.name -> JWEAlgorithm.ECDH_1PU
                JWEAlgorithm.ECDH_1PU_A128KW.name -> JWEAlgorithm.ECDH_1PU_A128KW
                JWEAlgorithm.ECDH_1PU_A192KW.name -> JWEAlgorithm.ECDH_1PU_A192KW
                JWEAlgorithm.ECDH_1PU_A256KW.name -> JWEAlgorithm.ECDH_1PU_A256KW
                JWEAlgorithm.A128GCMKW.name -> JWEAlgorithm.A128GCMKW
                JWEAlgorithm.A192GCMKW.name -> JWEAlgorithm.A192GCMKW
                JWEAlgorithm.A256GCMKW.name -> JWEAlgorithm.A256GCMKW
                JWEAlgorithm.PBES2_HS256_A128KW.name -> JWEAlgorithm.PBES2_HS256_A128KW
                JWEAlgorithm.PBES2_HS384_A192KW.name -> JWEAlgorithm.PBES2_HS384_A192KW
                JWEAlgorithm.PBES2_HS512_A256KW.name -> JWEAlgorithm.PBES2_HS512_A256KW
                else -> throw IllegalStateException("$this couldn't be inferred")
            }
        }
    }
}
