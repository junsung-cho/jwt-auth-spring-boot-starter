package dev.junsung.jwt.config

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import dev.junsung.jwt.converter.DefaultJwtHeaderConverter
import dev.junsung.jwt.converter.JwtClaimsSetConverter
import dev.junsung.jwt.converter.JwtHeaderConverter
import dev.junsung.jwt.converter.ScopeJwtClaimsSetConverter
import dev.junsung.jwt.properties.JwtProperties
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder

@Configuration(proxyBeanMethods = false)
class JwtConfig(
    private val jwtProperties: JwtProperties,
) {
    @Bean
    @ConditionalOnMissingBean
    fun algorithm(): Algorithm = jwtProperties.algorithm()

    @Bean
    @ConditionalOnMissingBean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    @ConditionalOnMissingBean
    fun jwkSource(): JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(jwtProperties.jwk()))

    @Bean
    @ConditionalOnMissingBean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder = NimbusJwtEncoder(jwkSource)

    @Bean
    @ConditionalOnMissingBean
    fun jwtDecoder(
        algorithm: Algorithm,
        jwkSource: JWKSource<SecurityContext>,
    ): JwtDecoder {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>()
        when (algorithm) {
            is JWSAlgorithm -> jwtProcessor.jwsKeySelector = JWSVerificationKeySelector(algorithm, jwkSource)
            else -> throw IllegalStateException("${algorithm.name} couldn't be inferred")
        }
        return NimbusJwtDecoder(jwtProcessor)
    }

    @Bean
    @ConditionalOnMissingBean
    fun jwtClaimsSetConverter(): JwtClaimsSetConverter = ScopeJwtClaimsSetConverter()

    @Bean
    @ConditionalOnMissingBean
    fun jwtHeaderConverter(): JwtHeaderConverter = DefaultJwtHeaderConverter()
}
