package dev.junsung.jwt.configurer

import com.nimbusds.jose.Algorithm
import dev.junsung.jwt.converter.JwtClaimsSetConverter
import dev.junsung.jwt.converter.JwtHeaderConverter
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsPasswordService
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import java.time.Instant
import kotlin.time.Duration

class BearerAuthenticationProvider(
    private val timeToLive: Duration,
    private val algorithm: Algorithm,
    private val passwordEncoder: PasswordEncoder,
    private val jwtEncoder: JwtEncoder,
    private val userDetailsService: UserDetailsService,
    private val userDetailsPasswordService: UserDetailsPasswordService?,
    private val jwtHeaderConverter: JwtHeaderConverter,
    private val jwtClaimsSetConverter: JwtClaimsSetConverter,
) : AbstractUserDetailsAuthenticationProvider() {
    companion object {
        private const val USER_NOT_FOUND_PASSWORD = "userNotFoundPassword"
        private const val CODE_BAD_CREDENTIALS = "AbstractUserDetailsAuthenticationProvider.badCredentials"
    }

    @Volatile
    private var userNotFoundEncodedPassword: String? = null

    override fun additionalAuthenticationChecks(
        userDetails: UserDetails,
        authentication: UsernamePasswordAuthenticationToken,
    ) {
        if (authentication.credentials == null) {
            logger.debug("Failed to authenticate since no credentials provided")
            throw BadCredentialsException(messages.getMessage(CODE_BAD_CREDENTIALS, "Bad credentials"))
        }
        val presentedPassword = authentication.credentials.toString()
        if (!passwordEncoder.matches(presentedPassword, userDetails.password)) {
            logger.debug("Failed to authenticate since password does not match stored value")
            throw BadCredentialsException(messages.getMessage(CODE_BAD_CREDENTIALS, "Bad credentials"))
        }
    }

    override fun retrieveUser(
        username: String?,
        authentication: UsernamePasswordAuthenticationToken,
    ): UserDetails {
        prepareTimingAttackProtection()
        try {
            return userDetailsService.loadUserByUsername(username)
        } catch (exception: UsernameNotFoundException) {
            mitigateAgainstTimingAttack(authentication)
            throw exception
        } catch (exception: InternalAuthenticationServiceException) {
            throw exception
        } catch (exception: Exception) {
            throw InternalAuthenticationServiceException(exception.message, exception)
        }
    }

    override fun createSuccessAuthentication(
        principal: Any,
        authentication: Authentication,
        userDetails: UserDetails,
    ): Authentication {
        if (userDetailsPasswordService != null && passwordEncoder.upgradeEncoding(userDetails.password)) {
            val presentedPassword = authentication.credentials.toString()
            val newPassword = passwordEncoder.encode(presentedPassword)
            userDetailsPasswordService.updatePassword(userDetails, newPassword)
        }

        val result = super.createSuccessAuthentication(principal, authentication, userDetails)
        val token =
            try {
                val jwsAlgorithm = SignatureAlgorithm.from(algorithm.name) ?: MacAlgorithm.from(algorithm.name)
                val jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm)
                val jwsHeader = jwtHeaderConverter.convert(jwsHeaderBuilder)

                val issuedAt = Instant.now()
                val builder =
                    JwtClaimsSet
                        .builder()
                        .issuedAt(issuedAt)
                        .notBefore(issuedAt)
                if (timeToLive.isFinite()) {
                    builder.expiresAt(issuedAt.plusMillis(timeToLive.inWholeMilliseconds))
                }
                val claims = jwtClaimsSetConverter.convert(builder, result)

                val jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, claims)
                jwtEncoder.encode(jwtEncoderParameters).tokenValue
            } catch (ex: Exception) {
                throw InternalAuthenticationServiceException(ex.message, ex)
            }
        return BearerAuthenticationToken(userDetails.username, token)
    }

    private fun prepareTimingAttackProtection() {
        if (userNotFoundEncodedPassword == null) {
            userNotFoundEncodedPassword = passwordEncoder.encode(USER_NOT_FOUND_PASSWORD)
        }
    }

    private fun mitigateAgainstTimingAttack(authentication: UsernamePasswordAuthenticationToken) {
        if (authentication.credentials != null) {
            val presentedPassword = authentication.credentials.toString()
            passwordEncoder.matches(presentedPassword, userNotFoundEncodedPassword)
        }
    }
}
