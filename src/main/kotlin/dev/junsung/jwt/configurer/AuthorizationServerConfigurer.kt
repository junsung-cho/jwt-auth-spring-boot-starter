package dev.junsung.jwt.configurer

import com.nimbusds.jose.Algorithm
import dev.junsung.jwt.converter.JwtClaimsSetConverter
import dev.junsung.jwt.converter.JwtHeaderConverter
import dev.junsung.jwt.properties.JwtProperties
import org.springframework.beans.factory.BeanFactory
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.context.ApplicationContext
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.HttpSecurityBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsPasswordService
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.NoOpAuthenticationEntryPoint
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.RequestMatcher

class AuthorizationServerConfigurer<H : HttpSecurityBuilder<H>>(
    private val context: ApplicationContext,
) : AbstractHttpConfigurer<AuthorizationServerConfigurer<H>, H>() {
    private var authenticationEntryPoint: AuthenticationEntryPoint
    private var authenticationConverter: AuthenticationConverter
    private var requestMatcher: RequestMatcher
    private var timeToLive: Long
    private var tokenName: String
    private var onSuccessfulAuthentication: (Authentication) -> Unit
    private var onUnsuccessfulAuthentication: (Authentication?) -> Unit

    private val jwtProperties: JwtProperties
        get() = this.context.getBean(JwtProperties::class.java)
    private val algorithm: Algorithm
        get() = this.context.getBean(Algorithm::class.java)
    private val passwordEncoder: PasswordEncoder
        get() = this.context.getBean(PasswordEncoder::class.java)
    private val jwtEncoder: JwtEncoder
        get() = this.context.getBean(JwtEncoder::class.java)
    private val userDetailsService: UserDetailsService
        get() = this.context.getBean(UserDetailsService::class.java)
    private val userDetailsPasswordService: UserDetailsPasswordService?
        get() = this.context.getBeanOrNull(UserDetailsPasswordService::class.java)
    private val jwtClaimsSetConverter: JwtClaimsSetConverter
        get() = this.context.getBean(JwtClaimsSetConverter::class.java)
    private val jwtHeaderConverter: JwtHeaderConverter
        get() = this.context.getBean(JwtHeaderConverter::class.java)

    init {
        timeToLive = jwtProperties.timeToLive()
        tokenName = jwtProperties.tokenName
        authenticationEntryPoint = NoOpAuthenticationEntryPoint()
        authenticationConverter = jwtProperties.authenticationConverter()
        requestMatcher = jwtProperties.requestMatcher()
        onSuccessfulAuthentication = {}
        onUnsuccessfulAuthentication = {}
    }

    override fun init(http: H) {
        http.authenticationProvider(authenticationProvider)
    }

    override fun configure(http: H) {
        val filter =
            UsernamePasswordAuthenticationFilter(
                tokenName = tokenName,
                requestMatcher = requestMatcher,
                authenticationManager = getAuthenticationManager(http),
                authenticationEntryPoint = authenticationEntryPoint,
                authenticationConverter = authenticationConverter,
                onSuccessfulAuthentication = onSuccessfulAuthentication,
                onUnsuccessfulAuthentication = onUnsuccessfulAuthentication,
            )
        postProcess(filter)
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)
    }

    fun authenticationEntryPoint(entryPoint: AuthenticationEntryPoint): AuthorizationServerConfigurer<H> =
        apply { authenticationEntryPoint = entryPoint }

    fun authenticationConverter(converter: AuthenticationConverter): AuthorizationServerConfigurer<H> =
        apply { authenticationConverter = converter }

    fun requestMatcher(matcher: RequestMatcher): AuthorizationServerConfigurer<H> = apply { requestMatcher = matcher }

    fun timeToLive(value: Long): AuthorizationServerConfigurer<H> = apply { this.timeToLive = value }

    fun tokenName(value: String): AuthorizationServerConfigurer<H> = apply { tokenName = value }

    fun processSuccess(block: (Authentication) -> Unit): AuthorizationServerConfigurer<H> = apply { onSuccessfulAuthentication = block }

    fun processFailure(block: (Authentication?) -> Unit): AuthorizationServerConfigurer<H> = apply { onUnsuccessfulAuthentication = block }

    private fun <T> BeanFactory.getBeanOrNull(requiredType: Class<T>): T? =
        try {
            getBean(requiredType)
        } catch (exception: NoSuchBeanDefinitionException) {
            null
        }

    private val authenticationProvider: AuthenticationProvider
        get() =
            BearerAuthenticationProvider(
                timeToLive = timeToLive,
                algorithm = algorithm,
                passwordEncoder = passwordEncoder,
                jwtEncoder = jwtEncoder,
                userDetailsService = userDetailsService,
                userDetailsPasswordService = userDetailsPasswordService,
                jwtHeaderConverter = jwtHeaderConverter,
                jwtClaimsSetConverter = jwtClaimsSetConverter,
            ).let { postProcess(it) }

    private fun getAuthenticationManager(http: H): AuthenticationManager = http.getSharedObject(AuthenticationManager::class.java)

    companion object {
        fun HttpSecurity.authorizationServer(customizer: Customizer<AuthorizationServerConfigurer<HttpSecurity>>): HttpSecurity {
            val context = getSharedObject(ApplicationContext::class.java)
            with(AuthorizationServerConfigurer<HttpSecurity>(context)) { customizer.customize(it) }
            return this
        }
    }
}
