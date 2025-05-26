package dev.junsung.jwt.configurer

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.HttpSecurityDsl
import org.springframework.security.config.annotation.web.SecurityMarker
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.util.matcher.RequestMatcher
import kotlin.also
import kotlin.apply
import kotlin.time.Duration

@SecurityMarker
class AuthorizationServerDsl {
    var authenticationEntryPoint: AuthenticationEntryPoint? = null
    var authenticationConverter: AuthenticationConverter? = null
    var requestMatcher: RequestMatcher? = null
    var timeToLive: Duration? = null
    var tokenName: String? = null
    var processSuccess: ((Authentication, HttpServletRequest) -> Unit)? = null
    var processFailure: ((Authentication, HttpServletRequest) -> Unit)? = null

    internal fun get(): (AuthorizationServerConfigurer<HttpSecurity>) -> Unit =
        { authorizationServer ->
            authenticationEntryPoint?.also { authorizationServer.authenticationEntryPoint(it) }
            authenticationConverter?.also { authorizationServer.authenticationConverter(it) }
            requestMatcher?.also { authorizationServer.requestMatcher(it) }
            timeToLive?.also { authorizationServer.timeToLive(it) }
            tokenName?.also { authorizationServer.tokenName(it) }
            processSuccess?.also { authorizationServer.processSuccess(it) }
            processFailure?.also { authorizationServer.processFailure(it) }
        }

    companion object {
        fun HttpSecurityDsl.authorizationServer(authorizationServerConfiguration: AuthorizationServerDsl.() -> Unit) {
            val authorizationServerCustomizer = AuthorizationServerDsl().apply(authorizationServerConfiguration).get()
            apply(AuthorizationServerConfigurer<HttpSecurity>(context), authorizationServerCustomizer)
        }
    }
}
