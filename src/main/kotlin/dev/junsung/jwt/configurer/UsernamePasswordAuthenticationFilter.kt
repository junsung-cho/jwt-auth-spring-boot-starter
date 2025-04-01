package dev.junsung.jwt.configurer

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.filter.GenericFilterBean

class UsernamePasswordAuthenticationFilter(
    private val tokenName: String,
    private val requestMatcher: RequestMatcher,
    private val authenticationManager: AuthenticationManager,
    private val authenticationEntryPoint: AuthenticationEntryPoint,
    private val authenticationConverter: AuthenticationConverter,
    private val onSuccessfulAuthentication: (Authentication) -> Unit,
    private val onUnsuccessfulAuthentication: (Authentication?) -> Unit,
) : GenericFilterBean() {
    override fun doFilter(
        request: ServletRequest,
        response: ServletResponse,
        chain: FilterChain,
    ) {
        doFilter((request as HttpServletRequest), (response as HttpServletResponse), chain)
    }

    private fun doFilter(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
    ) {
        if (!requestMatcher.matches(request)) {
            chain.doFilter(request, response)
            return
        }

        val authRequest = authenticationConverter.convert(request)

        try {
            val authenticationResult = attemptAuthentication(authRequest)
            successfulAuthentication(request, response, chain, authenticationResult)
        } catch (exception: AuthenticationException) {
            unsuccessfulAuthentication(authRequest, request, response, exception)
        }
    }

    private fun attemptAuthentication(authRequest: Authentication): Authentication = authenticationManager.authenticate(authRequest)

    private fun successfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
        authResult: Authentication,
    ) {
        if (authResult is BearerAuthenticationToken) {
            onSuccessfulAuthentication(authResult)
            response.contentType = "application/json"
            response.writer.println("{\"$tokenName\":\"${authResult.credentials}\"}")
        } else {
            chain.doFilter(request, response)
        }
    }

    private fun unsuccessfulAuthentication(
        authRequest: Authentication?,
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        exception: AuthenticationException?,
    ) {
        onUnsuccessfulAuthentication(authRequest)
        SecurityContextHolder.clearContext()
        authenticationEntryPoint.commence(request, response, exception)
    }
}
