package dev.junsung.jwt.configurer

import org.springframework.security.authentication.AbstractAuthenticationToken

class BearerAuthenticationToken(
    private val username: String,
    private val token: String,
) : AbstractAuthenticationToken(null) {
    override fun getCredentials(): Any = token

    override fun getPrincipal(): Any = username
}
