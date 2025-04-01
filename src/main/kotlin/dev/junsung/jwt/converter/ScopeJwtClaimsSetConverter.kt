package dev.junsung.jwt.converter

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.jwt.JwtClaimsSet

class ScopeJwtClaimsSetConverter : JwtClaimsSetConverter() {
    companion object {
        private const val DEFAULT_AUTHORITY_PREFIX = "SCOPE_"
        private const val DEFAULT_AUTHORITY_NAME = "scope"
    }

    override fun convert(
        builder: JwtClaimsSet.Builder,
        authentication: Authentication,
    ): JwtClaimsSet =
        builder
            .subject(authentication.name)
            .claims { it.putAll(convertAuthentication(authentication)) }
            .build()

    private fun convertAuthentication(authentication: Authentication): Map<String, Any> =
        mapOf(DEFAULT_AUTHORITY_NAME to authentication.authorities.map { it.toScope() })

    private fun GrantedAuthority.toScope(): String = authority.removePrefix(DEFAULT_AUTHORITY_PREFIX)
}
