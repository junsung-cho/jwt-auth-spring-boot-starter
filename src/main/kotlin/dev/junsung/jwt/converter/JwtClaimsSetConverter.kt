package dev.junsung.jwt.converter

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtClaimsSet

abstract class JwtClaimsSetConverter {
    abstract fun convert(
        builder: JwtClaimsSet.Builder,
        authentication: Authentication,
    ): JwtClaimsSet
}
