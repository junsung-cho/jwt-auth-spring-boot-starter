package dev.junsung.jwt.converter

import org.springframework.security.oauth2.jwt.JwsHeader

abstract class JwtHeaderConverter {
    abstract fun convert(builder: JwsHeader.Builder): JwsHeader
}
