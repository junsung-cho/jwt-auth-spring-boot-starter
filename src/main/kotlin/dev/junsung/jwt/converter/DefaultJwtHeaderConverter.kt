package dev.junsung.jwt.converter

import org.springframework.security.oauth2.jwt.JwsHeader

class DefaultJwtHeaderConverter : JwtHeaderConverter() {
    override fun convert(builder: JwsHeader.Builder): JwsHeader = builder.build()
}
