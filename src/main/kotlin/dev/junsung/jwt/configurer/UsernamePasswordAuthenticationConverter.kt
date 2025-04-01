package dev.junsung.jwt.configurer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationConverter

class UsernamePasswordAuthenticationConverter(
    private val usernameParameter: String,
    private val passwordParameter: String,
) : AuthenticationConverter {
    private val objectMapper = ObjectMapper()

    override fun convert(request: HttpServletRequest): Authentication {
        val username: String?
        val password: String?

        if (request.contentType == "application/json") {
            val parseObject =
                try {
                    objectMapper.readValue<Map<String, String>>(request.reader)
                } catch (ex: Exception) {
                    mapOf(usernameParameter to "", passwordParameter to "")
                }

            username = parseObject[usernameParameter]
            password = parseObject[passwordParameter]
        } else {
            username = request.getParameter(usernameParameter)
            password = request.getParameter(passwordParameter)
        }

        return UsernamePasswordAuthenticationToken
            .unauthenticated(username?.trim() ?: "", password ?: "")
            .apply { details = request }
    }
}
