package dev.junsung.jwt.handler

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import dev.junsung.exception.RestException

class RestAuthenticationEntryPoint : AuthenticationEntryPoint {
    private val objectMapper = ObjectMapper()

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        RestException
            .unauthorized(message = exception.localizedMessage, error = exception.javaClass.simpleName)
            .toResponse(request)
            .also {
                response.contentType = "application/json"
                response.status = it.status
                response.writer.println(objectMapper.writeValueAsString(it))
            }
    }
}
