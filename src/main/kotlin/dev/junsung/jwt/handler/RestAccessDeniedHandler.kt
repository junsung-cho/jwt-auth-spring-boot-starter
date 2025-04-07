package dev.junsung.jwt.handler

import com.fasterxml.jackson.databind.ObjectMapper
import dev.junsung.exception.RestException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler

class RestAccessDeniedHandler : AccessDeniedHandler {
    private val objectMapper = ObjectMapper()

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AccessDeniedException,
    ) {
        RestException
            .forbidden(message = exception.localizedMessage)
            .toResponse(request)
            .also {
                response.contentType = "application/json"
                response.status = it.status
                response.writer.println(objectMapper.writeValueAsString(it))
            }
    }
}
