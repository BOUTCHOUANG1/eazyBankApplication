package com.nathan.springsecurity.exceptionHandling;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {
    /**
     * @param request       that resulted in an <code>AuthenticationException</code>
     * @param response      so that the user agent can begin authentication
     * @param authException that caused the invocation
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        // Populate dynamic values
        // Extract the path from the HttpServletRequest
        // This is the value of the HTTP request URL
        // For example, if the user requests http://localhost:8080/myBalance
        // the value of the path variable will be "/myBalance"
        String path = request.getRequestURI();

        // Extract the time when the error occurred
        // This is the value of the current time
        // For example, if the user requests http://localhost:8080/myBalance and the request
        // is invalid, the value of the currentTime variable will be the current time
        // when the request was made
        LocalDateTime currentTimeStamp = LocalDateTime.now();

        // Extract the error message from the AuthenticationException
        // If the exception is null or the message is null, the message will be "Unauthorized"
        // This value will be used to construct the JSON response
        // The structure is as follows:
        // {
        //     "timestamp": "2023-02-27T13:24:04.234",
        //     "status": 401,
        //     "error": "Unauthorized",
        //     "message": "Authentication Failed",
        //     "path": "/myBalance"
        // }
        String message = (authException != null && authException.getMessage() != null) ? authException.getMessage() : "Unauthorized";
        // Construct the JSON response
        // Populate the HTTP response with the error code, status, error message and timestamp
        // This is the JSON that will be sent to the client
        // The structure is as follows:
        // {
        //     "timestamp": "2023-02-27T13:24:04.234",
        //     "status": 401,
        //     "error": "Unauthorized",
        //     "message": "Authentication Failed",
        //     "path": "/myBalance"
        // }
        response.setHeader("eazybank-error-reason", "Authentication Failed");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");

        String jsonResponse =
                String.format("{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                        currentTimeStamp, HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                        message, path);

        response.getWriter().write(jsonResponse);
    }
}
