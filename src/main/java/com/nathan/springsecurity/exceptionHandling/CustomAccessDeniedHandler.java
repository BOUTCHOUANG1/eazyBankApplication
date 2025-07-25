package com.nathan.springsecurity.exceptionHandling;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    /**
     * @param request               that resulted in an <code>AccessDeniedException</code>
     * @param response              so that the user agent can be advised of the failure
     * @param accessDeniedException that caused the invocation
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
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
        //     "status": 403,
        //     "error": "Authorized failed",
        //     "message": "Authentication Failed",
        //     "path": "/myBalance"
        // }
        String message = (accessDeniedException != null && accessDeniedException.getMessage() != null) ? accessDeniedException.getMessage() : "Authorized failed";
        // Construct the JSON response
        // Populate the HTTP response with the error code, status, error message and timestamp
        // This is the JSON that will be sent to the client
        // The structure is as follows:
        // {
        //     "timestamp": "2023-02-27T13:24:04.234",
        //     "status": 403,
        //     "error": "Forbidden",
        //     "message": "Authorization Failed",
        //     "path": "/myBalance"
        // }
        response.setHeader("eazybank-failed-reason", "Authorization Failed");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");

        String jsonResponse =
                String.format("{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                        currentTimeStamp, HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(),
                        message, path);

        response.getWriter().write(jsonResponse);

    }
}
