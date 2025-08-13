package com.nathan.springsecurity.config;

import com.nathan.springsecurity.exceptionHandling.CustomAccessDeniedHandler;
import com.nathan.springsecurity.exceptionHandling.CustomBasicAuthenticationEntryPoint;
import com.nathan.springsecurity.filter.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        /*
          This bean is used to handle the Csrf token request attribute.
          This attribute is used by the {@link csrfCookieFilter} to get the Csrf token from the request.
          The Csrf token is used to validate the request and prevent Cross-Site Request Forgery (CSRF) attacks.
          This is only needed for the development environment because in production the Csrf token is
          handled by the browser and the request is sent from the Angular application.
         */
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();

        /*
          This code block is used to configure the security context.
          The security context is used by Spring Security to store the current user's authentication information.
          By setting the requireExplicitSave to false, we are telling Spring Security to automatically save the security context
          when the user's authentication information changes. This is needed because in development environment, the Csrf token
          is handled by the browser and the request is sent from the Angular application, so we need to save the security context
          automatically when the user's authentication information changes.
         */
        /*http.securityContext(sc -> sc
                .requireExplicitSave(false));*

        /*
          This code block is used to configure the CSRF (Cross-Site Request Forgery) protection.
          CSRF is a type of attack where a malicious website tricks a user's browser into performing an unintended action on a trusted website.
          To prevent this type of attack, Spring Security provides a CSRF protection mechanism, which requires a CSRF token to be sent with each request.
          The CSRF token is a unique value that is generated for each request and is stored in the user's session.
          The CSRF token is sent with each request and is verified by the server to ensure that the request is valid.
          If the CSRF token is not sent or is invalid, the server will reject the request.
          This CSRF protection is only needed for the development environment because in production the CSRF token is handled by the browser and the request is sent from the Angular application.
          The lambda expression in this code block is used to configure the CSRF protection.
          The lambda expression takes a CsrfConfigurer object as a parameter and returns a void.
          The CsrfConfigurer object is used to configure the CSRF protection.
          The lambda expression is used to ignore the CSRF protection for the "/register" and "/contact" endpoints, which are used by the Angular application to register a new user and to send a contact email.
          The lambda expression is also used to set the CSRF token repository to a CookieCsrfTokenRepository with the HTTP only flag set to false.
          This means that the CSRF token will be stored in a cookie and will be sent with each request.
          The lambda expression is also used to add a filter to the filter chain to handle the CSRF token.
          The filter is added after the BasicAuthenticationFilter filter, which is used to handle the authentication of the user.
         */
        http.csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/register", "/contact", "/apiLogin")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new csrfCookieFilter(), BasicAuthenticationFilter.class)
                /*.addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)*/


                /*
                  This code block is used to configure the Cross-Origin Resource Sharing (CORS).
                  CORS is a security feature implemented in web browsers to prevent web pages from making requests to a different origin (domain, protocol, or port) than the one the web page was loaded from.
                  CORS is used to prevent malicious scripts from being injected into a web page and to protect sensitive data from being accessed by unauthorized scripts.
                  In this case, we need to configure CORS to allow the Angular application running on "http://localhost:4200" to make requests to the Spring Security application running on the same domain.
                  The lambda expression in this code block is used to provide a CorsConfigurationSource object, which is used by the CORS filter to determine the CORS configuration for a given request.
                  The lambda expression takes a HttpServletRequest object as a parameter and returns a CorsConfiguration object.
                  The CorsConfiguration object is used to specify the CORS configuration for the request.
                  In this case, we are allowing requests from "http://localhost:4200" to access the resources on the same domain.
                  We are also allowing all methods and headers, and we are setting the maximum age of the CORS configuration to 1 hour.
                  This means that the browser will cache the CORS configuration for 1 hour and will not send a new request to the server to get the CORS configuration during that time.
                 */
                .cors(corsConfig -> corsConfig.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(Arrays.asList("Authorization"));
                    config.setAllowCredentials(true);
                    config.setMaxAge(3600L);
                    return config;
                }))

                /*
                  This code block is used to configure the session management.
                  Session management is a feature of Spring Security that allows to control the user's session.
                  The session is used to store the user's authentication information and other data.
                  By configuring the session management, we can control how the session is created, how it is fixed, and how it is invalidated.
                  We can also control the maximum number of sessions that a user can have and what happens when the user's session is expired or invalid.
                  In this case, we are configuring the session management to create a new session for each request, and to invalidate the session when it is expired or invalid.
                  We are also setting the maximum number of sessions that a user can have to 3, and we are preventing the user from logging in when the maximum number of sessions is reached.
                  This is needed to prevent a user from having multiple sessions open at the same time, and to prevent a user from keeping a session open for an extended period of time.
                  The lambda expression in this code block is used to configure the session management.
                  The lambda expression takes a SessionManagementConfigurer object as a parameter and returns a void.
                  The SessionManagementConfigurer object is used to configure the session management.
                  The lambda expression is used to set the session creation policy to ALWAYS, which means that a new session will be created for each request.
                  The lambda expression is also used to set the session fixation to newSession(), which means that a new session will be created when the user's session is fixed.
                  The lambda expression is also used to set the invalid session URL to "/invalidSession", which means that the user will be redirected to this URL when the session is invalid.
                  The lambda expression is also used to set the maximum number of sessions that a user can have to 3, and to prevent the user from logging in when the maximum number of sessions is reached.
                  The lambda expression is also used to set the expired URL to "/expiredSession", which means that the user will be redirected to this URL when the session is expired.
                 */
                .sessionManagement(smc -> smc
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::newSession)
                        .invalidSessionUrl("/invalidSession")
                        .maximumSessions(3).maxSessionsPreventsLogin(true)
                        .expiredUrl("/expiredSession"))


                /*
                  This code block is used to configure the channel security.
                  The channel security is a feature of Spring Security that allows to control the protocol used to access the application.
                  The protocol can be either HTTP or HTTPS.
                  By configuring the channel security, we can control which protocol is used to access the application.
                  In this case, we are configuring the channel security to require an insecure protocol (HTTP) for all requests.
                  This means that the application will be accessible over HTTP.
                  The lambda expression in this code block is used to specify the requests that require an insecure protocol.
                  The lambda expression takes a ChannelRequestMatcherRegistry object as a parameter and returns a void.
                  The ChannelRequestMatcherRegistry object is used to configure the channel security.
                  The lambda expression is used to specify the requests that require an insecure protocol.
                  The anyRequest() method is used to specify that all requests require an insecure protocol.
                  The requiresInsecure() method is used to specify that the requests require an insecure protocol.
                  The authorizeHttpRequests() method is used to authorize the requests.
                  The lambda expression in this method is used to specify the authorization rules for the requests.
                  The requestMatchers() method is used to specify the requests that are authorized.
                  The authenticated() method is used to specify that the requests require authentication.
                  The permitAll() method is used to specify that the requests do not require authentication.
                 */
                .requiresChannel(rrc -> rrc.anyRequest().requiresInsecure())

                .authorizeHttpRequests((requests) -> requests

                /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/myLoans").authenticated()
                        .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/user").authenticated()
                .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession", "/apiLogin").permitAll());

        /*
          This code block is used to configure the form login.
          The form login is a feature of Spring Security that allows to authenticate users using a form.
          The form login is configured using the formLogin() method.
          The lambda expression in this method is used to specify the configuration for the form login.
          The lambda expression takes a FormLoginConfigurer object as a parameter and returns a void.
          The FormLoginConfigurer object is used to configure the form login.
          The lambda expression is used to specify the configuration for the form login.
          The withDefaults() method is used to specify the default configuration for the form login.
          The default configuration includes the username parameter, password parameter and login processing URL.
          The default configuration also includes the default success URL and the default failure URL.
          The default success URL is the URL that the user will be redirected to after a successful login.
          The default failure URL is the URL that the user will be redirected to after a failed login.
          The default failure URL can be overridden using the failureUrl() method.
          The default success URL can be overridden using the defaultSuccessUrl() method.
          The default failure URL can be overridden using the failureUrl() method.
          The default success URL can be overridden using the defaultSuccessUrl() method.
         */
        http.formLogin(withDefaults());

        /*
          This code block is used to configure the HTTP Basic authentication.
          The HTTP Basic authentication is a feature of Spring Security that allows to authenticate users using the HTTP Basic protocol.
          The HTTP Basic protocol is a simple authentication protocol that is used to authenticate users using a username and password.
          The HTTP Basic protocol is configured using the httpBasic() method.
          The lambda expression in this method is used to specify the configuration for the HTTP Basic protocol.
          The lambda expression takes a HttpBasicConfigurer object as a parameter and returns a void.
          The HttpBasicConfigurer object is used to configure the HTTP Basic protocol.
          The lambda expression is used to specify the configuration for the HTTP Basic protocol.
          The authenticationEntryPoint() method is used to specify the entry point that will be used to handle the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The AuthenticationEntryPoint interface is used to handle the authentication process.
          The entry point is responsible for handling the authentication process and for returning the appropriate HTTP response.
          The entry point is also responsible for handling any exceptions that may occur during the authentication process.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
          The entry point is an object that implements the AuthenticationEntryPoint interface.
          The entry point is used to handle the authentication process and to return the appropriate HTTP response.
          The entry point is also used to handle any exceptions that may occur during the authentication process.
         */

        http.httpBasic(hpc -> hpc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));

        // http.exceptionHandling(ehc -> ehc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        /*
          This code block is used to configure the exception handling for the Spring Security.
          The exception handling is a feature of Spring Security that allows to handle exceptions that may occur during the authentication process.
          The exception handling is configured using the exceptionHandling() method.
          The lambda expression in this method is used to specify the configuration for the exception handling.
          The lambda expression takes an ExceptionHandlingConfigurer object as a parameter and returns a void.
          The ExceptionHandlingConfigurer object is used to configure the exception handling.
          The lambda expression is used to specify the configuration for the exception handling.
          The accessDeniedHandler() method is used to specify the access denied handler that will be used to handle the access denied exceptions.
          The access denied handler is an object that implements the AccessDeniedHandler interface.
          The AccessDeniedHandler interface is used to handle the access denied exceptions.
          The access denied handler is responsible for handling the access denied exceptions and for returning the appropriate HTTP response.
          The access denied handler is also responsible for handling any exceptions that may occur during the handling of the access denied exceptions.
          The accessDeniedPage() method is used to specify the URL that the user will be redirected to when an access denied exception occurs.
          The URL is used to redirect the user to a page that will inform them that they do not have the required permissions to access the requested resource.
         */
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler())
              .accessDeniedPage("/denied")
        );

        return http.build();
    }
    /**
     * In-memory user details service that provides two users: user and admin.
     *
     * <p>This is a very simple implementation that is not suitable for production. It is only used for testing and development.
     *
     * <p>user has the role "read" and the password is "12345"
     *
     * <p>admin has the role "admin" and the password is "54321"
     *
     * the "{noop}" prefix means that the password is not hashed, it is the plain text password
     *
     * @return the user details service
     */

    //The Bean below will create a confusion since we already defined our custom UserDetailService
    /*@Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }*/

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    /**
     * Compromised password checker based on the HaveIBeenPwned breach data set.
     *
     * This bean is used to check if a password has been involved in a known breach.
     *
     * The implementation is based on the HaveIBeenPwned API, which is a free service that aggregates data from various sources.
     *
     * The API is called for each password that is being checked, and the response is cached for a short period of time (30 minutes).
     *
     * The password is sent to the API as a SHA-1 hash, and the response is a list of hashes that have been involved in a breach.
     *
     * The list of hashes is then checked against the hash of the password that is being checked.
     *
     * If the password has been involved in a breach, the checker will throw a PasswordInBreachException {@link "https://api.pwnedpasswords.com/range/"}.
     *
     * @return the compromised password checker
     */
//    @Bean
//    public CompromisedPasswordChecker compromisedPasswordChecker() {
//        return new HaveIBeenPwnedRestApiPasswordChecker();
//    }

//    @Bean
//    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
//                                                       PasswordEncoder passwordEncoder) {
//        EazyBankUsernamePwdAuthenticationProvider authenticationProvider =
//                new EazyBankUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);
//        ProviderManager providerManager = new ProviderManager(authenticationProvider);
//        providerManager.setEraseCredentialsAfterAuthentication(false);
//        return  providerManager;
//    }
}

