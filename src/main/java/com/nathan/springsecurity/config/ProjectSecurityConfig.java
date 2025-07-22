package com.nathan.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                .requestMatchers("/notices", "/contact", "/error").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

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
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}

