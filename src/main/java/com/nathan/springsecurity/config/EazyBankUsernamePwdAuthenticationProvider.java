//package com.nathan.springsecurity.config;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Profile;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//@Component
//@Profile("!prod")
//@RequiredArgsConstructor
//public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {
//
//    private final UserDetailsService userDetailService;
//    private final PasswordEncoder passwordEncoder;
//    /**
//     * @param authentication the authentication request object.
//     * @return
//     * @throws AuthenticationException
//     */
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String username = authentication.getName();
//        String pwd = authentication.getCredentials().toString();
//       UserDetails userDetails = userDetailService.loadUserByUsername(username);
//        return new UsernamePasswordAuthenticationToken(username, pwd, userDetails.getAuthorities());
//    }
//
//    /**
//     * @param authentication
//     * @return
//     */
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//    }
//}
