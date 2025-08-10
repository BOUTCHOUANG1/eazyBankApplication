package com.nathan.springsecurity.config;

import com.nathan.springsecurity.model.Customer;
import com.nathan.springsecurity.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EazyBankUserDetailService implements UserDetailsService {

    private final CustomerRepository customerRepository;
    /**
     * @param username the username identifying the user whose data is required.
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      Customer customer = customerRepository.findByEmail(username)
              .orElseThrow(() -> new UsernameNotFoundException("username not found for " + username));

        var authorities = customer.getAuthorities().stream().map(authority ->
              new SimpleGrantedAuthority(authority.getName()))
              .collect(Collectors.toList());
      return new User(customer.getEmail(), customer.getPwd(), authorities);
    }
}
