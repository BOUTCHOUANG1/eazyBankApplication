package com.nathan.springsecurity.controller;

import com.nathan.springsecurity.model.Cards;
import com.nathan.springsecurity.model.Customer;
import com.nathan.springsecurity.repository.CardsRepository;
import com.nathan.springsecurity.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class CardsController {

    private final CardsRepository cardsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myCards")
    public List<Cards> getCardsDetails(@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);
        if (optionalCustomer.isPresent()) {
            List<Cards> cards = cardsRepository.findByCustomerId(optionalCustomer.get().getId());
            if (cards != null ) {
                return cards;
            }else {
                return null;
            }
        } else {
            return null;
        }

    }
}
