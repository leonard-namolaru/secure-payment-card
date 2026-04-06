package secure.payment.card.server.controller;

import secure.payment.card.server.entity.User;
import secure.payment.card.server.model.RegistrationRequest;
import secure.payment.card.server.service.UserService;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    @PreAuthorize("hasRole('SECURE_PAYMENT_CARD_ADMIN')")
    public User createSecurePaymentCardAgent(@RequestBody RegistrationRequest registrationRequest) {
        return userService.createSecurePayementCardAgent(registrationRequest);
    }
}