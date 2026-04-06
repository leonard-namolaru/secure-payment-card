package secure.payment.card.server.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;

import secure.payment.card.server.entity.User;
import secure.payment.card.server.model.AuthenticationRequest;
import secure.payment.card.server.service.JwtService;
import secure.payment.card.server.model.AuthenticationResponse;
import secure.payment.card.server.model.RegistrationRequest;
import secure.payment.card.server.service.AuthenticationService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationService authenticationService;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    public User register(@RequestBody RegistrationRequest registrationRequest) {
        return authenticationService.register(registrationRequest);
    }

    @ResponseStatus(HttpStatus.OK)
    @PostMapping("")
    public AuthenticationResponse authenticate(@RequestBody AuthenticationRequest authenticationRequest) {
        UserDetails authenticatedUser = authenticationService.authenticate(authenticationRequest);
        String jwtToken = jwtService.generateToken(authenticatedUser);
        return new AuthenticationResponse(jwtToken, jwtService.getExpirationTime());
    }
}