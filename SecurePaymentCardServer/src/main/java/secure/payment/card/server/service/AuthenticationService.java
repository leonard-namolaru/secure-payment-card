package secure.payment.card.server.service;

import java.util.Optional;

import secure.payment.card.server.entity.Role;
import secure.payment.card.server.entity.User;
import secure.payment.card.server.entity.RoleEnum;
import secure.payment.card.server.model.AuthenticationRequest;
import secure.payment.card.server.model.RegistrationRequest;
import secure.payment.card.server.repository.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Service
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    public User register(RegistrationRequest registrationRequest) {
        Optional<Role> unauthorizedUserRole = roleService.findByName(RoleEnum.UNAUTHORIZED_USER);
        if (unauthorizedUserRole.isEmpty()) {
            return null;
        }

        User user = new User();
        user.setEmail(registrationRequest.email());
        user.setFullName(registrationRequest.fullName());
        user.setPassword(passwordEncoder.encode(registrationRequest.password()));
        user.setRole(unauthorizedUserRole.get());
        return userRepository.save(user);
    }

    public UserDetails authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.email(), authenticationRequest.password()));
        return userRepository.findByEmail(authenticationRequest.email()).orElseThrow();
    }
}