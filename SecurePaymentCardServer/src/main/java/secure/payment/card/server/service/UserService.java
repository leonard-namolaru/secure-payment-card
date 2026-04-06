package secure.payment.card.server.service;

import java.util.Optional;

import secure.payment.card.server.entity.User;
import secure.payment.card.server.entity.Role;
import secure.payment.card.server.entity.RoleEnum;
import secure.payment.card.server.model.RegistrationRequest;
import secure.payment.card.server.repository.UserRepository;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
public class UserService {

    @Autowired
    private Environment environment;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    void initAdmin(){
        RegistrationRequest registrationRequest = new RegistrationRequest(
                environment.getProperty("super.admin.email"),
                environment.getProperty("super.admin.password"),
                environment.getProperty("super.admin.full-name")
        );

        Optional<Role> securePaymentCardAdminRole = roleService.findByName(RoleEnum.SECURE_PAYMENT_CARD_ADMIN);
        Optional<User> existingUser = userRepository.findByEmail(registrationRequest.email());
        if (securePaymentCardAdminRole.isEmpty() || existingUser.isPresent()) {
            return;
        }

        var user = new User();
        user.setFullName(registrationRequest.fullName());
        user.setEmail(registrationRequest.email());
        user.setPassword(passwordEncoder.encode(registrationRequest.password()));
        user.setRole(securePaymentCardAdminRole.get());
        userRepository.save(user);
    }

    public User createSecurePayementCardAgent(RegistrationRequest registrationRequest) {
        Optional<Role> securePaymentCardAgentRole = roleService.findByName(RoleEnum.SECURE_PAYMENT_CARD_AGENT);
        if (securePaymentCardAgentRole.isEmpty()) {
            return null;
        }

        var user = new User();
        user.setFullName(registrationRequest.fullName());
        user.setEmail(registrationRequest.email());
        user.setPassword(passwordEncoder.encode(registrationRequest.password()));
        user.setRole(securePaymentCardAgentRole.get());
        return userRepository.save(user);
    }
}