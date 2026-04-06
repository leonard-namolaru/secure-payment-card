package secure.payment.card.server.service;

import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import secure.payment.card.server.entity.Role;
import secure.payment.card.server.entity.RoleEnum;
import secure.payment.card.server.repository.RoleRepository;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class RoleService {
    private final Logger logger = LoggerFactory.getLogger(RoleService.class);

    @Autowired
    private RoleRepository roleRepository;

    @PostConstruct
    void initRoles() {
        Map<RoleEnum, String> roleDescriptionMap = Map.of(
                RoleEnum.UNAUTHORIZED_USER, "Utilisateur sans aucun accès",
                RoleEnum.SECURE_PAYMENT_CARD_AGENT, "Un agent autorisé à effectuer des débits et des crédits",
                RoleEnum.SECURE_PAYMENT_CARD_ADMIN, "Administrateur"
        );

        roleDescriptionMap.forEach((roleName, description) ->
                roleRepository.findByName(roleName).ifPresentOrElse(
                        role -> logger.info("Ce rôle existe déjà : {}", role),
                        () -> {
                            Role roleToCreate = new Role();
                            roleToCreate.setName(roleName);
                            roleToCreate.setDescription(description);
                            roleRepository.save(roleToCreate);
                            logger.info("Création d'un nouveau rôle : {}", roleToCreate);
                        }
                )
        );
    }

    public Optional<Role> findByName(RoleEnum name) {
        return roleRepository.findByName(name);
    }
}