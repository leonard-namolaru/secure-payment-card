package secure.payment.card.server.repository;

import java.util.Optional;

import secure.payment.card.server.entity.Role;
import secure.payment.card.server.entity.RoleEnum;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(RoleEnum name);
}