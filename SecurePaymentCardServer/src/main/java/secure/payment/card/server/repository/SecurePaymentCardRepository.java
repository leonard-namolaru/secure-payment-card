package secure.payment.card.server.repository;

import org.springframework.stereotype.Repository;
import secure.payment.card.server.entity.SecurePaymentCard;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface SecurePaymentCardRepository extends JpaRepository<SecurePaymentCard, String> {

}
