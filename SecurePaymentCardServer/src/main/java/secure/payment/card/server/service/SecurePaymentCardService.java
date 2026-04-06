package secure.payment.card.server.service;

import secure.payment.card.server.entity.User;
import secure.payment.card.server.exception.ErrorCodeEnum;
import secure.payment.card.server.entity.SecurePaymentCard;
import secure.payment.card.server.exception.ElementNotFoundException;
import secure.payment.card.server.repository.SecurePaymentCardRepository;

import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

@Service
public class SecurePaymentCardService {

    @Autowired
    SecurePaymentCardRepository securePaymentCardRepository;

    public void createOrUpdateSecurePaymentCard(SecurePaymentCard securePaymentCard) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        securePaymentCard.setLastUpdateUser((User) authentication.getPrincipal());
        securePaymentCardRepository.save(securePaymentCard);
    }

    public SecurePaymentCard getSecurePaymentCardByID(String securePaymentCardID) {
        return securePaymentCardRepository.findById(securePaymentCardID)
                .orElseThrow(() -> new ElementNotFoundException(
                        ErrorCodeEnum.CARD_NOT_FOUND, securePaymentCardID));
    }
}
