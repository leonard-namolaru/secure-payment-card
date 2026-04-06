package secure.payment.card.server.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;

import secure.payment.card.server.model.OperationResult;
import secure.payment.card.server.entity.SecurePaymentCard;
import secure.payment.card.server.model.SecurePaymentCardRecord;
import secure.payment.card.server.service.SecurePaymentCardService;
import secure.payment.card.server.model.SecurePaymentCardCreationResponse;

@RestController
@RequestMapping("/api/v1/")
public class SecurePaymentCardController {

    @Autowired
    SecurePaymentCardService securePaymentCardService;

    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/{uuid}")
    @PreAuthorize("hasAnyRole('SECURE_PAYMENT_CARD_AGENT','SECURE_PAYMENT_CARD_ADMIN')")
    public SecurePaymentCard getSecurePaymentCardById(@PathVariable String uuid) {
        return securePaymentCardService.getSecurePaymentCardByID(uuid);
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("")
    @PreAuthorize("hasAnyRole('SECURE_PAYMENT_CARD_AGENT','SECURE_PAYMENT_CARD_ADMIN')")
    public SecurePaymentCardCreationResponse registerNewSecurePaymentCard(@RequestBody SecurePaymentCardRecord securePaymentCardRecord) {
        String securePaymentCardID = SecurePaymentCard.generateID();

        SecurePaymentCard securePaymentCard = new SecurePaymentCard();
        securePaymentCard.setSecurePaymentCardID(securePaymentCardID);
        securePaymentCard.setPublicKey(securePaymentCardRecord.publicKey());
        securePaymentCard.setBalanceSignature(securePaymentCardRecord.balanceSignature());

        securePaymentCardService.createOrUpdateSecurePaymentCard(securePaymentCard);
        return new SecurePaymentCardCreationResponse(securePaymentCard.getSecurePaymentCardID());
    }

    @ResponseStatus(HttpStatus.OK)
    @PutMapping("/{uuid}")
    @PreAuthorize("hasAnyRole('SECURE_PAYMENT_CARD_AGENT','SECURE_PAYMENT_CARD_ADMIN')")
    public OperationResult updateSecurePaymentCard(@PathVariable String uuid, @RequestBody SecurePaymentCardRecord securePaymentCardRecord) {
        SecurePaymentCard securePaymentCard = securePaymentCardService.getSecurePaymentCardByID(uuid);
        securePaymentCard.setBalanceSignature(securePaymentCardRecord.balanceSignature());
        securePaymentCard.setPublicKey(securePaymentCardRecord.publicKey());

        securePaymentCardService.createOrUpdateSecurePaymentCard(securePaymentCard);
        return new OperationResult("La mise à jour a réussi.");
    }
}