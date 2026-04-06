package secure.payment.card.server.exception;

public class ElementNotFoundException extends SecurePaymentCardClientException {
    public static final String MESSAGE = "Ressource introuvable";
    public static final String DESCRIPTION = "Le serveur n'a pas pu trouver la ressource demandée.";

    public ElementNotFoundException(ErrorCodeEnum code, String requestedElement) {
        super(code, String.format("%s : %s", MESSAGE, requestedElement), DESCRIPTION);
    }

    public ElementNotFoundException(ErrorCodeEnum code, String requestedElement, Throwable cause) {
        super(code, String.format("%s : %s", MESSAGE, requestedElement), cause);
    }
}
