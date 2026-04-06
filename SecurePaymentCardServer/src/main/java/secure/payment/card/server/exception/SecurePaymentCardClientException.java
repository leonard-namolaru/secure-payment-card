package secure.payment.card.server.exception;

public class SecurePaymentCardClientException extends SecurePaymentCardException {

    public SecurePaymentCardClientException(ErrorCodeEnum code, String message, String description) {
        super(code, message, description);
    }

    public SecurePaymentCardClientException(ErrorCodeEnum code, String message, Throwable cause) {
        super(code, message, cause);
    }
}
