package secure.payment.card.server.exception;

public class SecurePaymentCardServerException extends SecurePaymentCardException {

    public SecurePaymentCardServerException(ErrorCodeEnum code, String message, String description) {
        super(code, message, description);
    }

    public SecurePaymentCardServerException(ErrorCodeEnum code, String message, Throwable cause) {
        super(code, message, cause);
    }
}
