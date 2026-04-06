package secure.payment.card.server.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import secure.payment.card.server.model.ErrorResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.security.authentication.BadCredentialsException;

@ControllerAdvice
public class GlobalExceptionHandler {
    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ErrorResponse> handleSignatureExceptions(SignatureException exception) {
        ErrorResponse error = new ErrorResponse(ErrorCodeEnum.JWT_INVALID.getCodeId(), "Accès non autorisé",
                "Jeton d'accès invalide");
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredJwtExceptions(ExpiredJwtException exception) {
        ErrorResponse error = new ErrorResponse(ErrorCodeEnum.JWT_EXPIRED.getCodeId(), "Accès non autorisé",
                "Jeton d'accès expiré");
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedExceptions(AccessDeniedException exception) {
        ErrorResponse error = new ErrorResponse(ErrorCodeEnum.ACCESS_DENIED.getCodeId(), "Accès non autorisé",
                "Vous n'êtes pas autorisé à accéder à cette ressource");
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsExceptions(BadCredentialsException exception) {
        ErrorResponse error = new ErrorResponse(ErrorCodeEnum.BAD_CREDENTIALS.getCodeId(), "Échec d'authentification",
                "Le nom d'utilisateur ou le mot de passe est incorrect");
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ElementNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleElementNotFoundExceptions(ElementNotFoundException exception) {
        ErrorResponse error = new ErrorResponse(exception.getCode(), exception.getMessage(),
                exception.getDescription());
        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(SecurePaymentCardClientException.class)
    public ResponseEntity<ErrorResponse> handleClientExceptions(SecurePaymentCardClientException exception) {
        ErrorResponse error = new ErrorResponse(exception.getCode(), exception.getMessage(),
                exception.getDescription());
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(SecurePaymentCardServerException.class)
    public ResponseEntity<ErrorResponse> handleServerExceptions(SecurePaymentCardServerException exception) {
        ErrorResponse error = new ErrorResponse(exception.getCode(), exception.getMessage(),
                exception.getDescription());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneralExceptions(Exception exception) {
        logger.error("Erreur inattendue : {}", exception.getMessage());
        // exception.printStackTrace();
        ErrorResponse error = new ErrorResponse("Erreur", "Internal Server Error", "");
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
