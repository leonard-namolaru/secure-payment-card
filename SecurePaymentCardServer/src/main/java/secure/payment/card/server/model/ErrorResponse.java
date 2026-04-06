package secure.payment.card.server.model;

import lombok.Getter;
import lombok.AllArgsConstructor;

@Getter
@AllArgsConstructor
public class ErrorResponse {
    private String code;
    private String message;
    private String description;
}
