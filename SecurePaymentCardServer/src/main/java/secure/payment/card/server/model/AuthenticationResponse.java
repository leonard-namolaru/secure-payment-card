package secure.payment.card.server.model;

import lombok.Getter;
import lombok.AllArgsConstructor;

@Getter
@AllArgsConstructor
public class AuthenticationResponse {
    private String token;
    private long expiresIn;
}