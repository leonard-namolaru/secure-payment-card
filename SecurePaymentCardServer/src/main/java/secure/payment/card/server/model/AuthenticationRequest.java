package secure.payment.card.server.model;

public record AuthenticationRequest(String email, String password) { }