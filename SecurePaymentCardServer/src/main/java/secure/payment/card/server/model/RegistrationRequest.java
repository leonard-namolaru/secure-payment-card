package secure.payment.card.server.model;

public record RegistrationRequest(String email, String password, String fullName) { }