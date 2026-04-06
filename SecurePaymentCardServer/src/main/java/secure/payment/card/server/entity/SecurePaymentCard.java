package secure.payment.card.server.entity;

import lombok.Getter;
import lombok.Setter;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;

@Setter
@Getter
@Entity(name = "SecurePaymentCard")
@Table(name = "secure_payment_cards")
public class SecurePaymentCard {

    @Id // Clé primaire
    @Column(name = "secure_payment_card_id", unique = true, nullable = false)
    private String securePaymentCardID;

    @Column(name = "balance_signature", nullable = false)
    private String balanceSignature;

    @Column(name = "public_key", nullable = false)
    private String publicKey;

    @ManyToOne(cascade = CascadeType.REMOVE)
    @JoinColumn(name = "last_update_user_id", referencedColumnName = "id", nullable = false)
    private User lastUpdateUser;

    @CreationTimestamp
    @Column(updatable = false, name = "created_at")
    private Date createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Date updatedAt;

    private static final AtomicLong COUNTER = new AtomicLong(1);

    public static String generateID() {
        LocalDateTime localDateTime = LocalDateTime.now();
        String formattedDate = localDateTime.format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        long counter = COUNTER.getAndIncrement();
        return String.format("CARD-%s-%05d", formattedDate, counter);
    }
}
