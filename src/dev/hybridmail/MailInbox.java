package dev.hybridmail;
import java.util.List;
import jakarta.mail.internet.MimeMessage;
/** Read-only inbox transport. */
public interface MailInbox extends AutoCloseable {
    List<ImapInbox.Entry> latest() throws Exception;
    MimeMessage message(long uid) throws Exception;
    void close() throws Exception;
}
