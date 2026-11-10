using System.Net;
using System.Net.Sockets;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Net.Smtp;
using MailKit.Security;

/*
 * The shapes MailKit consumers write. SecureSocketOptions appears 848 times in MailKit's own tree
 * alone, and in code that merely uses MailKit it is the only TLS statement there is.
 */
public class MailKitUsage
{
    /* Implicit TLS on the IMAPS port: TLS before anything is sent. */
    public void ImplicitTls(ImapClient client)
    {
        client.Connect("imap.example.org", 993, SecureSocketOptions.SslOnConnect);
    }

    /* STARTTLS on the submission port, required: MailKit fails rather than continue plaintext. */
    public void RequiredStartTls(SmtpClient client)
    {
        client.ConnectAsync("smtp.example.org", 587, SecureSocketOptions.StartTls);
    }

    /* The socket-taking overload: the options sit one position later and still have to be found. */
    public void OverSocket(ImapClient client, Socket socket)
    {
        client.Connect(socket, "imap.example.org", 993, SecureSocketOptions.SslOnConnect);
    }

    /* Keyword arguments, written out of order. */
    public void KeywordArguments(ImapClient client)
    {
        client.Connect(options: SecureSocketOptions.SslOnConnect, port: 993, host: "imap.example.org");
    }

    /* Counter-check: no encryption at all. There is no component for that, and TLS would be a lie. */
    public void NoEncryption(ImapClient client)
    {
        client.Connect("imap.example.org", 143, SecureSocketOptions.None);
    }

    /*
     * Counter-check: Auto and StartTlsWhenAvailable both continue in plaintext against a server
     * that offers nothing, so the call does not state that any cryptography happens.
     */
    public void Opportunistic(ImapClient client)
    {
        client.Connect("imap.example.org", 143, SecureSocketOptions.Auto);
        client.Connect("imap.example.org", 143, SecureSocketOptions.StartTlsWhenAvailable);
    }

    /* Counter-check: the decision arrives as a parameter, so none may be invented. */
    public void FromParameter(ImapClient client, SecureSocketOptions configured)
    {
        client.Connect("imap.example.org", 993, configured);
    }

    /* Counter-check: an ordinary socket connect. Connect is matched on any receiver. */
    public void UnrelatedConnect(Socket socket, EndPoint endPoint)
    {
        socket.Connect(endPoint);
    }

    /*
     * Counter-check: a bool third argument. MailKit's own obsolete overload writes useSsl there,
     * but so does any other Connect in the world, so it is deliberately not read.
     */
    public void UnrelatedBoolean(ImapClient client)
    {
        client.Connect("imap.example.org", 993, true);
    }
}
