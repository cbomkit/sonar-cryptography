using Npgsql;
using MySqlConnector;

/*
 * How .NET database drivers state transport security. Npgsql's own tree writes
 * "SslMode = SslMode.Require" twelve times; code that merely uses the driver writes nothing else.
 */
public class NpgsqlUsage
{
    /* TLS required, certificate not validated. */
    public void Required(NpgsqlConnectionStringBuilder builder)
    {
        builder.SslMode = SslMode.Require;
    }

    /* An object initializer, which becomes the same property setter. */
    public NpgsqlConnectionStringBuilder VerifiedFully()
    {
        return new NpgsqlConnectionStringBuilder { SslMode = SslMode.VerifyFull };
    }

    /* Required plus chain validation. The validation itself has nowhere to go in the CBOM. */
    public void VerifiedCa(NpgsqlConnectionStringBuilder builder)
    {
        builder.SslMode = SslMode.VerifyCA;
    }

    /* MySqlConnector spells the same decision "Required". */
    public void MySqlRequired(MySqlConnectionStringBuilder builder)
    {
        builder.SslMode = SslMode.Required;
    }

    /*
     * Counter-check: Prefer, Allow and Preferred all fall back to an unencrypted connection when
     * the server declines, so none of them states that cryptography happens.
     */
    public void Opportunistic(NpgsqlConnectionStringBuilder builder)
    {
        builder.SslMode = SslMode.Prefer;
        builder.SslMode = SslMode.Allow;
    }

    /* Counter-check: TLS switched off. */
    public void Disabled(NpgsqlConnectionStringBuilder builder)
    {
        builder.SslMode = SslMode.Disable;
    }

    /* Counter-check: the mode arrives as a parameter, so none may be invented. */
    public void FromParameter(NpgsqlConnectionStringBuilder builder, SslMode configured)
    {
        builder.SslMode = configured;
    }

    /*
     * Counter-check: an unrelated class with a property of the same name holding a string. The
     * declared type is what refuses it -- a string can never be an SslMode.
     */
    public void UnrelatedProperty(SomeConfig config)
    {
        config.SslMode = "Require";
    }

    /*
     * Counter-check: the same setting inside a connection string. A connection string is an opaque
     * literal, and picking settings out of one by substring would report any string that mentions
     * them.
     */
    public NpgsqlConnection FromConnectionString()
    {
        return new NpgsqlConnection("Host=db.example.org;Username=app;SslMode=Require");
    }
}
