using System.Security.Cryptography;

/*
 * A key size written in hex or binary is the same number as in decimal. The C# lexer has three
 * integer tokens -- INTEGER_LITERAL, HEX_INTEGER_LITERAL, BIN_INTEGER_LITERAL -- and the converter
 * used to classify only the first as an integer, so 0x100 fell through to the string branch and
 * the key length was silently lost. These are the shapes that pins it.
 */
public class DotNetHexLiteralUsage
{
    /* Decimal, the control case. */
    public void DecimalKeySize()
    {
        var aes = Aes.Create();
        aes.KeySize = 256;
    }

    /* The same size in hex -- 0x100 is 256. */
    public void HexKeySize()
    {
        var aes = Aes.Create();
        aes.KeySize = 0x100;
    }

    /* Upper-case prefix and digits. */
    public void HexUpperCase()
    {
        var aes = Aes.Create();
        aes.KeySize = 0XC0;
    }

    /* Binary, and with the digit separator C# allows. */
    public void BinaryKeySize()
    {
        var aes = Aes.Create();
        aes.KeySize = 0b1000_0000;
    }

    /* Counter-check: a size from a parameter stays unknown, in any base. */
    public void FromParameter(int configured)
    {
        var aes = Aes.Create();
        aes.KeySize = configured;
    }
}
