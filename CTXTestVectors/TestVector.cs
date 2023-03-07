namespace CTXTestVectors;


[Serializable]
public class TestVector
{
    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Key { get; set; }
    
    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Nonce { get; set; }

    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Ad { get; set; }

    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Msg { get; set; }

    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Ciphertext { get; set; }
    
    /// <summary>
    /// Hex-encoded. The tag of the underlying AEAD.
    /// </summary>
    public string? AeadTag { get; set; }

    /// <summary>
    /// Hex-encoded.
    /// </summary>
    public string? Tag { get; set; }

    /// <summary>
    /// "true" or "false".
    /// </summary>
    public string? Result { get; set; }
    
    public string? Comment { get; set; }
}