using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace ActionSmokeFixture;

// Deliberately vulnerable examples for testing SARIF upload and source paths.
[ApiController]
[Route("action-smoke")]
public sealed class ExamplesController : ControllerBase
{
    [HttpGet]
    public IActionResult Render([FromQuery] string message) => Content(message, "text/html");

    public static void LegacyEncryption()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
    }
}
