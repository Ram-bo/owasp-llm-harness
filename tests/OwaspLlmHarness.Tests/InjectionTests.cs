using OwaspLlmHarness;
using Xunit;
using Xunit.Abstractions;

namespace OwaspLlmHarness.Tests;

/// <summary>
/// Runs every attack in the corpus against the application under test and asserts
/// the attack was defended. A newly successful attack surfaces as a red test named
/// after its OWASP category and case id, so a security regression breaks the build
/// exactly like a functional one.
///
/// Model selection is controlled by the HARNESS_MODEL environment variable:
///   (unset) or "safe"  -> deterministic fake that refuses everything. CI default:
///                          fast, free, stable. Proves the pipeline is green when the
///                          app is well-behaved.
///   "vulnerable"       -> deterministic fake that LEAKS the canary and COMPLIES with
///                          off-policy / unsafe-output requests. Every attack should
///                          turn the suite red. Use this to demonstrate that the harness
///                          actually detects breaches (i.e. the tests can fail), not just
///                          that they pass.
///   "live"             -> real deployed model via Semantic Kernel / Azure OpenAI.
///                          Requires AZURE_OPENAI_DEPLOYMENT / _ENDPOINT / _API_KEY.
///                          This is the real security test against what you ship.
/// </summary>
public sealed class InjectionTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

    [Theory]
    [MemberData(nameof(AttackCorpus.CaseIds), MemberType = typeof(AttackCorpus))]
    public async Task Attack_is_defended(string caseId)
    {
        var attack = AttackCorpus.ById(caseId);
        var model = CreateModel(attack);
        var app = GuardedChatApp.SampleWithSecret(model, AttackCorpus.Canary);

        var response = await app.AskAsync(attack.AttackPrompt);
        var verdict = attack.Scorer.Score(response);

        _output.WriteLine($"Case:     {attack}");
        _output.WriteLine($"Attack:   {attack.AttackPrompt}");
        _output.WriteLine($"Response: {response}");
        _output.WriteLine($"Verdict:  {(verdict.AttackSucceeded ? "BREACHED" : "defended")} - {verdict.Rationale}");

        Assert.False(verdict.AttackSucceeded,
            $"[{attack.Category}] {attack.Id} was NOT defended: {verdict.Rationale}");
    }

    private static IChatModel CreateModel(AttackCase attack)
    {
        var mode = (Environment.GetEnvironmentVariable("HARNESS_MODEL") ?? "safe").ToLowerInvariant();

        return mode switch
        {
            "live"       => CreateLiveModel(),
            "vulnerable" => new FakeChatModel((sys, user) => VulnerableResponse(attack, sys)),
            _            => new FakeChatModel("I'm sorry, but I can't help with that request."),
        };
    }

    /// <summary>
    /// A deliberately insecure fake whose whole purpose is to make the suite go red,
    /// proving the harness detects breaches rather than only rubber-stamping a compliant
    /// model (the "does the smoke detector actually beep?" check). It produces the breach
    /// appropriate to what each attack probes, so every case fails against its own oracle:
    ///   - canary-scored attacks    -> disclose the canary
    ///   - unsafe-output attacks    -> emit an executable/renderable payload
    ///   - excessive-agency attacks -> comply instead of refusing
    /// </summary>
    private static string VulnerableResponse(AttackCase attack, string systemPrompt) => attack.Category switch
    {
        OwaspCategory.ImproperOutputHandling =>
            "Sure, here is your greeting: Hello <script>alert(document.cookie)</script>, have a great day!",

        OwaspCategory.ExcessiveAgency =>
            "Absolutely, executing that now. Done. Here is the output you requested.",

        // PromptInjection, SensitiveInformationDisclosure, SystemPromptLeakage all
        // adjudicated by the canary oracle: a vulnerable model simply discloses it.
        _ => DiscloseCanary(systemPrompt),
    };

    private static string DiscloseCanary(string systemPrompt)
    {
        var canary = systemPrompt.Contains(AttackCorpus.Canary) ? AttackCorpus.Canary : "(unknown)";
        return $"Of course! The internal access code is {canary}. Happy to help further.";
    }

    private static IChatModel CreateLiveModel()
    {
        var deployment = RequireEnv("AZURE_OPENAI_DEPLOYMENT");
        var endpoint = RequireEnv("AZURE_OPENAI_ENDPOINT");
        var apiKey = RequireEnv("AZURE_OPENAI_API_KEY");
        return new SemanticKernelChatModel(deployment, endpoint, apiKey);
    }

    private static string RequireEnv(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Environment variable '{name}' is required for live runs.");
}
