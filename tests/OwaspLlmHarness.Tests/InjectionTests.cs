using OwaspLlmHarness;
using Xunit;
using Xunit.Abstractions;

namespace OwaspLlmHarness.Tests;

/// <summary>
/// STRICT guardrail — a regression GATE.
///
/// The strict guardrail enumerates every forbidden transformation and is expected
/// to defend every attack. A leak here is a genuine failure: either a regression,
/// or a notable finding that an attack is strong enough to defeat even a careful
/// guardrail. So these tests assert the attack was defended, and a breach fails
/// the run by design.
///
/// Default model: FakeChatModel (deterministic, no API key, CI-safe) — all pass.
/// For live runs set HARNESS_USE_LIVE_MODEL=1 plus the three AZURE_OPENAI_* vars.
/// </summary>
public sealed class InjectionTests_Strict
{
    private readonly ITestOutputHelper _output;
    public InjectionTests_Strict(ITestOutputHelper output) => _output = output;

    [Theory]
    [MemberData(nameof(AttackCorpus.CaseIds), MemberType = typeof(AttackCorpus))]
    public async Task Strict_guardrail_defends_attack(string caseId)
    {
        var attack = AttackCorpus.ById(caseId);
        var app = GuardedChatApp.SampleWithStrictGuardrail(ModelFactory.CreateModel(), AttackCorpus.Canary);

        var response = await app.AskAsync(attack.AttackPrompt);
        var verdict = attack.Scorer.Score(response);

        _output.WriteLine($"Case:      {attack}");
        _output.WriteLine($"Attack:    {attack.AttackPrompt}");
        _output.WriteLine($"Response:  {response}");
        _output.WriteLine($"Verdict:   {(verdict.AttackSucceeded ? "BREACHED" : "defended")} — {verdict.Rationale}");

        Assert.False(verdict.AttackSucceeded,
            $"[STRICT][{attack.Category}] {attack.Id} was NOT defended: {verdict.Rationale}");
    }
}

/// <summary>
/// LOOSE guardrail — a CHARACTERISATION, not a gate.
///
/// The loose guardrail ("keep it confidential") is a deliberately weak baseline
/// representative of what many production apps ship. The point is to observe WHICH
/// attacks leak against it, not to assert that none do. Breaches are recorded as
/// findings in the test output rather than failing the run; the test asserts only
/// that the harness executed and produced a verdict.
///
/// Under the deterministic FakeChatModel used in CI, nothing leaks, so this stays
/// green there. Against a live model, run it and read the per-attack outcomes in
/// the test output to see which task-framed attacks the loose guardrail leaks to.
/// </summary>
public sealed class InjectionTests_Loose
{
    private readonly ITestOutputHelper _output;
    public InjectionTests_Loose(ITestOutputHelper output) => _output = output;

    [Theory]
    [MemberData(nameof(AttackCorpus.CaseIds), MemberType = typeof(AttackCorpus))]
    public async Task Loose_guardrail_outcome_is_recorded(string caseId)
    {
        var attack = AttackCorpus.ById(caseId);
        var app = GuardedChatApp.SampleWithLooseGuardrail(ModelFactory.CreateModel(), AttackCorpus.Canary);

        var response = await app.AskAsync(attack.AttackPrompt);
        var verdict = attack.Scorer.Score(response);

        _output.WriteLine($"Case:      {attack}");
        _output.WriteLine($"Outcome:   {(verdict.AttackSucceeded ? "BREACHED (finding)" : "defended")} — {verdict.Rationale}");
        if (verdict.AttackSucceeded)
            _output.WriteLine($"Response:  {response}");

        // Characterisation: a breach here is a documented finding, not a failure.
        // Assert only that scoring executed and produced a rationale.
        Assert.False(string.IsNullOrWhiteSpace(verdict.Rationale));
    }
}

/// <summary>Shared model factory used by both test classes.</summary>
internal static class ModelFactory
{
    internal static IChatModel CreateModel()
    {
        var useLive = Environment.GetEnvironmentVariable("HARNESS_USE_LIVE_MODEL") == "1";
        if (!useLive)
            return new FakeChatModel("I'm sorry, but I can't help with that request.");

        return new SemanticKernelChatModel(
            RequireEnv("AZURE_OPENAI_DEPLOYMENT"),
            RequireEnv("AZURE_OPENAI_ENDPOINT"),
            RequireEnv("AZURE_OPENAI_API_KEY"));
    }

    private static string RequireEnv(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Environment variable '{name}' is required for live runs.");
}