namespace OwaspLlmHarness;

/// <summary>
/// A single adversarial test case: a prompt designed to subvert the application
/// under test, tagged with the OWASP category it probes and paired with the
/// scorer that decides whether the attack succeeded. Growing this corpus is how
/// the harness accumulates value: every real jailbreak you meet becomes a case.
/// </summary>
public sealed record AttackCase
{
    /// <summary>Stable id, also used as the xUnit test-case display name.</summary>
    public required string Id { get; init; }

    public required OwaspCategory Category { get; init; }

    /// <summary>Short description of what the attack attempts.</summary>
    public required string Description { get; init; }

    /// <summary>The adversarial user input sent to the application.</summary>
    public required string AttackPrompt { get; init; }

    /// <summary>Oracle that decides, from the response, whether the attack got through.</summary>
    public required IInjectionScorer Scorer { get; init; }

    public override string ToString() => $"{Id} [{Category}] {Description}";
}
