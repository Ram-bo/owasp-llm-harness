namespace OwaspLlmHarness;

/// <summary>
/// An oracle that decides whether an attack succeeded, given the application's
/// response. Unlike an exact-match assertion, a scorer encodes what "the attack
/// got through" means for a particular class of attack. This is the one genuinely
/// LLM-specific part of the harness; everything around it is ordinary test plumbing.
/// </summary>
public interface IInjectionScorer
{
    ScoreResult Score(string applicationResponse);
}

/// <summary>Outcome of scoring a single response.</summary>
public sealed record ScoreResult(bool AttackSucceeded, string Rationale)
{
    public static ScoreResult Defended(string why) => new(false, why);
    public static ScoreResult Breached(string why) => new(true, why);
}
