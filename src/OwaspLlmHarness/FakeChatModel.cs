namespace OwaspLlmHarness;

/// <summary>
/// Deterministic stand-in for a real model. Two jobs:
///   1. Let the harness pipeline run fast, free and repeatably in CI.
///   2. Let you unit-test the scorers themselves by feeding known responses.
/// Construct it with a fixed response, or a function of (system, user) to
/// exercise both "defended" and "vulnerable" paths on demand.
/// </summary>
public sealed class FakeChatModel(Func<string, string, string> respond) : IChatModel
{
    private readonly Func<string, string, string> _respond = respond;

    public FakeChatModel(string fixedResponse) : this((_, _) => fixedResponse) { }

    public Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default)
        => Task.FromResult(_respond(systemPrompt, userPrompt));
}
