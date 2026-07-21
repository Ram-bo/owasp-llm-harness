namespace OwaspLlmHarness;

/// <summary>
/// Minimal abstraction over a chat LLM. Decoupling the harness from any specific
/// provider keeps the test logic independent of Semantic Kernel and, crucially,
/// lets the whole pipeline run against a deterministic fake in CI without calling
/// a paid, non-deterministic API on every push.
/// </summary>
public interface IChatModel
{
    Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default);
}
