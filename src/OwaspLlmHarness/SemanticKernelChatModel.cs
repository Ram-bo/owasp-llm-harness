using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Microsoft.SemanticKernel.Connectors.OpenAI;

namespace OwaspLlmHarness;

/// <summary>
/// Live model backed by Azure OpenAI via Semantic Kernel. Temperature is pinned
/// to 0 to make behaviour as repeatable as the model allows (LLM output is never
/// perfectly deterministic, which is itself part of what a security test must cope with).
///
/// Note on defence-in-depth: Azure OpenAI applies its own content-management policy
/// *before* the model sees some prompts. When it blocks one, the API returns HTTP 400
/// with a content_filter code. That is a platform-level defence, not a model refusal
/// and not a harness error, so we surface it as a distinct, recognisable outcome
/// (<see cref="ContentFilteredMarker"/>) rather than letting the request throw. The
/// attack was stopped; it simply was not the model that stopped it.
/// </summary>
public sealed class SemanticKernelChatModel : IChatModel
{
    /// <summary>
    /// Sentinel returned when Azure's content filter blocks the request upstream of
    /// the model. Scorers treat a response containing this marker as "defended at the
    /// platform layer" rather than a breach.
    /// </summary>
    public const string ContentFilteredMarker = "[[CONTENT_FILTERED_BY_PLATFORM]]";

    private readonly IChatCompletionService _chat;

    public SemanticKernelChatModel(string deploymentName, string endpoint, string apiKey)
    {
        var builder = Kernel.CreateBuilder();
        builder.AddAzureOpenAIChatCompletion(deploymentName, endpoint, apiKey);
        var kernel = builder.Build();
        _chat = kernel.GetRequiredService<IChatCompletionService>();
    }

    public async Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default)
    {
        var history = new ChatHistory();
        history.AddSystemMessage(systemPrompt);
        history.AddUserMessage(userPrompt);

        var settings = new OpenAIPromptExecutionSettings { Temperature = 0 };

        // Transient transport failures (dropped sockets, timeouts) are infrastructure
        // noise, not security results: turning a flaky connection into a red "attack
        // succeeded" is a false signal. Retry a few times with backoff, and only if it
        // still fails let the exception surface as an error (clearly distinct from a
        // scored breach) rather than silently passing or failing.
        const int maxAttempts = 3;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var response = await _chat.GetChatMessageContentAsync(history, settings, cancellationToken: ct);
                return response.Content ?? string.Empty;
            }
            catch (HttpOperationException ex) when (IsContentFilter(ex))
            {
                // Azure blocked the prompt before the model answered. The attack did not
                // get through; record it as a platform-level defence rather than crashing.
                return ContentFilteredMarker;
            }
            catch (Exception ex) when (attempt < maxAttempts && IsTransient(ex))
            {
                await Task.Delay(TimeSpan.FromSeconds(attempt), ct); // 1s, then 2s
            }
        }
    }

    private static bool IsContentFilter(HttpOperationException ex) =>
        (ex.Message?.Contains("content_filter", StringComparison.OrdinalIgnoreCase) ?? false)
        || (ex.InnerException?.Message?.Contains("content_filter", StringComparison.OrdinalIgnoreCase) ?? false);

    /// <summary>
    /// True for transport-level failures worth retrying (dropped connection, socket
    /// abort, timeout). We walk the inner-exception chain because Semantic Kernel wraps
    /// the original socket error several layers deep.
    /// </summary>
    private static bool IsTransient(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is System.Net.Sockets.SocketException
                or IOException
                or HttpRequestException
                or TaskCanceledException)
            {
                return true;
            }
        }
        return false;
    }
}