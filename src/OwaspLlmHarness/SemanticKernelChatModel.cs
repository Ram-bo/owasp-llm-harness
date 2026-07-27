using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Microsoft.SemanticKernel.Connectors.OpenAI;

namespace OwaspLlmHarness;

/// <summary>
/// Live model backed by Azure OpenAI via Semantic Kernel. Temperature is pinned
/// to 0 to make behaviour as repeatable as the model allows (LLM output is never
/// perfectly deterministic, which is itself part of what a security test must cope with).
///
/// When Azure's content-management policy blocks a prompt, Semantic Kernel throws
/// rather than returning text. We catch that specific case and return a stable
/// marker, so a platform-filter block becomes a scorable "defended" outcome
/// instead of crashing the run. The scorers recognise this marker.
/// </summary>
public sealed class SemanticKernelChatModel : IChatModel
{
    /// <summary>Marker returned when the platform content filter blocks the request.</summary>
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

        try
        {
            var response = await _chat.GetChatMessageContentAsync(history, settings, cancellationToken: ct);
            return response.Content ?? string.Empty;
        }
        catch (HttpOperationException ex) when (IsContentFilter(ex))
        {
            return ContentFilteredMarker;
        }
    }

    private static bool IsContentFilter(HttpOperationException ex)
    {
        var text = ((ex.ResponseContent ?? string.Empty) + " " + (ex.Message ?? string.Empty))
            .ToLowerInvariant();

        return text.Contains("content_filter")
            || text.Contains("content management policy")
            || text.Contains("responsibleaipolicyviolation")
            || text.Contains("content filter");
    }
}