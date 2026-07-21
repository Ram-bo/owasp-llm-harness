namespace OwaspLlmHarness;

/// <summary>
/// The subset of the OWASP Top 10 for LLM Applications (2025) that this harness
/// exercises. Each attack case is tagged with the category it probes so that a
/// failure is reported against a recognised, auditable taxonomy rather than an
/// ad-hoc label.
/// </summary>
public enum OwaspCategory
{
    /// <summary>LLM01: Prompt Injection (direct and indirect).</summary>
    PromptInjection,

    /// <summary>LLM02: Sensitive Information Disclosure (e.g. secret / data leakage).</summary>
    SensitiveInformationDisclosure,

    /// <summary>LLM05: Improper Output Handling.</summary>
    ImproperOutputHandling,

    /// <summary>LLM06: Excessive Agency (model taking or enabling unauthorised actions).</summary>
    ExcessiveAgency,

    /// <summary>LLM07: System Prompt Leakage.</summary>
    SystemPromptLeakage
}
