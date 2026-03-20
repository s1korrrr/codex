use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::config_types::WebSearchMode;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::AgentMessageContentDeltaEvent;
use codex_protocol::protocol::AgentMessageDeltaEvent;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExitedReviewModeEvent;
use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::ReviewOutputEvent;
use codex_protocol::protocol::SubAgentSource;
use tokio_util::sync::CancellationToken;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex_delegate::run_codex_thread_one_shot;
use crate::config::Constrained;
use crate::review_format::format_review_findings_block;
use crate::review_format::render_review_output_text;
use crate::state::TaskKind;
use codex_features::Feature;
use codex_protocol::user_input::UserInput;

use super::SessionTask;
use super::SessionTaskContext;

#[derive(Clone, Copy)]
pub(crate) struct ReviewTask;

impl ReviewTask {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SessionTask for ReviewTask {
    fn kind(&self) -> TaskKind {
        TaskKind::Review
    }

    fn span_name(&self) -> &'static str {
        "session_task.review"
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<SessionTaskContext>,
        ctx: Arc<TurnContext>,
        input: Vec<UserInput>,
        cancellation_token: CancellationToken,
    ) -> Option<String> {
        let _ = session.session.services.session_telemetry.counter(
            "codex.task.review",
            /*inc*/ 1,
            &[],
        );

        // Start sub-codex conversation and get the receiver for events.
        let output = match start_review_conversation(
            session.clone(),
            ctx.clone(),
            input,
            cancellation_token.clone(),
        )
        .await
        {
            Some(receiver) => process_review_events(session.clone(), ctx.clone(), receiver).await,
            None => None,
        };
        if !cancellation_token.is_cancelled() {
            exit_review_mode(session.clone_session(), output.clone(), ctx.clone()).await;
        }
        None
    }

    async fn abort(&self, session: Arc<SessionTaskContext>, ctx: Arc<TurnContext>) {
        exit_review_mode(session.clone_session(), /*review_output*/ None, ctx).await;
    }
}

async fn start_review_conversation(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    input: Vec<UserInput>,
    cancellation_token: CancellationToken,
) -> Option<async_channel::Receiver<Event>> {
    let sub_agent_config = build_review_sub_agent_config(ctx.as_ref());
    (run_codex_thread_one_shot(
        sub_agent_config,
        session.auth_manager(),
        session.models_manager(),
        input,
        session.clone_session(),
        ctx.clone(),
        cancellation_token,
        SubAgentSource::Review,
        /*final_output_json_schema*/ None,
        /*initial_history*/ None,
    )
    .await)
        .ok()
        .map(|io| io.rx_event)
}

fn build_review_sub_agent_config(ctx: &TurnContext) -> crate::config::Config {
    let mut config = ctx.config.as_ref().clone();
    config.model = Some(ctx.model_info.slug.clone());
    config.model_provider = ctx.provider.clone();
    config.model_reasoning_effort = ctx.reasoning_effort;
    config.model_reasoning_summary = Some(ctx.reasoning_summary);
    config.developer_instructions = ctx.developer_instructions.clone();
    config.compact_prompt = ctx.compact_prompt.clone();
    config.permissions.shell_environment_policy = ctx.shell_environment_policy.clone();
    config.codex_linux_sandbox_exe = ctx.codex_linux_sandbox_exe.clone();
    config.cwd = ctx.cwd.clone();
    config.permissions.sandbox_policy = ctx.sandbox_policy.clone();
    config.permissions.file_system_sandbox_policy = ctx.file_system_sandbox_policy.clone();
    config.permissions.network_sandbox_policy = ctx.network_sandbox_policy;

    // Carry over review-only feature restrictions so the delegate cannot
    // re-enable blocked tools (web search, collab tools, view image).
    if let Err(err) = config.web_search_mode.set(WebSearchMode::Disabled) {
        panic!("by construction Constrained<WebSearchMode> must always support Disabled: {err}");
    }
    let _ = config.features.disable(Feature::SpawnCsv);
    let _ = config.features.disable(Feature::Collab);

    // Set explicit review rubric for the sub-agent and keep review turns
    // approval-free even when the parent turn is interactive.
    config.base_instructions = Some(crate::REVIEW_PROMPT.to_string());
    config.permissions.approval_policy = Constrained::allow_only(AskForApproval::Never);

    let model = config
        .review_model
        .clone()
        .unwrap_or_else(|| ctx.model_info.slug.clone());
    config.model = Some(model);
    config
}

async fn process_review_events(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    receiver: async_channel::Receiver<Event>,
) -> Option<ReviewOutputEvent> {
    let mut prev_agent_message: Option<Event> = None;
    while let Ok(event) = receiver.recv().await {
        match event.clone().msg {
            EventMsg::AgentMessage(_) => {
                if let Some(prev) = prev_agent_message.take() {
                    session
                        .clone_session()
                        .send_event(ctx.as_ref(), prev.msg)
                        .await;
                }
                prev_agent_message = Some(event);
            }
            // Suppress ItemCompleted only for assistant messages: forwarding it
            // would trigger legacy AgentMessage via as_legacy_events(), which this
            // review flow intentionally hides in favor of structured output.
            EventMsg::ItemCompleted(ItemCompletedEvent {
                item: TurnItem::AgentMessage(_),
                ..
            })
            | EventMsg::AgentMessageDelta(AgentMessageDeltaEvent { .. })
            | EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent { .. }) => {}
            EventMsg::TurnComplete(task_complete) => {
                // Parse review output from the last agent message (if present).
                let out = task_complete
                    .last_agent_message
                    .as_deref()
                    .map(parse_review_output_event);
                return out;
            }
            EventMsg::TurnAborted(_) => {
                // Cancellation or abort: consumer will finalize with None.
                return None;
            }
            other => {
                session
                    .clone_session()
                    .send_event(ctx.as_ref(), other)
                    .await;
            }
        }
    }
    // Channel closed without TurnComplete: treat as interrupted.
    None
}

/// Parse a ReviewOutputEvent from a text blob returned by the reviewer model.
/// If the text is valid JSON matching ReviewOutputEvent, deserialize it.
/// Otherwise, attempt to extract the first JSON object substring and parse it.
/// If parsing still fails, return a structured fallback carrying the plain text
/// in `overall_explanation`.
fn parse_review_output_event(text: &str) -> ReviewOutputEvent {
    if let Ok(ev) = serde_json::from_str::<ReviewOutputEvent>(text) {
        return ev;
    }
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}'))
        && start < end
        && let Some(slice) = text.get(start..=end)
        && let Ok(ev) = serde_json::from_str::<ReviewOutputEvent>(slice)
    {
        return ev;
    }
    ReviewOutputEvent {
        overall_explanation: text.to_string(),
        ..Default::default()
    }
}

/// Emits an ExitedReviewMode Event with optional ReviewOutput,
/// and records a developer message with the review output.
pub(crate) async fn exit_review_mode(
    session: Arc<Session>,
    review_output: Option<ReviewOutputEvent>,
    ctx: Arc<TurnContext>,
) {
    const REVIEW_USER_MESSAGE_ID: &str = "review_rollout_user";
    const REVIEW_ASSISTANT_MESSAGE_ID: &str = "review_rollout_assistant";
    let (user_message, assistant_message) = if let Some(out) = review_output.clone() {
        let mut findings_str = String::new();
        let text = out.overall_explanation.trim();
        if !text.is_empty() {
            findings_str.push_str(text);
        }
        if !out.findings.is_empty() {
            let block = format_review_findings_block(&out.findings, /*selection*/ None);
            findings_str.push_str(&format!("\n{block}"));
        }
        let rendered =
            crate::client_common::REVIEW_EXIT_SUCCESS_TMPL.replace("{results}", &findings_str);
        let assistant_message = render_review_output_text(&out);
        (rendered, assistant_message)
    } else {
        let rendered = crate::client_common::REVIEW_EXIT_INTERRUPTED_TMPL.to_string();
        let assistant_message =
            "Review was interrupted. Please re-run /review and wait for it to complete."
                .to_string();
        (rendered, assistant_message)
    };

    session
        .record_conversation_items(
            &ctx,
            &[ResponseItem::Message {
                id: Some(REVIEW_USER_MESSAGE_ID.to_string()),
                role: "user".to_string(),
                content: vec![ContentItem::InputText { text: user_message }],
                end_turn: None,
                phase: None,
            }],
        )
        .await;

    session
        .send_event(
            ctx.as_ref(),
            EventMsg::ExitedReviewMode(ExitedReviewModeEvent { review_output }),
        )
        .await;
    session
        .record_response_item_and_emit_turn_item(
            ctx.as_ref(),
            ResponseItem::Message {
                id: Some(REVIEW_ASSISTANT_MESSAGE_ID.to_string()),
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: assistant_message,
                }],
                end_turn: None,
                phase: None,
            },
        )
        .await;

    // Review turns can run before any regular user turn, so explicitly
    // materialize rollout persistence. Do this after emitting review output so
    // file creation + git metadata collection cannot delay client-facing items.
    session.ensure_rollout_materialized().await;
}

#[cfg(test)]
mod tests {
    use super::build_review_sub_agent_config;
    use crate::codex::make_session_and_context;
    use codex_protocol::permissions::FileSystemSandboxPolicy;
    use codex_protocol::permissions::NetworkSandboxPolicy;
    use codex_protocol::protocol::AskForApproval;
    use codex_protocol::protocol::SandboxPolicy;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    fn pick_runtime_sandbox(
        constraint: &crate::config::Constrained<SandboxPolicy>,
        base: SandboxPolicy,
    ) -> SandboxPolicy {
        let candidates = [
            SandboxPolicy::DangerFullAccess,
            SandboxPolicy::new_workspace_write_policy(),
            SandboxPolicy::new_read_only_policy(),
        ];
        candidates
            .into_iter()
            .find(|candidate| *candidate != base && constraint.can_set(candidate).is_ok())
            .unwrap_or(base)
    }

    #[tokio::test]
    async fn build_review_sub_agent_config_uses_turn_runtime_sandbox_state() {
        let (_session, mut turn) = make_session_and_context().await;
        let runtime_sandbox = pick_runtime_sandbox(
            &turn.config.permissions.sandbox_policy,
            turn.config.permissions.sandbox_policy.get().clone(),
        );
        let runtime_cwd = tempfile::tempdir().expect("temp dir");
        let runtime_cwd_path = runtime_cwd.path().to_path_buf();
        let expected_file_system_sandbox_policy =
            FileSystemSandboxPolicy::from_legacy_sandbox_policy(
                &runtime_sandbox,
                &runtime_cwd_path,
            );
        let expected_network_sandbox_policy = NetworkSandboxPolicy::from(&runtime_sandbox);
        turn.cwd = runtime_cwd_path.clone();
        turn.sandbox_policy = turn.config.permissions.sandbox_policy.clone();
        turn.sandbox_policy
            .set(runtime_sandbox.clone())
            .expect("runtime sandbox policy set");
        turn.file_system_sandbox_policy = expected_file_system_sandbox_policy.clone();
        turn.network_sandbox_policy = expected_network_sandbox_policy;
        turn.codex_linux_sandbox_exe = Some(PathBuf::from("/bin/echo"));

        assert_ne!(
            runtime_sandbox,
            turn.config.permissions.sandbox_policy.get().clone(),
            "test requires runtime sandbox override to differ from base config"
        );

        let config = build_review_sub_agent_config(&turn);

        assert_eq!(config.cwd, runtime_cwd_path);
        assert_eq!(config.permissions.sandbox_policy.get(), &runtime_sandbox);
        assert_eq!(
            config.permissions.file_system_sandbox_policy,
            expected_file_system_sandbox_policy
        );
        assert_eq!(
            config.permissions.network_sandbox_policy,
            expected_network_sandbox_policy
        );
        assert_eq!(
            config.permissions.approval_policy.value(),
            AskForApproval::Never
        );
        assert_eq!(
            config.codex_linux_sandbox_exe,
            Some(PathBuf::from("/bin/echo"))
        );
    }
}
