use crate::broadcaster::BroadcastMsg;
use crate::error::Error;
use crate::metrics::{LISTEN_EVENTS_DROPPED, LISTEN_EVENTS_SENT};
use crate::{
    auth::Authenticated,
    namespace::{NamespaceName, NamespaceStore},
};
use axum::extract::State as AxumState;
use axum::http::Uri;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::{extract::Query, json_lines::JsonLines};
use futures::{Stream, StreamExt};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use super::db_factory::namespace_from_headers;
use super::AppState;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    UNKNOWN,
    DELETE,
    INSERT,
    UPDATE,
}

#[derive(Deserialize)]
pub struct ListenQuery {
    table: String,
    action: Vec<Action>,
}

pub(super) async fn handle_listen(
    auth: Authenticated,
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    uri: Uri,
    query: Query<ListenQuery>,
) -> crate::Result<Response> {
    let namespace = namespace_from_headers(
        &headers,
        state.disable_default_namespace,
        state.disable_namespaces,
    )?;

    if !auth.is_namespace_authorized(&namespace) {
        return Err(Error::NamespaceDoesntExist(namespace.to_string()));
    }

    if let Some(primary_url) = state.primary_url {
        let url = primary_url + uri.path_and_query().map_or("", |x| x.as_str());
        return Ok(Redirect::temporary(&url).into_response());
    }

    let stream = listen_stream(
        state.namespaces.clone(),
        namespace,
        query.table.clone(),
        query.action.clone(),
    )
    .await;
    Ok(JsonLines::new(stream).into_response())
}

static LAGGED_MSG: &str = "some changes were lost";

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum AggregatorEvent {
    Error(&'static str),
    #[serde(untagged)]
    Changes(BroadcastMsg),
}

struct Subscription {
    store: NamespaceStore,
    namespace: NamespaceName,
    table: String,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.store.unsubscribe(self.namespace.clone(), &self.table);
    }
}

async fn listen_stream(
    store: NamespaceStore,
    namespace: NamespaceName,
    table: String,
    actions: Vec<Action>,
) -> impl Stream<Item = crate::Result<AggregatorEvent>> {
    async_stream::try_stream! {
        let _sub = Subscription {
            store: store.clone(),
            namespace: namespace.clone(),
            table: table.clone(),
        };

        let mut stream = store.subscribe(namespace.clone(), table.clone());

        while let Some(item) = stream.next().await  {
            match item {
                Ok(msg) => if filter_actions(&msg, &actions) {
                    LISTEN_EVENTS_SENT.increment(1);
                    yield AggregatorEvent::Changes(msg);
                },
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    LISTEN_EVENTS_DROPPED.increment(n as u64);
                    yield AggregatorEvent::Error(&LAGGED_MSG);
                },
            }
        }
    }
}

fn filter_actions(msg: &BroadcastMsg, actions: &Vec<Action>) -> bool {
    for action in actions {
        let count = match action {
            Action::DELETE => msg.delete,
            Action::INSERT => msg.insert,
            Action::UPDATE => msg.update,
            Action::UNKNOWN => msg.unknown,
        };
        if count > 0 {
            return true;
        }
    }
    actions.is_empty()
}
