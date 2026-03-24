use super::*;

pub trait RelayHandler: Send + Sync {
    fn handle(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>>;
}

#[derive(Default)]
pub struct RelayRouter {
    handlers: HashMap<String, Arc<dyn RelayHandler>>,
}

impl RelayRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<H>(&mut self, route: impl Into<String>, handler: H)
    where
        H: RelayHandler + 'static,
    {
        self.handlers.insert(route.into(), Arc::new(handler));
    }

    pub fn dispatch(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>> {
        let Some(handler) = self.handlers.get(&envelope.route) else {
            return Ok(vec![]);
        };
        handler.handle(envelope)
    }

    pub fn has_route(&self, route: &str) -> bool {
        self.handlers.contains_key(route)
    }
}

fn validate_route(route: &str) -> Result<()> {
    if route.trim().is_empty() {
        return Err(bad_request("invalid_route", "route must be non-empty"));
    }
    if !route.starts_with("relay.") {
        return Err(bad_request(
            "invalid_route_type",
            format!("route must start with relay.: {route}"),
        ));
    }
    if !route
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(bad_request(
            "invalid_route",
            format!("route contains unsupported chars: {route}"),
        ));
    }
    Ok(())
}

pub struct EchoHandler;

impl RelayHandler for EchoHandler {
    fn handle(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>> {
        Ok(vec![RelayEnvelope {
            envelope_id: 0,
            session_id: envelope.session_id.clone(),
            sequence: 0,
            route: "relay.echo.reply".to_string(),
            from: envelope.to.clone().unwrap_or_else(|| "relay".to_string()),
            to: Some(envelope.from.clone()),
            payload: envelope.payload.clone(),
            created_at_unix_ms: 0,
        }])
    }
}
