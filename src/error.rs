use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Clone, Debug)]
pub struct Error(pub StatusCode, pub String);
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self(StatusCode::FORBIDDEN, message.into())
    }
    pub fn missing(message: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, message.into())
    }
    pub fn upstream(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_GATEWAY, message.into())
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, message.into())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1)
    }
}
impl std::error::Error for Error {}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if self.0.is_server_error() {
            tracing::warn!(status = %self.0, error = %self.1, "request failed");
        }
        (
            self.0,
            [("cache-control", "no-store")],
            Json(json!({"error": self.1})),
        )
            .into_response()
    }
}
