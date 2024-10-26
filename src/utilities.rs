use chrono::Local;
use cookie::Cookie;
use core::net::SocketAddr;
use futures_util::stream;
use har::v1_2::{self, Entries, Headers};
use hyper::{
    header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
    Body, Response, StatusCode,
};
use serde_json::Value::Null;
use serde_json::{json, Value};
use time::format_description;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Converts an HTTP request into a HAR request format.
///
/// # Arguments
/// * `parts` - The parts of the incoming HTTP request.
/// * `body` - The body of the HTTP request as a byte vector.
///
/// # Returns
/// A `v1_2::Request` object representing the HTTP request in HAR format.
pub async fn copy_from_http_request_to_har(
    parts: &hyper::http::request::Parts,
    body: Vec<u8>,
) -> v1_2::Request {
    let method = parts.method.as_str().to_string();
    let url = format!("{}", parts.uri);
    let http_version = "HTTP/1.1".to_string();
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<v1_2::Cookies> = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &COOKIE)
        .map(|(_, value)| parse_cookie(value.to_str().unwrap()))
        .collect();

    let body = match String::from_utf8(body) {
        Ok(valid_string) => valid_string,
        Err(e) => {
            eprintln!("Error converting bytes to UTF-8: {}", e);
            String::new()
        }
    };
    let body_size = body.len() as i64;
    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .next()
        .unwrap_or("".to_string());
    let post_data = if body_size > 0 {
        Some(v1_2::PostData {
            mime_type,
            text: Some(body),
            params: None,
            comment: None,
        })
    } else {
        None
    };

    v1_2::Request {
        method,
        url,
        http_version,
        cookies,
        headers,
        query_string: Vec::new(),
        post_data,
        headers_size,
        body_size,
        comment: None,
    }
}

/// Converts an HTTP response into a HAR response format.
///
/// # Arguments
/// * `parts` - The parts of the HTTP response.
/// * `body` - The body of the HTTP response as a byte vector.
///
/// # Returns
/// A `v1_2::Response` object representing the HTTP response in HAR format.
pub async fn copy_from_http_response_to_har(
    parts: &hyper::http::response::Parts,
    body: Vec<u8>,
) -> v1_2::Response {
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<String> = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &SET_COOKIE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .collect();
    let cookies: Vec<har::v1_2::Cookies> = cookies
        .iter()
        .map(|cookie_string| parse_cookie(cookie_string))
        .collect();

    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .next()
        .unwrap_or("".to_string());

    let redirect_url = if parts.status.is_redirection() {
        let url_option = parts
            .headers
            .iter()
            .filter(|(key, _)| key == &LOCATION)
            .map(|(_, value)| value.to_str().unwrap_or("").to_string())
            .next();

        match url_option {
            Some(url) => url,
            None => "".to_string(),
        }
    } else {
        "".to_string() // Default case if not a redirection
    };

    let http_version = "HTTP/1.1".to_string();

    let body = match String::from_utf8(body) {
        Ok(valid_string) => valid_string,
        Err(e) => {
            eprintln!("Error converting bytes to UTF-8: {}", e);
            String::new()
        }
    };

    let body_size = body.len() as i64;
    let content = v1_2::Content {
        size: body_size,
        compression: None,
        mime_type: Some(mime_type),
        text: Some(body),
        encoding: None,
        comment: None,
    };
    v1_2::Response {
        http_version,
        status: parts.status.as_u16() as i64,
        status_text: parts.status.canonical_reason().unwrap_or("").to_string(),
        cookies,
        headers,
        headers_size,
        body_size,
        comment: None,
        redirect_url: Some(redirect_url),
        content,
    }
}

/// Parses a cookie string into a HAR Cookies format.
///
/// # Arguments
/// * `cookie_str` - A string representation of a cookie.
///
/// # Returns
/// A `v1_2::Cookies` object containing parsed cookie details.
pub fn parse_cookie(cookie_str: &str) -> v1_2::Cookies {
    let parsed = Cookie::parse(cookie_str).unwrap();
    v1_2::Cookies {
        name: parsed.name().to_string(),
        value: parsed.value().to_string(),
        path: parsed.path().map(|p| p.to_string()),
        domain: parsed.domain().map(|d| d.to_string()),
        expires: parsed.expires().and_then(|e| match e {
            cookie::Expiration::DateTime(datetime) => {
                let format_description = format_description::parse("%F %r %z").unwrap();
                datetime.format(&format_description).ok()
            }
            cookie::Expiration::Session => Some("session".to_owned()),
        }),
        http_only: parsed.http_only(),
        secure: parsed.secure(),
        comment: None,
    }
}

/// Converts the body of a request from bytes to a JSON value.
///
/// # Arguments
/// * `body_bytes` - A byte vector containing the body of a request.
///
/// # Returns
/// A `Value` representing the parsed JSON, or `Value::Null` if parsing fails.
pub fn convert_body_to_json(body_bytes: Vec<u8>) -> Value {
    // Convert the body bytes to a string and handle errors
    let body_string = match String::from_utf8(body_bytes.clone()) {
        Ok(valid_string) => valid_string,
        Err(e) => {
            eprintln!("Error converting bytes to UTF-8: {}", e);
            String::new()
        }
    };

    // Parse the request body as JSON and handle errors
    match serde_json::from_str(&body_string) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to parse body as JSON: {}", e);
            Value::Null
        }
    }
}

// Extracts specific content from a JSON request body, particularly the message.
///
/// # Arguments
/// * `body_bytes` - A byte vector containing the body of a request.
///
/// # Returns
/// A string containing the message content extracted from the JSON body.
pub fn parse_request(body_bytes: Vec<u8>) -> String {
    let mut body_json: Value = convert_body_to_json(body_bytes);

    // Extract the message content and check for specific keywords
    if body_json.get_mut("messages").is_some() {
        let message = body_json.get_mut("messages").unwrap();
        let content = message[0].get_mut("content").unwrap();
        let parts = content.get_mut("parts").unwrap();
        parts[0].to_string()
    } else {
        String::new()
    }
}

/// Creates an HTTP response for streaming data using Server-Sent Events (SSE).
///
/// # Arguments
/// * `body_bytes` - A byte vector containing the body of the request.
///
/// # Returns
/// A `Response<Body>` object representing the HTTP response.
pub fn create_response(body_bytes: Vec<u8>) -> Response<Body> {
    // Default response builder
    let mut response_builder = Response::builder().status(StatusCode::OK);

    // Set the Content-Type header to text/event-stream for streaming
    response_builder = response_builder.header(CONTENT_TYPE, "text/event-stream");

    // Create a channel to send data chunks
    let (tx, rx) = mpsc::channel(10);

    let mut body_json = convert_body_to_json(body_bytes);

    // Spawn an async task to send data chunks to the stream
    tokio::spawn(async move {
        let mut body_json_copy = body_json.clone();
        let messages = body_json.get_mut("messages").unwrap();
        let parent_id = messages[0].get_mut("id").unwrap();
        let is_conversation_id = body_json_copy.get_mut("conversation_id").is_none();
        let conversation_id = if is_conversation_id {
            // Creation of new conversation
            &mut serde_json::Value::String(Uuid::new_v4().to_string())
        } else {
            body_json_copy.get_mut("conversation_id").unwrap()
        };
        let message_id = serde_json::Value::String(Uuid::new_v4().to_string());

        let message1 = json!({
            "message": {
                "id": message_id,
                "author": {
                    "role": "assistant",
                    "name": Null,
                    "metadata": {}
                },
                "create_time": Null,
                "update_time": Null,
                "content": {
                    "content_type": "text",
                    "parts": ["Impossible d'executer votre requête car elle contient des informations compromettantes pour votre entreprise !"]
                },
                "status": "finished_successfully",
                "end_turn": true,
                "weight": 1.0,
                "metadata": {
                    "citations": [],
                    "content_references": [],
                    "gizmo_id": Null,
                    "message_type": "next",
                    "model_slug": "gpt-4o",
                    "default_model_slug": "auto",
                    "pad": "AAAAAAAAAAAAAAAAAAAAAA",
                    "parent_id": parent_id,
                    "finish_details": {
                        "type": "stop",
                        "stop_tokens": [200002]
                    },
                    "is_complete": true,
                    "model_switcher_deny": []
                },
                "recipient": "all",
                "channel": Null
            },
            "conversation_id": conversation_id,
            "error": Null
        });

        let message2 = if is_conversation_id {
            json!({
                "type": "title_generation",
                "title": "New chat",
                "conversation_id": conversation_id
            })
        } else {
            Value::String(String::new())
        };

        let message3 = json!({
            "type": "conversation_detail_metadata",
            "banner_info": Null,
            "blocked_features": [],
            "model_limits": [],
            "default_model_slug": "auto",
            "conversation_id": conversation_id
        });

        // Send the messages
        let _ = tx
            .send(Ok::<_, hyper::Error>(format!("data: {}\n\n", message1)))
            .await;
        let _ = tx
            .send(Ok::<_, hyper::Error>(format!("data: {}\n\n", message2)))
            .await;
        let _ = tx
            .send(Ok::<_, hyper::Error>(format!("data: {}\n\n", message3)))
            .await;
        // Finally send the DONE message
        let _ = tx
            .send(Ok::<_, hyper::Error>("data: [DONE]\n\n".into()))
            .await;
    });

    // Convert the receiver into a body stream
    let body_stream = Body::wrap_stream(stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|chunk| (chunk, rx))
    }));

    // Build the response with the streaming body
    response_builder.body(body_stream).unwrap()
}

/// Logs a blocked HTTP request and returns its HAR representation.
///
/// # Arguments
/// * `req_parts` - The parts of the HTTP request.
/// * `body_bytes` - The body of the HTTP request as a byte vector.
///
/// # Returns
/// A tuple containing the HAR log entries and the HTTP response for the blocked request.
pub async fn log_blocked_request(
    req_parts: &hyper::http::request::Parts,
    body_bytes: Vec<u8>,
    ip_client: SocketAddr,
) -> (Entries, Response<Body>) {
    // Process the request and prepare it for logging
    let mut copied_bytes = Vec::with_capacity(body_bytes.len());
    copied_bytes.extend(&body_bytes); // Make a copy of the request body
    let har_request = copy_from_http_request_to_har(req_parts, copied_bytes).await;

    // Creation of the response
    let response = create_response(body_bytes);
    let (res_parts, res_body) = response.into_parts();

    // Process the response and prepare it for logging
    let body_bytes: Vec<u8> = hyper::body::to_bytes(res_body).await.unwrap().to_vec();
    let mut copied_bytes = Vec::with_capacity(body_bytes.len());
    copied_bytes.extend(&body_bytes); // Make a copy of the response body
    let har_response = copy_from_http_response_to_har(&res_parts, copied_bytes).await;

    // Create HAR log entries
    let entries = Entries {
        request: har_request,
        response: har_response,
        time: 0.0,
        server_ip_address: Some(ip_client.to_string()),
        connection: None,
        comment: None,
        started_date_time: Local::now().format("%d/%m/%Y %H:%M:%S").to_string(),
        cache: v1_2::Cache {
            before_request: None,
            after_request: None,
        },
        timings: v1_2::Timings {
            blocked: None,
            dns: None,
            connect: None,
            send: 0.0,
            wait: 0.0,
            receive: 0.0,
            ssl: None,
            comment: None,
        },
        pageref: None,
    };

    // Rebuild the response from its parts and body
    let body: Body = Body::from(hyper::body::Bytes::from(body_bytes));
    let response = Response::<Body>::from_parts(res_parts, body);

    (entries, response)
}