use chrono::Local;
use core::net::SocketAddr;
use futures_util::stream;
use hyper::header::{CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE};
use hyper::service::Service;
use hyper::{Body, Request, Response, StatusCode};
use serde_json::Value::Null;
use serde_json::{json, Value};
use std::fs::File;
use std::io::prelude::*;
use time::format_description;
use tokio::join;
use tokio::sync::mpsc;
use uuid::Uuid;

use argh::FromArgs;
use cookie::Cookie;
use har::v1_2::{self, Entries, Headers};

// Declare the modules that you want to include
mod third_wheel {
    pub mod certificates; // if you need to use certificates.rs
    pub mod error; // if you need to use error.rs
    pub mod proxy; // if you need to use proxy.rs
}

// Import necessary modules and items
use third_wheel::certificates::CertificateAuthority;
use third_wheel::error::Error;
use third_wheel::proxy::mitm::{mitm_layer, ThirdWheel};
use third_wheel::proxy::MitmProxy;

/// Run a TLS mitm proxy that records a HTTP ARchive (HAR) file of the session.
/// Currently this is a proof-of-concept and won't handle binary data or non-utf8 encodings
#[derive(FromArgs)]
struct StartMitm {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8081")]
    port: u16,

    /// output file to save the HAR to
    #[argh(option, short = 'o', default = "\"logs.har\".to_string()")]
    outfile: String,

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"ca/ca_certs/cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"ca/ca_certs/key.pem\".to_string()")]
    key_file: String,
}

/// Converts an HTTP request into a HAR request format.
///
/// # Arguments
/// * `parts` - The parts of the incoming HTTP request.
/// * `body` - The body of the HTTP request as a byte vector.
///
/// # Returns
/// A `v1_2::Request` object representing the HTTP request in HAR format.
async fn copy_from_http_request_to_har(
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
async fn copy_from_http_response_to_har(
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
fn parse_cookie(cookie_str: &str) -> v1_2::Cookies {
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
fn convert_body_to_json(body_bytes: Vec<u8>) -> Value {
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
fn parse_request(body_bytes: Vec<u8>) -> String {
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
fn create_response(body_bytes: Vec<u8>) -> Response<Body> {
    // Default response builder
    let mut response_builder = Response::builder().status(StatusCode::OK); // Default status code is 200 OK

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
async fn log_blocked_request(
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

/// The main entry point for running the TLS MITM proxy.
///
/// # Returns
/// A `Result<(), Error>` indicating success or failure of the operation.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Load the MITM certificate and key
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files_with_passphrase_on_key(
        &args.cert_file,
        &args.key_file,
        "third-wheel", // Passphrase for the private key
    )?;

    // Create a channel for sending HAR log entries
    let (sender, mut receiver) = mpsc::channel(100);

    // Create a middleware layer to intercept requests
    let make_har_sender = mitm_layer(move |req: Request<Body>, mut third_wheel: ThirdWheel| {
        let sender = sender.clone();

        // Define the async block to process requests and responses
        let fut = async move {
            // Get the client IP from the request extensions
            let ip_client = third_wheel.get_client_ip();

            // Intercept the request parts and body
            let (req_parts, req_body) = req.into_parts();
            let body_bytes = hyper::body::to_bytes(req_body).await.unwrap().to_vec();

            // Extract host and request method from headers and URI
            let host = req_parts
                .headers
                .get(HOST)
                .map(|h| h.to_str().unwrap_or(""))
                .unwrap();
            let method = req_parts.method.to_string();
            let url_request = req_parts.uri.path();
            // Check if the request matches certain conditions to block
            if host.eq("chatgpt.com")
                && url_request.eq("/backend-api/conversation")
                && method == "POST"
            {
                // Extract the message write by the user in his prompt
                let prompt = parse_request(body_bytes.clone());
                println!("Prompt {}", prompt);

                // Block requests containing the word "confidential"
                // TODO : Change the condition by the IA detection
                if prompt.contains("confidential") {
                    println!("Blocked");

                    // Get the tuple containing the HAR log entries and the HTTP response for the blocked request
                    let (entries, response) =
                        log_blocked_request(&req_parts, body_bytes.clone(), ip_client).await;

                    // Send the HAR entries over the channel
                    sender.send(entries).await.unwrap();

                    return Ok(response); // Return the response
                }
            }

            // Forward the request if it doesn't contain blocked content
            let body = Body::from(hyper::body::Bytes::from(body_bytes));
            let req = Request::<Body>::from_parts(req_parts, body);
            let response = third_wheel.call(req).await.unwrap();

            Ok(response) // Return the response
        };
        Box::pin(fut) // Return the future for the async operation
    });

    // Set up and bind the MITM proxy
    let mitm_proxy = MitmProxy::builder(make_har_sender, ca).build();
    let addr = format!("127.0.0.1:{}", args.port).parse().unwrap();
    let (_, mitm_proxy) = mitm_proxy.bind(addr);

    // Spawn a task to run the proxy
    let proxy_task = tokio::spawn(async {
        mitm_proxy.await.unwrap();
        println!("Proxy is running");
    });

    // Store the intercepted HAR entries
    let mut entries = Vec::new();

    // Open a file to write HAR logs
    let mut file = File::create(&args.outfile).unwrap();

    // Spawn a task to receive and log entries
    let receiver_task = tokio::spawn(async move {
        while let Some(entry) = receiver.recv().await {
            entries.push(entry.clone());

            let out = har::Har {
                log: har::Spec::V1_2(v1_2::Log {
                    entries: entries.clone(),
                    browser: None,
                    comment: Some("Confidential disclosure blocked".to_string()),
                    pages: None,
                    creator: v1_2::Creator {
                        name: "SentineLLM".to_string(),
                        version: "0.5".to_string(),
                        comment: Some("The IA at the service of confidentiality".to_string()),
                    },
                }),
            };

            // Write the HAR log to the file
            file.write_all(har::to_json(&out).unwrap().as_bytes())
                .unwrap();
            file.write_all(b",\n").unwrap();
        }
    });

    // Wait for both proxy and logging tasks to complete
    let (proxy_result, receiver_result) = join!(proxy_task, receiver_task);

    // Handle errors from the proxy or logging task
    if let Err(e) = proxy_result {
        eprintln!("Error in proxy task: {:?}", e);
    }

    if let Err(e) = receiver_result {
        eprintln!("Error in receiver task: {:?}", e);
    }

    Ok(()) // Exit the function
}
