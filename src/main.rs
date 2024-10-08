use futures_util::stream;
use hyper::header::HOST;
use hyper::service::Service;
use hyper::StatusCode;
use hyper::{Body, Request, Response};
use serde_json::{json, Value};
use std::fs::File;
use std::io::prelude::*;
use time::format_description;
use tokio::join;
use tokio::sync::mpsc;

use argh::FromArgs;
use cookie::Cookie;
use har::v1_2::{self, Entries, Headers};

use third_wheel::*;

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

async fn copy_from_http_request_to_har(
    parts: &hyper::http::request::Parts,
    body: Vec<u8>,
) -> v1_2::Request {
    let method = parts.method.as_str().to_string();
    let url = format!("{}", parts.uri);
    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1
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
        .filter(|(key, _)| key == &hyper::http::header::COOKIE)
        .map(|(_, value)| parse_cookie(value.to_str().unwrap()))
        .collect();

    let body = match String::from_utf8(body) {
        Ok(valid_string) => valid_string, // Return the valid UTF-8 string directly
        Err(e) => {
            eprintln!("Error converting bytes to UTF-8: {}", e);
            String::new() // Or handle it however you want, e.g., return an empty string or some default
        }
    }; // TODO: handle other encodings correctly
    let body_size = body.len() as i64;
    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &hyper::http::header::CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .nth(0)
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
        .filter(|(key, _)| key == &hyper::http::header::SET_COOKIE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .collect();
    let cookies: Vec<har::v1_2::Cookies> = cookies
        .iter()
        .map(|cookie_string| parse_cookie(cookie_string))
        .collect();

    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &hyper::http::header::CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .nth(0)
        .unwrap_or("".to_string());

    let redirect_url = if parts.status.is_redirection() {
        let url_option = parts
            .headers
            .iter()
            .filter(|(key, _)| key == &hyper::http::header::LOCATION)
            .map(|(_, value)| value.to_str().unwrap_or("").to_string())
            .nth(0);

        match url_option {
            Some(url) => url,
            None => "".to_string(),
        }
    } else {
        "".to_string() // Default case if not a redirection
    };

    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1

    let body = match String::from_utf8(body) {
        Ok(valid_string) => valid_string,
        Err(e) => {
            eprintln!("Error converting bytes to UTF-8: {}", e);
            String::new()
        }
    };

    // TODO: handle other encodings correctly
    let body_size = body.len() as i64;
    let content = v1_2::Content {
        size: body_size,
        compression: None,
        mime_type: Some(mime_type),
        text: Some(body),
        encoding: None, //TODO: handle the base64 case
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
        }), // TODO: ISO 8601 format
        http_only: parsed.http_only(),
        secure: parsed.secure(),
        comment: None,
    }
}

fn create_response(mut body_json: Value) -> Response<Body> {
    // Default response builder
    let mut response_builder = Response::builder().status(StatusCode::OK); // Default status code is 200 OK

    // Set the Content-Type header to text/event-stream for streaming
    response_builder =
        response_builder.header(hyper::http::header::CONTENT_TYPE, "text/event-stream");

    // Create a channel to send data chunks
    let (tx, rx) = mpsc::channel(10);

    // Spawn an async task to send data chunks to the stream
    tokio::spawn(async move {
        let mut body_json_copy = body_json.clone();
        let messages = body_json.get_mut("messages").unwrap();
        let parent_id = messages[0].get_mut("id").unwrap();
        let conversation_id = body_json_copy.get_mut("conversation_id").unwrap();

        // First message
        let message1 = json!({
            "message": {
                "id": null,
                "author": {
                    "role": "assistant",
                    "name": null,
                    "metadata": {}
                },
                "create_time": null,
                "update_time": null,
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
                    "gizmo_id": null,
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
                "channel": null
            },
            "conversation_id": conversation_id,
            "error": null
        });

        // Second message
        let message2 = json!({
            "type": "conversation_detail_metadata",
            "banner_info": null,
            "blocked_features": [],
            "model_limits": [],
            "default_model_slug": "auto",
            "conversation_id": conversation_id
        });

        // Send the messages
        let _ = tx
            .send(Ok::<_, hyper::Error>(format!("data: {}\n\n", message1)).into())
            .await;
        let _ = tx
            .send(Ok::<_, hyper::Error>(format!("data: {}\n\n", message2)).into())
            .await;
        // Finally send the DONE message
        let _ = tx
            .send(Ok::<_, hyper::Error>("data: [DONE]\n\n".into()))
            .await;
    });

    // Convert the receiver into a body stream
    let body_stream = Body::wrap_stream(stream::unfold(rx, |mut rx| async {
        match rx.recv().await {
            Some(chunk) => Some((chunk, rx)),
            None => None,
        }
    }));

    // Build the response with the streaming body
    response_builder.body(body_stream).unwrap()
}

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
            // Intercept the request parts and body
            let (req_parts, req_body) = req.into_parts();
            let body_bytes = hyper::body::to_bytes(req_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes); // Make a copy of the request body
            let har_request = copy_from_http_request_to_har(&req_parts, copied_bytes).await;

            // Extract host and request method from headers and URI
            let host = req_parts
                .headers
                .get(HOST)
                .map(|h| h.to_str().unwrap_or(""))
                .unwrap();
            let method = req_parts.method.to_string();
            let url_request = req_parts.uri.path();

            let response;
            // Check if the request matches certain conditions to block
            if host.contains("chatgpt.com")
                && url_request.contains("/backend-api/conversation")
                && method == "POST"
            {
                // Convert the body bytes to a string and handle errors
                let body_string = match String::from_utf8(body_bytes.clone()) {
                    Ok(valid_string) => valid_string,
                    Err(e) => {
                        eprintln!("Error converting bytes to UTF-8: {}", e);
                        String::new()
                    }
                };

                // Parse the request body as JSON and handle errors
                let mut body_json: Value = match serde_json::from_str(&body_string) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to parse body as JSON: {}", e);
                        Value::Null
                    }
                };
                let body_json_copy = body_json.clone();

                // Extract the message content and check for specific keywords
                let message = body_json.get_mut("messages").unwrap();
                let content = message[0].get_mut("content").unwrap();
                let parts = content.get_mut("parts").unwrap();
                let prompt = parts[0].to_string();
                println!("Prompt {}", prompt);

                // Block requests containing the word "confidential"
                if prompt.contains("confidential") {
                    println!("Blocked");
                    response = create_response(body_json_copy);
                } else {
                    // Forward the request if it doesn't contain blocked content
                    let body = Body::from(hyper::body::Bytes::from(body_bytes));
                    let req = Request::<Body>::from_parts(req_parts, body);
                    response = third_wheel.call(req).await.unwrap();
                }
            } else {
                // Forward other requests
                let body = Body::from(hyper::body::Bytes::from(body_bytes));
                let req = Request::<Body>::from_parts(req_parts, body);
                response = third_wheel.call(req).await.unwrap();
            }

            // Process the response and prepare it for logging
            let (res_parts, res_body) = response.into_parts();
            let body_bytes: Vec<u8> = hyper::body::to_bytes(res_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes);
            let har_response = copy_from_http_response_to_har(&res_parts, copied_bytes).await;

            // Rebuild the response from its parts and body
            let body: Body = Body::from(hyper::body::Bytes::from(body_bytes));
            let response = Response::<Body>::from_parts(res_parts, body);

            // Create HAR log entries
            let entries = Entries {
                request: har_request,
                response: har_response,
                time: 0.0,
                server_ip_address: None,
                connection: None,
                comment: None,
                started_date_time: "bla".to_string(),
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
            // Send the HAR entries over the channel
            sender.send(entries).await.unwrap();

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
                    comment: None,
                    pages: None,
                    creator: v1_2::Creator {
                        name: "third-wheel".to_string(),
                        version: "0.5".to_string(),
                        comment: None,
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
