use hyper::header::HOST;
use hyper::service::Service;
use hyper::{Body, Request, Response};
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files_with_passphrase_on_key(
        &args.cert_file,
        &args.key_file,
        "third-wheel",
    )?;
    let (sender, mut receiver) = mpsc::channel(100);

    let make_har_sender = mitm_layer(move |req: Request<Body>, mut third_wheel: ThirdWheel| {
        let sender = sender.clone();
        let fut = async move {
            // Intercept the request parts and body
            let (req_parts, req_body) = req.into_parts();
            let body_bytes = hyper::body::to_bytes(req_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes);
            let har_request = copy_from_http_request_to_har(&req_parts, copied_bytes).await;

            let host = req_parts
                .headers
                .get(HOST)
                .map(|h| h.to_str().unwrap_or(""))
                .unwrap();
            println!("{}", host);

            let response;
            if host.contains("chatgpt.com") {
                println!("Blocked");
                // If the request matches the condition to be blocked, return a custom response
                response = Response::builder()
                    .status(403)
                    .header("Content-Type", "text/plain")
                    .body(Body::from("Blocked by proxy"))
                    .unwrap();
            } else {
                println!("Ok");
                // If the request is not blocked, proceed with forwarding it
                let body = Body::from(hyper::body::Bytes::from(body_bytes));
                let req = Request::<Body>::from_parts(req_parts, body);

                // Forward the request to the actual server
                response = third_wheel.call(req).await.unwrap();
            }

            // Process the response and send it back
            let (res_parts, res_body) = response.into_parts();

            let body_bytes: Vec<u8> = hyper::body::to_bytes(res_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes);
            let har_response = copy_from_http_response_to_har(&res_parts, copied_bytes).await;

            let body: Body = Body::from(hyper::body::Bytes::from(body_bytes));
            let response = Response::<Body>::from_parts(res_parts, body);

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
            sender.send(entries).await.unwrap();

            Ok(response)
        };
        Box::pin(fut)
    });

    let mitm_proxy = MitmProxy::builder(make_har_sender, ca).build();
    let addr = format!("127.0.0.1:{}", args.port).parse().unwrap();
    let (_, mitm_proxy) = mitm_proxy.bind(addr);

    // Exécution du proxy
    let proxy_task = tokio::spawn(async {
        mitm_proxy.await.unwrap();
        println!("Proxy is running");
    });

    let mut entries = Vec::new();

    // Open a file and write entries to it
    let mut file = File::create(&args.outfile).unwrap();
    // Lecture et affichage des entrées au fur et à mesure
    let receiver_task = tokio::spawn(async move {
        while let Some(entry) = receiver.recv().await {
            // On affiche et stocke les entrées
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

            file.write_all(har::to_json(&out).unwrap().as_bytes()).unwrap();
        }
    });

    // On attend que les deux tâches se terminent (ceci arrive si l'une échoue ou si le proxy est arrêté)
    let (proxy_result, receiver_result) = join!(proxy_task, receiver_task);

    // Gestion des erreurs éventuelles
    if let Err(e) = proxy_result {
        eprintln!("Error in proxy task: {:?}", e); // Log the error
    }

    if let Err(e) = receiver_result {
        eprintln!("Error in receiver task: {:?}", e); // Log the error
    }

    Ok(())
}
