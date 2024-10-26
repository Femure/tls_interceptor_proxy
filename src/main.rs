use argh::FromArgs;
use har::v1_2;
use hyper::{header::HOST, Body, Request};
use std::fs::File;
use std::io::prelude::*;
use tokio::join;
use tokio::sync::mpsc;
use tower::Service;

mod utilities;
use crate::utilities::*;

mod third_wheel;
use crate::third_wheel::{
    certificates::CertificateAuthority,
    error::Error,
    proxy::{
        mitm::{mitm_layer, ThirdWheel},
        MitmProxy,
    },
};

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
