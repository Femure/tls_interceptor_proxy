#[cfg(test)]
mod tests {

    use hyper::{
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
        Body, Request, Response, StatusCode,
    };
    use tls_interceptor_proxy::utilities::*;

    #[tokio::test]
    async fn test_copy_from_http_request_to_har() {
        // Create a mock HTTP request
        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/test")
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, "name=value")
            .body(Body::from(r#"{"key":"value"}"#))
            .unwrap();
        let (parts, body) = request.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await.unwrap().to_vec();

        // Call the function
        let har_request = copy_from_http_request_to_har(&parts, body_bytes).await;

        // Verify the resulting HAR request
        assert_eq!(har_request.method, "POST");
        assert_eq!(har_request.url, "https://example.com/test");
        assert_eq!(har_request.headers[0].name, CONTENT_TYPE.as_str());
        assert_eq!(har_request.headers[0].value, "application/json");
        assert_eq!(har_request.cookies[0].name, "name");
        assert_eq!(har_request.cookies[0].value, "value");
    }

    #[tokio::test]
    async fn test_copy_from_http_response_to_har() {
        // Create a mock HTTP response
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(SET_COOKIE, "name=value")
            .body(Body::from(r#"{"key":"value"}"#))
            .unwrap();
        let (parts, body) = response.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await.unwrap().to_vec();

        // Call the function
        let har_response = copy_from_http_response_to_har(&parts, body_bytes).await;

        // Verify the resulting HAR response
        assert_eq!(har_response.status, 200);
        assert_eq!(har_response.content.mime_type.unwrap(), "application/json");
        assert_eq!(har_response.cookies[0].name, "name");
        assert_eq!(har_response.cookies[0].value, "value");
    }

    #[test]
    fn test_parse_cookie() {
        // Create a mock cookie string
        let cookie_str = "sessionId=abc123; Path=/; HttpOnly; Secure";

        // Call the function
        let parsed_cookie = parse_cookie(cookie_str);

        // Verify the parsed cookie fields
        assert_eq!(parsed_cookie.name, "sessionId");
        assert_eq!(parsed_cookie.value, "abc123");
        assert_eq!(parsed_cookie.path.unwrap(), "/");
        assert_eq!(parsed_cookie.http_only, Some(true));
        assert_eq!(parsed_cookie.secure, Some(true));
    }

    #[test]
    fn test_convert_body_to_json() {
        // Define a JSON string
        let body_bytes = br#"{"message":"Hello"}"#.to_vec();

        // Call the function
        let json_value = convert_body_to_json(body_bytes);

        // Verify the JSON content
        assert_eq!(json_value["message"], "Hello");
    }

    #[test]
    fn test_parse_request() {
        // Define a JSON string with a message structure
        let body_bytes =
            br#"{ "messages": [{ "content": { "parts": ["Hello, world!"] }}] }"#.to_vec();

        // Call the function
        let parsed_message = parse_request(body_bytes);

        // Verify the parsed message content
        assert_eq!(parsed_message, "\"Hello, world!\"");
    }

    #[tokio::test]
    async fn test_create_response() {
        // Define a body byte array
        let body_bytes =
            br#"{"messages":[{"id":"aaa211a5-24d7-4868-8d8c-b657402be43b"}]}"#.to_vec();

        // Call the function
        let response = create_response(body_bytes);

        // Verify the response headers and status
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );

        // Check if the response body is structured as expected
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert!(body_bytes.starts_with(b"data: "));
    }
}
