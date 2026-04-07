use actix_cors::{Cors, CorsServiceError};
use actix_utils::future::ok;
use actix_web::{
    body::{self, BoxBody},
    dev::{fn_service, ServiceRequest, ServiceResponse, Transform},
    http::{
        header::{self, HeaderValue},
        Method, StatusCode,
    },
    test::{self, TestRequest},
    HttpResponse, ResponseError,
};
use regex::bytes::Regex;

fn val_as_str(val: &HeaderValue) -> &str {
    val.to_str().unwrap()
}

#[derive(Debug)]
struct CustomError;

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("custom error")
    }
}

impl ResponseError for CustomError {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized()
            .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
            .body("custom error")
    }
}

#[actix_web::test]
#[should_panic]
async fn test_wildcard_origin() {
    Cors::default()
        .allowed_origin("*")
        .new_transform(test::ok_service())
        .await
        .unwrap();
}

#[actix_web::test]
async fn test_not_allowed_origin_fn() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .allowed_origin_fn(|origin, req| {
            assert_eq!(&origin, req.headers.get(header::ORIGIN).unwrap());

            req.headers
                .get(header::ORIGIN)
                .map(HeaderValue::as_bytes)
                .filter(|b| b.ends_with(b".unknown.com"))
                .is_some()
        })
        .new_transform(test::ok_service())
        .await
        .unwrap();

    {
        let req = TestRequest::get()
            .insert_header(("Origin", "https://www.example.com"))
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;

        assert_eq!(
            Some(&b"https://www.example.com"[..]),
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(HeaderValue::as_bytes)
        );
    }

    {
        let req = TestRequest::get()
            .insert_header(("Origin", "https://www.known.com"))
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;

        assert_eq!(
            None,
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }
}

#[actix_web::test]
async fn test_allowed_origin_fn() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .allowed_origin_fn(|origin, req| {
            assert_eq!(&origin, req.headers.get(header::ORIGIN).unwrap());

            req.headers
                .get(header::ORIGIN)
                .map(HeaderValue::as_bytes)
                .filter(|b| b.ends_with(b".unknown.com"))
                .is_some()
        })
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.example.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;

    assert_eq!(
        "https://www.example.com",
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(val_as_str)
            .unwrap()
    );

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.unknown.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;

    assert_eq!(
        Some(&b"https://www.unknown.com"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
}

#[actix_web::test]
async fn test_allowed_origin_fn_with_environment() {
    let regex = Regex::new("https:.+\\.unknown\\.com").unwrap();

    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .allowed_origin_fn(move |origin, req| {
            assert_eq!(&origin, req.headers.get(header::ORIGIN).unwrap());

            req.headers
                .get(header::ORIGIN)
                .map(HeaderValue::as_bytes)
                .filter(|b| regex.is_match(b))
                .is_some()
        })
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.example.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;

    assert_eq!(
        "https://www.example.com",
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(val_as_str)
            .unwrap()
    );

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.unknown.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;

    assert_eq!(
        Some(&b"https://www.unknown.com"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
}

#[actix_web::test]
async fn test_multiple_origins_preflight() {
    let cors = Cors::default()
        .allowed_origin("https://example.com")
        .allowed_origin("https://example.org")
        .allowed_methods(vec![Method::GET])
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header(("Origin", "https://example.com"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .method(Method::OPTIONS)
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"https://example.com"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );

    let req = TestRequest::default()
        .insert_header(("Origin", "https://example.org"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .method(Method::OPTIONS)
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"https://example.org"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
}

#[actix_web::test]
async fn test_multiple_origins() {
    let cors = Cors::default()
        .allowed_origin("https://example.com")
        .allowed_origin("https://example.org")
        .allowed_methods(vec![Method::GET])
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::get()
        .insert_header(("Origin", "https://example.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"https://example.com"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );

    let req = TestRequest::get()
        .insert_header(("Origin", "https://example.org"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"https://example.org"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
}

#[actix_web::test]
async fn test_response() {
    let exposed_headers = vec![header::AUTHORIZATION, header::ACCEPT];
    let cors = Cors::default()
        .allow_any_origin()
        .send_wildcard()
        .disable_preflight()
        .max_age(3600)
        .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
        .allowed_headers(exposed_headers.clone())
        .expose_headers(exposed_headers.clone())
        .allowed_header(header::CONTENT_TYPE)
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header(("Origin", "https://www.example.com"))
        .method(Method::OPTIONS)
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"*"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        resp.headers().get(header::VARY).map(HeaderValue::as_bytes),
        Some(&b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"[..]),
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        resp.headers().get(header::VARY).map(HeaderValue::as_bytes),
        Some(&b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"[..]),
    );

    #[allow(clippy::needless_collect)]
    {
        let headers = resp
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .map(val_as_str)
            .unwrap()
            .split(',')
            .map(|s| s.trim())
            .collect::<Vec<&str>>();

        // TODO: use HashSet subset check
        for h in exposed_headers {
            assert!(headers.contains(&h.as_str()));
        }
    }

    let exposed_headers = vec![header::AUTHORIZATION, header::ACCEPT];
    let cors = Cors::default()
        .allow_any_origin()
        .send_wildcard()
        .disable_preflight()
        .max_age(3600)
        .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
        .allowed_headers(exposed_headers.clone())
        .expose_headers(exposed_headers.clone())
        .allowed_header(header::CONTENT_TYPE)
        .new_transform(fn_service(|req: ServiceRequest| {
            ok(req.into_response({
                HttpResponse::Ok()
                    .insert_header((header::VARY, "Accept"))
                    .finish()
            }))
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header(("Origin", "https://www.example.com"))
        .method(Method::OPTIONS)
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .map(HeaderValue::as_bytes)
            .unwrap(),
        b"Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        resp.headers().get(header::VARY).map(HeaderValue::as_bytes).unwrap(),
        b"Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    );

    let cors = Cors::default()
        .disable_vary_header()
        .allowed_methods(vec!["POST"])
        .allowed_origin("https://www.example.com")
        .allowed_origin("https://www.google.com")
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header(("Origin", "https://www.example.com"))
        .method(Method::OPTIONS)
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    let origins_str = resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .map(val_as_str);
    assert_eq!(Some("https://www.example.com"), origins_str);
}

#[actix_web::test]
async fn test_validate_origin() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.example.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_blocks_mismatched_origin_by_default() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::get()
        .insert_header(("Origin", "https://www.example.test"))
        .to_srv_request();

    let res = test::call_service(&cors, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!res
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
}

#[actix_web::test]
async fn test_mismatched_origin_block_turned_off() {
    let cors = Cors::default()
        .allow_any_method()
        .allowed_origin("https://www.example.com")
        .block_on_origin_mismatch(false)
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .method(Method::OPTIONS)
        .insert_header(("Origin", "https://wrong.com"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_srv_request();
    let res = test::call_service(&cors, req).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN), None);

    let req = TestRequest::get()
        .insert_header(("Origin", "https://wrong.com"))
        .to_srv_request();
    let res = test::call_service(&cors, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN), None);
}

#[actix_web::test]
async fn test_no_origin_response() {
    let cors = Cors::permissive()
        .disable_preflight()
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default().method(Method::GET).to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    let req = TestRequest::default()
        .insert_header(("Origin", "https://www.example.com"))
        .method(Method::OPTIONS)
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert_eq!(
        Some(&b"https://www.example.com"[..]),
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(HeaderValue::as_bytes)
    );
}

#[actix_web::test]
async fn validate_origin_allows_all_origins() {
    let cors = Cors::permissive()
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header(("Origin", "https://www.example.com"))
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn vary_header_on_all_handled_responses() {
    let cors = Cors::permissive()
        .new_transform(test::ok_service())
        .await
        .unwrap();

    // preflight request
    let req = TestRequest::default()
        .method(Method::OPTIONS)
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    );

    // follow-up regular request
    let req = TestRequest::default()
        .method(Method::PUT)
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    );

    let cors = Cors::default()
        .allow_any_method()
        .new_transform(test::ok_service())
        .await
        .unwrap();

    // regular request OK with no CORS response headers
    let req = TestRequest::default()
        .method(Method::PUT)
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .to_srv_request();
    let res = test::call_service(&cors, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!res
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));

    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        res.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        res.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    );

    // regular request no origin
    let req = TestRequest::default().method(Method::PUT).to_srv_request();
    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    #[cfg(not(feature = "draft-private-network-access"))]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    #[cfg(feature = "draft-private-network-access")]
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .expect("response should have Vary header")
            .to_str()
            .unwrap(),
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    );
}

#[actix_web::test]
async fn test_allow_any_origin_any_method_any_header() {
    let cors = Cors::default()
        .allow_any_origin()
        .allow_any_method()
        .allow_any_header()
        .new_transform(test::ok_service())
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type"))
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .method(Method::OPTIONS)
        .to_srv_request();

    let resp = test::call_service(&cors, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn expose_all_request_header_values() {
    let cors = Cors::permissive()
        .new_transform(fn_service(|req: ServiceRequest| async move {
            let res = req.into_response(
                HttpResponse::Ok()
                    .insert_header((header::CONTENT_DISPOSITION, "test disposition"))
                    .finish(),
            );

            Ok(res)
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type"))
        .to_srv_request();

    let res = test::call_service(&cors, req).await;

    let cd_hdr = res
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(cd_hdr.contains("content-disposition"));
    assert!(cd_hdr.contains("access-control-allow-origin"));
}

#[actix_web::test]
async fn middleware_errors_receive_cors_headers() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .supports_credentials()
        .new_transform(fn_service(|_req: ServiceRequest| async {
            Err::<ServiceResponse<BoxBody>, _>(CustomError.into())
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .to_srv_request();

    let err = test::try_call_service(&cors, req)
        .await
        .expect_err("request should return an error");
    let wrapped = err
        .as_error::<CorsServiceError>()
        .expect("error should be wrapped by CORS");
    assert!(wrapped.as_error::<CustomError>().is_some());
    let resp = err.error_response();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(val_as_str),
        Some("https://www.example.com")
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .map(val_as_str),
        Some("true")
    );
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).map(val_as_str),
        Some("Bearer")
    );
    assert_eq!(
        resp.headers().get(header::VARY).map(val_as_str),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );

    let body = body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "custom error");
}

#[actix_web::test]
async fn middleware_errors_without_origin_only_receive_vary() {
    let cors = Cors::default()
        .new_transform(fn_service(|_req: ServiceRequest| async {
            Err::<ServiceResponse<BoxBody>, _>(actix_web::error::ErrorBadRequest("bad request"))
        }))
        .await
        .unwrap();

    let req = TestRequest::default().to_srv_request();

    let err = test::try_call_service(&cors, req)
        .await
        .expect_err("request should return an error");
    let resp = err.error_response();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        None
    );
    assert_eq!(
        resp.headers().get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        None
    );
    assert_eq!(
        resp.headers().get(header::VARY).map(val_as_str),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
}

#[actix_web::test]
async fn middleware_errors_with_mismatched_origin_keep_non_origin_headers() {
    let cors = Cors::default()
        .allowed_origin("https://www.example.com")
        .supports_credentials()
        .block_on_origin_mismatch(false)
        .new_transform(fn_service(|_req: ServiceRequest| async {
            Err::<ServiceResponse<BoxBody>, _>(actix_web::error::ErrorBadRequest("bad request"))
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://wrong.com"))
        .to_srv_request();

    let err = test::try_call_service(&cors, req)
        .await
        .expect_err("request should return an error");
    let resp = err.error_response();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        None
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .map(val_as_str),
        Some("true")
    );
    assert_eq!(
        resp.headers().get(header::VARY).map(val_as_str),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
}

#[actix_web::test]
async fn middleware_errors_expose_response_headers_when_configured() {
    let cors = Cors::permissive()
        .new_transform(fn_service(|_req: ServiceRequest| async {
            Err::<ServiceResponse<BoxBody>, _>(CustomError.into())
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://www.example.com"))
        .to_srv_request();

    let err = test::try_call_service(&cors, req)
        .await
        .expect_err("request should return an error");
    let resp = err.error_response();
    let exposed = resp
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .map(val_as_str)
        .unwrap();

    assert!(exposed.contains("access-control-allow-origin"));
    assert!(exposed.contains("www-authenticate"));
    assert!(!exposed.contains("access-control-allow-credentials"));
}

#[cfg(feature = "draft-private-network-access")]
#[actix_web::test]
async fn private_network_access() {
    let cors = Cors::permissive()
        .allowed_origin("https://public.site")
        .allow_private_network_access()
        .new_transform(fn_service(|req: ServiceRequest| async move {
            let res = req.into_response(
                HttpResponse::Ok()
                    .insert_header((header::CONTENT_DISPOSITION, "test disposition"))
                    .finish(),
            );

            Ok(res)
        }))
        .await
        .unwrap();

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://public.site"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
        .to_srv_request();
    let res = test::call_service(&cors, req).await;
    assert!(res.headers().contains_key("access-control-allow-origin"));

    let req = TestRequest::default()
        .insert_header((header::ORIGIN, "https://public.site"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
        .insert_header(("Access-Control-Request-Private-Network", "true"))
        .to_srv_request();
    let res = test::call_service(&cors, req).await;
    assert!(res.headers().contains_key("access-control-allow-origin"));
    assert!(res
        .headers()
        .contains_key("access-control-allow-private-network"));
}
