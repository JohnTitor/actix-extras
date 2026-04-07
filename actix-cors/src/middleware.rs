use std::{collections::HashSet, error::Error as StdError, fmt, rc::Rc};

use actix_utils::future::ok;
use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{forward_ready, RequestHead, Service, ServiceRequest, ServiceResponse},
    http::{
        header::{self, HeaderValue},
        Method, StatusCode,
    },
    Error, HttpResponse, ResponseError, Result,
};
use futures_util::future::{FutureExt as _, LocalBoxFuture};
use log::debug;

use crate::{
    builder::intersperse_header_values,
    inner::{add_vary_header, header_value_try_into_method},
    AllOrSome, CorsError, Inner,
};

/// Service wrapper for Cross-Origin Resource Sharing support.
///
/// This struct contains the settings for CORS requests to be validated and for responses to
/// be generated.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct CorsMiddleware<S> {
    pub(crate) service: S,
    pub(crate) inner: Rc<Inner>,
}

#[derive(Debug)]
struct CorsResponseContext {
    allow_origin: Option<HeaderValue>,
    expose_headers: Option<HeaderValue>,
    expose_all_headers: bool,
    supports_credentials: bool,
    #[cfg(feature = "draft-private-network-access")]
    should_allow_private_network: bool,
    vary_header: bool,
}

impl CorsResponseContext {
    fn from_request_head(inner: &Inner, req: &RequestHead, origin_allowed: bool) -> Self {
        Self {
            allow_origin: if origin_allowed {
                inner.access_control_allow_origin(req)
            } else {
                None
            },
            expose_headers: inner.expose_headers_baked.clone(),
            expose_all_headers: matches!(inner.expose_headers, AllOrSome::All),
            supports_credentials: inner.supports_credentials,
            #[cfg(feature = "draft-private-network-access")]
            should_allow_private_network: inner.allow_private_network_access
                && req
                    .headers()
                    .contains_key("access-control-request-private-network"),
            vary_header: inner.vary_header,
        }
    }

    fn apply(&self, headers: &mut header::HeaderMap) {
        if let Some(ref origin) = self.allow_origin {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        }

        if let Some(ref expose) = self.expose_headers {
            log::trace!("exposing selected headers: {:?}", expose);

            headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        } else if self.expose_all_headers {
            // intersperse_header_values requires that argument is non-empty
            if !headers.is_empty() {
                let expose_all_headers = headers
                    .keys()
                    .map(|name| name.as_str())
                    .collect::<HashSet<_>>();

                let expose_headers_value = intersperse_header_values(&expose_all_headers);

                log::trace!(
                    "exposing all headers from request: {:?}",
                    expose_headers_value
                );

                headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose_headers_value);
            }
        }

        if self.supports_credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }

        #[cfg(feature = "draft-private-network-access")]
        if self.should_allow_private_network {
            headers.insert(
                header::HeaderName::from_static("access-control-allow-private-network"),
                HeaderValue::from_static("true"),
            );
        }

        if self.vary_header {
            add_vary_header(headers);
        }
    }

    fn into_service_response<B>(self, mut res: ServiceResponse<B>) -> ServiceResponse<B> {
        self.apply(res.headers_mut());
        res
    }
}

/// Error wrapper used when `Cors` adds CORS headers to a wrapped service error response.
///
/// This wrapper preserves the original error response body and status while allowing callers to
/// recover the inner error through [`Self::as_error`] or [`Self::as_response_error`].
#[derive(Debug)]
pub struct CorsServiceError {
    inner: Error,
    context: CorsResponseContext,
}

impl CorsServiceError {
    /// Returns the wrapped response error as a trait object.
    pub fn as_response_error(&self) -> &dyn ResponseError {
        self.inner.as_response_error()
    }

    /// Downcasts the wrapped response error.
    pub fn as_error<T: ResponseError + 'static>(&self) -> Option<&T> {
        self.inner.as_error()
    }

    /// Returns the wrapped Actix Web error.
    pub fn into_inner(self) -> Error {
        self.inner
    }
}

impl fmt::Display for CorsServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl StdError for CorsServiceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl ResponseError for CorsServiceError {
    fn status_code(&self) -> StatusCode {
        self.inner.as_response_error().status_code()
    }

    fn error_response(&self) -> HttpResponse {
        let mut res = self.inner.error_response();
        self.context.apply(res.headers_mut());
        res
    }
}

impl<S> CorsMiddleware<S> {
    /// Returns true if request is `OPTIONS` and contains an `Access-Control-Request-Method` header.
    fn is_request_preflight(req: &ServiceRequest) -> bool {
        // check request method is OPTIONS
        if req.method() != Method::OPTIONS {
            return false;
        }

        // check follow-up request method is present and valid
        if req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(header_value_try_into_method)
            .is_none()
        {
            return false;
        }

        true
    }

    /// Validates preflight request headers against configuration and constructs preflight response.
    ///
    /// Checks:
    /// - `Origin` header is acceptable;
    /// - `Access-Control-Request-Method` header is acceptable;
    /// - `Access-Control-Request-Headers` header is acceptable.
    fn handle_preflight(&self, req: ServiceRequest) -> ServiceResponse {
        let inner = Rc::clone(&self.inner);

        match inner.validate_origin(req.head()) {
            Ok(true) => {}
            Ok(false) => return req.error_response(CorsError::OriginNotAllowed),
            Err(err) => return req.error_response(err),
        };

        if let Err(err) = inner
            .validate_allowed_method(req.head())
            .and_then(|_| inner.validate_allowed_headers(req.head()))
        {
            return req.error_response(err);
        }

        let mut res = HttpResponse::Ok();

        if let Some(origin) = inner.access_control_allow_origin(req.head()) {
            res.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
        }

        if let Some(ref allowed_methods) = inner.allowed_methods_baked {
            res.insert_header((
                header::ACCESS_CONTROL_ALLOW_METHODS,
                allowed_methods.clone(),
            ));
        }

        if let Some(ref headers) = inner.allowed_headers_baked {
            res.insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, headers.clone()));
        } else if let Some(headers) = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
            // all headers allowed, return
            res.insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, headers.clone()));
        }

        #[cfg(feature = "draft-private-network-access")]
        if inner.allow_private_network_access
            && req
                .headers()
                .contains_key("access-control-request-private-network")
        {
            res.insert_header((
                header::HeaderName::from_static("access-control-allow-private-network"),
                HeaderValue::from_static("true"),
            ));
        }

        if inner.supports_credentials {
            res.insert_header((
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            ));
        }

        if let Some(max_age) = inner.max_age {
            res.insert_header((header::ACCESS_CONTROL_MAX_AGE, max_age.to_string()));
        }

        let mut res = res.finish();

        if inner.vary_header {
            add_vary_header(res.headers_mut());
        }

        req.into_response(res)
    }
}

impl<S, B> Service<ServiceRequest> for CorsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,

    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let origin = req.headers().get(header::ORIGIN);

        // handle preflight requests
        if self.inner.preflight && Self::is_request_preflight(&req) {
            let res = self.handle_preflight(req);
            return ok(res.map_into_right_body()).boxed_local();
        }

        // only check actual requests with a origin header
        let origin_allowed = match (origin, self.inner.validate_origin(req.head())) {
            (None, _) => false,
            (_, Ok(origin_allowed)) => origin_allowed,
            (_, Err(err)) => {
                debug!("origin validation failed; inner service is not called");
                let mut res = req.error_response(err);

                if self.inner.vary_header {
                    add_vary_header(res.headers_mut());
                }

                return ok(res.map_into_right_body()).boxed_local();
            }
        };

        let inner = Rc::clone(&self.inner);
        let error_context =
            CorsResponseContext::from_request_head(&self.inner, req.head(), origin_allowed);
        let fut = self.service.call(req);

        Box::pin(async move {
            match fut.await {
                Ok(res) => Ok(CorsResponseContext::from_request_head(
                    &inner,
                    res.request().head(),
                    origin_allowed,
                )
                .into_service_response(res)
                .map_into_left_body()),
                Err(err) => Err(CorsServiceError {
                    inner: err,
                    context: error_context,
                }
                .into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        dev::Transform,
        middleware::Compat,
        test::{self, TestRequest},
        App,
    };

    use super::*;
    use crate::Cors;

    #[test]
    fn compat_compat() {
        let _ = App::new().wrap(Compat::new(Cors::default()));
    }

    #[actix_web::test]
    async fn test_options_no_origin() {
        // Tests case where allowed_origins is All but there are validate functions to run in case.
        // In this case, origins are only allowed when the DNT header is sent.

        let cors = Cors::default()
            .allow_any_origin()
            .allowed_origin_fn(|origin, req_head| {
                assert_eq!(&origin, req_head.headers.get(header::ORIGIN).unwrap());
                req_head.headers().contains_key(header::DNT)
            })
            .new_transform(test::ok_service())
            .await
            .unwrap();

        let req = TestRequest::get()
            .insert_header((header::ORIGIN, "http://example.com"))
            .to_srv_request();
        let res = cors.call(req).await.unwrap();
        assert_eq!(
            None,
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(HeaderValue::as_bytes)
        );

        let req = TestRequest::get()
            .insert_header((header::ORIGIN, "http://example.com"))
            .insert_header((header::DNT, "1"))
            .to_srv_request();
        let res = cors.call(req).await.unwrap();
        assert_eq!(
            Some(&b"http://example.com"[..]),
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(HeaderValue::as_bytes)
        );
    }
}
