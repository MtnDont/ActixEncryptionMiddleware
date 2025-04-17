#![allow(dead_code)]

use actix_web:: {
    body::{self, MessageBody},
    dev::{self, ServiceResponse},
    middleware::Next,
    Error
};
//use actix_web_lab::middleware::Next;

pub async fn encrypt_payloads(
    req: dev::ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<dev::ServiceResponse<impl MessageBody>, Error> {
    // get cipher from app data
    //let cipher = req.extract::<web::Data<Aes256GcmSiv>>().await.unwrap();

    // call next service
    let res = next.call(req).await?;

    //log::info!("encrypting response {id:?}");

    // deconstruct response into parts
    let (req, res) = res.into_parts();
    let (res, body) = res.into_parts();

    // Read all bytes out of response stream. Only use `to_bytes` if you can guarantee all handlers
    // wrapped by this middleware return complete responses or bounded streams.
    let body = body::to_bytes(body).await.ok().unwrap();

    // set response body as new JSON payload and re-combine response object
    let res = res.set_body(body);
    let res = ServiceResponse::new(req, res);

    Ok(res)
}