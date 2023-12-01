use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};

use actix_web::{dev::ServiceRequest, error::Error, web, HttpMessage};
use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
    middleware::HttpAuthentication,
};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Mutex;
use uuid::Uuid;

mod auth;
use auth::{
    models::User,
    services::{basic_auth, create_user},
};

mod todolist;
use todolist::services;

struct AppState {
    users: Mutex<Vec<User>>, // <- Mutex is necessary to mutate safely across threads
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    id: Uuid,
}

async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    // Grab the JWT secret from the .env file
    let jwt_secret: String = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set!");

    // Build key to verify integrity of the token
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();
    let token_string = credentials.token();

    // Verify the token
    let claims: Result<TokenClaims, &str> = token_string
        .verify_with_key(&key)
        .map_err(|_| "Invalid token");

    match claims {
        Ok(value) => {
            // If token is verified, continue the request chain
            req.extensions_mut().insert(value);
            Ok(req)
        }
        Err(_) => {
            // If token is not verified, return an error
            let config = req
                .app_data::<bearer::Config>()
                .cloned()
                .unwrap_or_default()
                .scope("");

            Err((AuthenticationError::from(config).into(), req))
        }
    }
}

#[get("/")] // GET method for the "/" path
async fn index() -> impl Responder {
    HttpResponse::Ok().json("{ status: OK }")
}

// This tells our program to utilize the actix_web runtime
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    HttpServer::new(move || {
        // Build middleware for JWT validation
        let bearer_middleware = HttpAuthentication::bearer(validator);

        App::new()
            .app_data(Data::new(AppState {
                users: Mutex::new(vec![]),
            }))
            .service(index)
            .service(basic_auth)
            .service(create_user)
            .service(
                // Wrap the services in the middleware
                web::scope("")
                    .wrap(bearer_middleware)
                    .configure(services::config),
            )
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
