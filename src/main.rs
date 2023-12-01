use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};

// Actix Web
use actix_web::{dev::ServiceRequest, error::Error, web, HttpMessage};

// Auth Extractors and Middleware
use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
    middleware::HttpAuthentication,
};

// Json Web Token
use jwt::VerifyWithKey;

// Password Hashing
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Other
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
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

// Structure of the data contained in the JWT
#[derive(Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    id: Uuid,
}

// Middleware for JWT validation
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
            // Routes outside the Bearer token middleware
            .service(index)
            .service(basic_auth)
            .service(create_user)
            .service(
                // Define a new scope to add middleware
                // This string is located in between the base (http://localhost:8080/) and your endpoints (/create-todolist-entry, /get-todolist-entries, etc.)
                // Ex. http://localhost:8080/v1/create-todolist-entry
                web::scope("") // http://localhost:8080/<endpoint name>
                    // Utilize the Bearer middleware
                    .wrap(bearer_middleware)
                    // Routes requiring a Bearer token
                    .configure(services::config),
            )
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
