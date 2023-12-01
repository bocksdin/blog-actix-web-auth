// Actix Web
use actix_web::{
    get, post,
    web::{Data, Json},
    HttpResponse, Responder,
};

// Auth extractors
use actix_web_httpauth::extractors::basic::BasicAuth;

// JWT
use jwt::SignWithKey;

// Password hashing
use argonautica::{Hasher, Verifier};
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Other
use uuid::Uuid;

// Structs from src/main.rs
use crate::{AppState, TokenClaims};

// Structs from src/auth/models.rs
use super::models::{CreateUserBody, User};

#[post("/user")]
async fn create_user(state: Data<AppState>, body: Json<CreateUserBody>) -> impl Responder {
    // Grab the body of the request
    let user: CreateUserBody = body.into_inner();

    // Hash the password
    let hash_secret = std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
    let mut hasher = Hasher::default();
    let hashed_password = hasher
        .with_password(user.password)
        .with_secret_key(hash_secret)
        .hash()
        .unwrap();

    // Create a new user
    let new_user = User {
        id: Uuid::new_v4(),
        username: user.username,
        password: hashed_password,
    };

    // Add the user to the list of users
    state.users.lock().unwrap().push(new_user.clone());

    // Return the new user
    HttpResponse::Ok().json(new_user)
}

#[get("/login")]
async fn basic_auth(state: Data<AppState>, credentials: BasicAuth) -> impl Responder {
    // Grab the JWT secret from the .env file
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(
        std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set!")
            .as_bytes(),
    )
    .unwrap();

    // Grab the username and password from the request's Authorization header
    let username = credentials.user_id();
    let password = credentials.password();

    match password {
        None => HttpResponse::Unauthorized().json("Must provide username and password"),
        Some(pass) => {
            // Find the user in the AppState
            match state
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|user| user.username == username)
            {
                Some(user) => {
                    // Verify the password sent matches the hashed password
                    let hash_secret =
                        std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
                    let mut verifier = Verifier::default();
                    let password_is_valid = verifier
                        .with_hash(&user.password)
                        .with_password(pass)
                        .with_secret_key(hash_secret)
                        .verify()
                        .unwrap();

                    if password_is_valid {
                        // If the password is valid, return a JWT
                        let claims = TokenClaims { id: user.id };
                        let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                        HttpResponse::Ok().json(token_str)
                    } else {
                        // If the password is invalid, return an error
                        HttpResponse::Unauthorized().json("Incorrect password")
                    }
                }
                None => HttpResponse::Unauthorized().json("User does not exist"),
            }
        }
    }
}
