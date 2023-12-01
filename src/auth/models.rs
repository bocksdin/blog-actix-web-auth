use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Uuid,         // 123e4567-e89b-12d3-a456-426614174000
    pub username: String, // johndoe123
    pub password: String, // Hashed password123
}

#[derive(Deserialize)]
pub struct CreateUserBody {
    pub username: String, // johndoe123
    pub password: String, // password123
}
