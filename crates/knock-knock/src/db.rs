use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub async fn connect(url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
}

pub fn hash_token(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    hex::encode(b)
}
