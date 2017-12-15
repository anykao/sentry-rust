extern crate sentry;
extern crate dotenv;

use std::env;
use dotenv::dotenv;

use std::default::Default;
use sentry::{Sentry, SentryCredential};


fn main() {
    dotenv().ok();
    match env::var("SENTRY_DSN") {
        Ok(sentry_dsn) => {
            print!("{}", sentry_dsn);
            let credential = sentry_dsn
                .parse::<SentryCredential>()
                .unwrap();
            let sentry = Sentry::from_settings(Default::default(), credential);
            sentry.info("test.logger", "new Message", None);
        }

        Err(_) => print!("cannot read `SENTRY_DSN` from .env file."),
    }
}

