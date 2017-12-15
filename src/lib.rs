extern crate log;
extern crate reqwest;
extern crate backtrace;
extern crate time;
extern crate url;
#[macro_use] extern crate hyper;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;

use std::sync::Arc;
use std::default::Default;
use std::collections::HashMap;
use failure::Error;

use reqwest::header::{ContentType, ContentLength};
use reqwest::Url;

#[derive(Debug, Fail)]
#[fail(display = "Invalid Sentry DSN syntax.")]
pub struct CredentialParseError;


#[derive(Debug, Clone, Serialize)]
pub struct StackFrame {
    filename: String,
    function: String,
    lineno: u32,
}

// see https://docs.getsentry.com/hosted/clientdev/attributes/
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    // required
    event_id: String,
    // uuid4 exactly 32 characters (no dashes!)
    message: String,
    // Maximum length is 1000 characters.
    timestamp: String,
    // ISO 8601 format, without a timezone ex: "2011-05-02T17:41:36"
    level: String,
    // fatal, error, warning, info, debug
    logger: String,
    // ex "my.logger.name"
    platform: String,
    // Acceptable values ..., other
    sdk: SDK,
    device: Device,
    // optional
    culprit: Option<String>,
    // the primary perpetrator of this event ex: "my.module.function_name"
    server_name: Option<String>,
    // host client from which the event was recorded
    stack_trace: Option<Vec<StackFrame>>,
    // stack trace
    release: Option<String>,
    // generally be something along the lines of the git SHA for the given project
    tags: HashMap<String, String>,
    // WARNING! should be serialized as json object k->v
    environment: Option<String>,
    // ex: "production"
    modules: HashMap<String, String>,
    // WARNING! should be serialized as json object k->v
    extra: HashMap<String, String>,
    // WARNING! should be serialized as json object k->v
    fingerprint: Vec<String>, // An array of strings used to dictate the deduplicating for this event.
}

impl Event {
    pub fn new(
        logger: &str,
        level: &str,
        message: &str,
        device: &Device,
        culprit: Option<&str>,
        fingerprint: Option<Vec<String>>,
        server_name: Option<&str>,
        stack_trace: Option<Vec<StackFrame>>,
        release: Option<&str>,
        environment: Option<&str>,
        tags: Option<HashMap<String, String>>,
        extra: Option<HashMap<String, String>>,
    ) -> Event {
        Event {
            event_id: "".to_owned(),
            message: message.to_owned(),
            timestamp: time::strftime("%FT%T", &time::now().to_utc()).unwrap_or("".to_owned()),
            level: level.to_owned(),
            logger: logger.to_owned(),
            platform: "other".to_owned(),
            sdk: SDK {
                name: "rust-sentry".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            device: device.to_owned(),
            culprit: culprit.map(|c| c.to_owned()),
            server_name: server_name.map(|c| c.to_owned()),
            stack_trace,
            release: release.map(|c| c.to_owned()),
            tags: tags.unwrap_or(Default::default()),
            environment: environment.map(|c| c.to_owned()),
            modules: Default::default(),
            extra: extra.unwrap_or_else(|| Default::default()),
            fingerprint: fingerprint.unwrap_or(vec![]),
        }
    }

    pub fn push_tag(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SDK {
    name: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Device {
    name: String,
    version: String,
    build: String,
}

impl Device {
    pub fn new(name: String, version: String, build: String) -> Device {
        Device {
            name: name,
            version: version,
            build: build,
        }
    }
}

impl Default for Device {
    fn default() -> Device {
        Device {
            name: std::env::var_os("OSTYPE")
                .and_then(|cs| cs.into_string().ok())
                .unwrap_or("".to_owned()),
            version: "".to_owned(),
            build: "".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentryCredential {
    scheme: String,
    key: String,
    secret: String,
    host: String,
    port: u16,
    project_id: String,

    uri: Url,
}


// FIXME take care of unwrap()...
impl std::str::FromStr for SentryCredential {
    type Err = CredentialParseError;
    fn from_str(s: &str) -> std::result::Result<SentryCredential, CredentialParseError> {
        let url = Url::parse(s).unwrap();

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(CredentialParseError)
        }

        let host = url.host_str().unwrap();
        let port = url.port().unwrap_or_else(
            || if scheme == "http" { 80 } else { 443 },
        );

        let key = url.username();
        let secret = url.password().unwrap();

        let project_id = url.path_segments().and_then(|paths| paths.last()).unwrap();

        if key.is_empty() || project_id.is_empty() {
            return Err(CredentialParseError)
        }

        let uri_str = format!(
            "{}://{}:{}@{}:{}/api/{}/store/",
            scheme,
            key,
            secret,
            host,
            port,
            project_id
        );
        let uri = uri_str.parse().unwrap();

        Ok(SentryCredential {
            scheme: scheme.to_owned(),
            key: key.to_owned(),
            secret: secret.to_owned(),
            host: host.to_owned(),
            port,
            project_id: project_id.to_owned(),

            uri,
        })
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct Settings {
    pub server_name: String,
    pub release: String,
    pub environment: String,
    pub device: Device,
}

impl Settings {
    pub fn new(
        server_name: String,
        release: String,
        environment: String,
        device: Device,
    ) -> Settings {
        Settings {
            server_name: server_name,
            release: release,
            environment: environment,
            device: device,
        }
    }
}

header! { (XSentryAuth, "X-Sentry-Auth") => [String] }

#[derive(Clone)]
pub struct Sentry {
    //    remote: Remote,
    credential: Arc<SentryCredential>,
    settings: Arc<Settings>,
}

impl Sentry {
    pub fn new(
//        handle: Handle,
server_name: String,
release: String,
environment: String,
credential: SentryCredential,
    ) -> Sentry {
        let settings = Settings {
            server_name: server_name,
            release: release,
            environment: environment,
            ..Settings::default()
        };

        Sentry::from_settings(settings, credential)
    }

    pub fn from_settings(
//        handle: Handle,
settings: Settings,
credential: SentryCredential,
    ) -> Sentry {
        Sentry {
//            remote: handle.remote().clone(),
            credential: Arc::new(credential),
            settings: Arc::new(settings),
        }
    }

    pub fn log_event(&self, e: Event) {
        let cred = self.credential.clone();
        let _  = post(&cred, e);
    }

    pub fn register_panic_handler<F>(&self, maybe_f: Option<F>)
        where
            F: Fn(&std::panic::PanicInfo) + 'static + Sync + Send,
    {
        let cred = self.credential.clone();
        let settings = self.settings.clone();
//        let remote = self.remote.clone();
        std::panic::set_hook(Box::new(move |info: &std::panic::PanicInfo| {
            let location = info.location()
                .map(|l| format!("{}: {}", l.file(), l.line()))
                .unwrap_or("NA".to_owned());
            let msg = match info.payload().downcast_ref::<&'static str>() {
                Some(s) => *s,
                None => {
                    match info.payload().downcast_ref::<String>() {
                        Some(s) => &s[..],
                        None => "Box<Any>",
                    }
                }
            };

            let mut frames = vec![];
            backtrace::trace(|frame: &backtrace::Frame| {
                backtrace::resolve(frame.ip(), |symbol| {
                    let name = symbol.name().map_or(
                        "unresolved symbol".to_owned(),
                        |name| name.to_string(),
                    );
                    let filename = symbol.filename().map_or("".to_owned(), |sym| {
                        sym.to_string_lossy().into_owned()
                    });
                    let lineno = symbol.lineno().unwrap_or(0);
                    frames.push(StackFrame {
                        filename: filename,
                        function: name,
                        lineno: lineno,
                    });
                });

                true // keep going to the next frame
            });

            let e = Event::new(
                "panic",
                "fatal",
                msg,
                &settings.device,
                Some(&location),
                None,
                Some(&settings.server_name),
                Some(frames),
                Some(&settings.release),
                Some(&settings.environment),
                None,
                None,
            );
            if let Some(ref f) = maybe_f {
                f(info);
            }
            let cred = cred.clone();
            let _ = post(&cred, e);
        }));
    }

    pub fn unregister_panic_handler(&self) {
        let _ = std::panic::take_hook();
    }

    // fatal, error, warning, info, debug
    pub fn fatal(&self, logger: &str, message: &str, culprit: Option<&str>) {
        self.log(logger, "fatal", message, culprit, None, None, None);
    }
    pub fn error(&self, logger: &str, message: &str, culprit: Option<&str>) {
        self.log(logger, "error", message, culprit, None, None, None);
    }
    pub fn warning(&self, logger: &str, message: &str, culprit: Option<&str>) {
        self.log(logger, "warning", message, culprit, None, None, None);
    }
    pub fn info(&self, logger: &str, message: &str, culprit: Option<&str>) {
        self.log(logger, "info", message, culprit, None, None, None);
    }
    pub fn debug(&self, logger: &str, message: &str, culprit: Option<&str>) {
        self.log(logger, "debug", message, culprit, None, None, None);
    }

    pub fn log(
        &self,
        logger: &str,
        level: &str,
        message: &str,
        culprit: Option<&str>,
        fingerprint: Option<Vec<String>>,
        tags: Option<HashMap<String, String>>,
        extra: Option<HashMap<String, String>>,
    ) {
        let fpr = match fingerprint {
            Some(f) => f,
            None => {
                vec![
                    logger.to_owned(),
                    level.to_owned(),
                    culprit.unwrap_or("").to_owned(),
                ]
            }
        };
        let settings = self.settings.clone();
        let e = Event::new(
            logger,
            level,
            message,
            &settings.device,
            culprit,
            Some(fpr),
            Some(&settings.server_name),
            None,
            Some(&settings.release),
            Some(&settings.environment),
            tags,
            extra,
        );
        self.log_event(e)
    }
}

fn post(cred: &SentryCredential, e: Event) -> Result<(), Error> {
//    let mut req = reqwest::Request::new(hyper::Method::Post, cred.uri().clone());
    let body = serde_json::to_string(&e).map_err(Error::from)?;
    let mut  headers = reqwest::header::Headers::new();

    // X-Sentry-Auth: Sentry sentry_version=7,
    // sentry_client=<client version, arbitrary>,
    // sentry_timestamp=<current timestamp>,
    // sentry_key=<public api key>,
    // sentry_secret=<secret api key>
    //
    let timestamp = time::get_time().sec.to_string();
    let xsentryauth = format!(
        "Sentry sentry_version=7,sentry_client=rust-sentry/{},sentry_timestamp={},sentry_key={},sentry_secret={}",
        env!("CARGO_PKG_VERSION"),
        timestamp,
        cred.key,
        cred.secret
    );
    headers.set(XSentryAuth(xsentryauth));
    headers.set(ContentType::json());
    headers.set(ContentLength(body.len() as u64));

    let client = reqwest::Client::new();
    let _ = client.post(cred.uri.as_ref()).headers(headers).body(body).send().unwrap();

    Ok(())
}

