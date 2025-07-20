use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use hyper::body::{Bytes, Incoming};
use std::path::Path;
use std::process::exit;
use std::str::FromStr;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri};
use hyper::service::service_fn;
use hyper_rustls::{HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use lazy_static::lazy_static;
use tokio::net::{TcpListener};
use log::{debug, error, info, LevelFilter};
use simplelog::{ColorChoice, CombinedLogger, TermLogger, TerminalMode};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    bind: String,
    #[serde(rename = "auth")]
    own_api_key: String,
    servers: HashMap<String, String>,
    #[serde(rename = "extraHeaders")]
    extra_headers: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut map = HashMap::new();
        map.insert(String::from("prod1"), String::from("https://localhost:8443/api/servers/server-id"));
        Config {
            bind: "127.0.0.1:3000".into(),
            own_api_key: "EMPTY".into(),
            servers: map,
            extra_headers: HashMap::new()
        }
    }
}

async fn handle(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let headers = req.headers();
    let authorization = match headers.get("Authorization") {
        Some(o) => o.to_str().unwrap_or(""),
        None => return Ok(response_with_status(StatusCode::UNAUTHORIZED, "Authorization header not found"))
    };

    let request_server = match headers.get("X-Request-Server") {
        Some(o) => o.to_str().unwrap_or(""),
        None => return Ok(response_with_status(StatusCode::BAD_REQUEST, "Invalid server"))
    };

    if authorization != CONFIG.own_api_key {
        return Ok(response_with_status(StatusCode::FORBIDDEN, "Invalid authorization"));
    }

    let url = match CONFIG.servers.get(request_server) {
        Some(o) => o,
        None => return Ok(response_with_status(StatusCode::BAD_REQUEST, "Server not found"))
    };

    let path = req.uri().path();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    // much faster way to concat a string
    let mut request_path = String::with_capacity(path.len() + url.len() + query.len());
    request_path.push_str(url);
    request_path.push_str(path);
    request_path.push_str(&query);

    let target_uri = match Uri::from_str(&request_path) {
        Ok(u) => u,
        Err(e) => return Ok(response_with_status(StatusCode::INTERNAL_SERVER_ERROR, &format!("Invalid URI: {}", e)))
    };

    let (parts, body) = req.into_parts();
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(target_uri);
    let mut found_server = false;
    for (name, value) in parts.headers.iter() {
        let val = name.to_string().to_lowercase();
        if CONFIG.extra_headers.contains_key(&val) {
            continue;
        }
        if !found_server && val == "x-request-server" {
            found_server = true;
            continue;
        }
        builder = builder.header(val, value)
    }

    for header in &CONFIG.extra_headers {
        builder = builder.header(header.0, header.1);
    }

    let proxy_req = match builder.body(body) {
        Ok(req) => req,
        Err(e) => return Ok(response_with_status(StatusCode::BAD_GATEWAY, e.to_string().as_str()))
    };

    let resp = match HTTP_CLIENT.request(proxy_req).await {
        Ok(o) => o,
        Err(e) => return Ok(response_with_status(StatusCode::BAD_GATEWAY, e.to_string().as_str()))
    };

    Ok(resp.map(|b| b.boxed())) // stream response
}

async fn wrap(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().path().to_string();
    let res = handle(req).await;
    match &res {
        Ok(r) => {
            info!("{} {} -> {}", method, uri, r.status().to_string());
        },
        Err(e) => {
            error!("{} {} -> {}",  method, uri, e.to_string())
        }
    }

    res
}

fn response_with_status(status: StatusCode, content: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from(content.to_string()))
        .map_err(|never| match never {})
        .boxed();

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

lazy_static! {
    static ref CONFIG: Config = load_config().expect("Failed to load configuration");
    static ref HTTP_CLIENT: Client<HttpsConnector<HttpConnector>, Incoming> = {
        let https = HttpsConnector::<HttpConnector>::builder()
            .with_webpki_roots()
            .https_or_http()
            .enable_http2()
            .build();
        Client::builder(TokioExecutor::new()).build(https)
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed, ColorChoice::Always),
        ]
    ).unwrap();

    let addr = SocketAddr::from_str(CONFIG.bind.as_str()).expect(format!("Invalid bind: {}", CONFIG.bind).as_str());

    let listener = TcpListener::bind(addr).await?;
    info!("Listening at {}", addr.to_string());

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(wrap))
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = Path::new("config.toml");
    if !path.exists() {
        let parent = path.parent().unwrap();
        if !parent.exists() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, toml::to_string_pretty(&Config::default()).unwrap()).expect("Could not write default config");
        println!("This is your first time running this. Please configure config.toml");
        exit(0);
    }
    let config_content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(config_content.as_str())?;
    if config.own_api_key == "EMPTY" {
        println!("This is your first time running this. Please configure config.toml");
        exit(0);
    }
    let mut new_map = HashMap::<String, String>::new();
    for header in config.extra_headers {
        new_map.insert(header.0.to_lowercase(), header.1);
    }
    config.extra_headers = new_map;
    Ok(config)
}