use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufReader};
use std::io::ErrorKind::NotFound;
use std::net::SocketAddr;
use std::ops::Deref;
use hyper::body::{Bytes, Incoming};
use std::path::Path;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
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
use log::{error, info, LevelFilter};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer};
use rustls_pemfile::{certs, private_key};
use simplelog::{ColorChoice, CombinedLogger, TermLogger, TerminalMode};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SslConfig {
    #[serde(rename = "cert")]
    cert_path: String,
    #[serde(rename = "privateKey")]
    key_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    bind: String,
    #[serde(rename = "auth")]
    own_api_key: String,
    servers: HashMap<String, String>,
    #[serde(rename = "extraHeaders")]
    extra_headers: HashMap<String, String>,
    ssl: Option<SslConfig>
}

impl Default for Config {
    fn default() -> Self {
        let mut map = HashMap::new();
        map.insert(String::from("prod1"), String::from("https://localhost:8443/api/servers/server-id"));
        Config {
            bind: "127.0.0.1:3000".into(),
            own_api_key: "EMPTY".into(),
            servers: map,
            extra_headers: HashMap::new(),
            ssl: None
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

async fn wrap(req: Request<Incoming>, sock: Arc<SocketAddr>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().path().to_string();
    let res = handle(req).await;
    match &res {
        Ok(r) => {
            info!("{} {} {} -> {}", sock, method, uri, r.status().to_string());
        },
        Err(e) => {
            error!("{} {} {} -> {}", sock, method, uri, e.to_string())
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
    match &CONFIG.ssl {
        Some(ssl) => {
            info!("Loading SSL config");
            let tls_config = load_tls_config(ssl).expect("Failed to load TLS");
            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
            info!("Listening at https://{}", &addr);
            loop {
                let (stream, sock) = listener.accept().await?;
                let tls_acceptor = tls_acceptor.clone();
                let socket_addr = Arc::new(sock);
                tokio::task::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service_fn(|req| wrap(req, socket_addr.clone())))
                                .await
                            {
                                error!("Error serving HTTPS connection: {:?} for {}", err, socket_addr);
                            }
                        }
                        Err(e) => {
                            error!("TLS handshake failed: {:?} from {}", e, socket_addr);
                        }
                    }
                });
            }
        },
        None => {
            info!("Listening at http://{}", &addr);

            loop {
                let (stream, sock) = listener.accept().await?;
                let socket_addr = Arc::new(sock);
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(|req| wrap(req, socket_addr.clone())))
                        .await
                    {
                        error!("Error serving connection: {:?} for {}", err, socket_addr);
                    }
                });
            }
        }
    };

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

fn load_tls_config(ssl_config: &SslConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = &mut BufReader::new(File::open(&ssl_config.cert_path)?);
    let key_file = &mut BufReader::new(File::open(&ssl_config.key_path)?);

    let certs: Vec<CertificateDer<'static>> = certs(cert_file)
        .into_iter()
        .map(|res| CertificateDer::from(res.expect(&format!("Failed to read certificate {}", &ssl_config.cert_path))))
        .collect();

    let key = match private_key(key_file)? {
        Some(k) => k,
        None => return Err(Box::from(std::io::Error::new(NotFound, "Key not found")))
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}