use actix_files::NamedFile;
use actix_web::middleware::Logger;
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
//use actix_web::middleware::from_fn;

mod encryption_middleware;
mod encrypt_res;
mod read_response_body;
mod file_manage;
mod keyset;

/// Takes a `Path` and file name and returns data in that file
///
/// Strips attempts to go to previous directories
#[get("/{path:[^{}]+}/{filename:.*}")]
async fn file_index(req: HttpRequest, param: web::Path<(String, String)>) -> impl Responder {
    // Parse parameters
    let path_arg = &param.0;
    let filename_arg = &param.1;
    println!("path_arg: {}\nfilename_arg: {}", path_arg.to_string(), filename_arg.to_string());
    
    let pathbuf = if let Some(parsed_path) = file_manage::parse_path(path_arg.to_string(), Some(filename_arg.to_string())) {
            parsed_path
        } else {
            return HttpResponse::BadRequest().body("Bad path token.");
        };
    let path = pathbuf.as_path();

    // Return file by converting into HttpResponse
    let file = NamedFile::open_async(path).await.unwrap();
    file.into_response(&req)
}

/// Takes a `Path` and returns files in that directory.
///
/// Strips attempts to go to previous directories.
#[get("/{path}/")]
async fn path_req_index(path: web::Path<String>) -> impl Responder {
    let pathbuf = if let Some(parsed_path) = file_manage::parse_path(path.into_inner(), None) {
        parsed_path
    } else {
        return HttpResponse::BadRequest().body("Bad path token.");
    };
    let path = pathbuf.as_path();

    println!("{:?}", path.display().to_string());
    println!("absolute: {}", path.is_absolute());
    //println!("{path_req:?}");

    if !path.is_dir() {
        return HttpResponse::BadRequest().body("Path does not exist.");
    }

    HttpResponse::Ok().json(file_manage::list_dir(Some(path)))
}

#[get("/thumb")]
async fn test() -> HttpResponse {
    let thumbnail = file_manage::create_thumb("bunger/20230114_154037.jpg");
    let thumb_data = thumbnail.into_inner();
    //let thumb_data: &[u8] = &thumbnail.get_ref();
    //let mut thumb_data = String::new();
    //thumbnail.read_to_string(&mut thumb_data);
    HttpResponse::Ok().body(thumb_data)
}

#[post("/pj")]
async fn path_index(file_req: web::Json<file_manage::FileReq>) -> impl Responder {
    let path_req = file_req.into_inner().path.clone();
    println!("{:?}", path_req);
    let pathbuf = if let Some(parsed_path) = file_manage::parse_path(path_req, None) {
        parsed_path
    } else {
        println!("parsed_path 400");
        return HttpResponse::BadRequest().body("Bad path token.");
    };
    let path = pathbuf.as_path();

    if !path.is_dir() {
        return HttpResponse::BadRequest().body("Path does not exist.");
    }

    HttpResponse::Ok().json(file_manage::list_dir(Some(path)))
}

/// Takes a `Path` and file name and returns data in that file
///
/// Strips attempts to go to previous directories
#[post("/pf")]
async fn file_json_index(req: HttpRequest, file_req: web::Json<file_manage::FileReq>) -> impl Responder {
    // Parse parameters
    let json_request = file_req.into_inner();
    
    let path_arg = json_request.path.clone();
    let filename_arg = if let Some(filename) = json_request.filename.clone() {
        filename
    } else {
        return HttpResponse::BadRequest().body("Bad request.");
    };
    println!("path_arg: {}\nfilename_arg: {}", path_arg.to_string(), filename_arg.to_string());
    
    let pathbuf = if let Some(parsed_path) = file_manage::parse_path(path_arg.to_string(), Some(filename_arg.to_string())) {
            parsed_path
        } else {
            return HttpResponse::BadRequest().body("Bad path token.");
        };
    let path = pathbuf.as_path();

    // Return file by converting into HttpResponse
    let file = NamedFile::open_async(path).await;//.unwrap();
    let file = match file {
        Ok(f) => f,
        Err(_) => {
            return HttpResponse::ImATeapot().body("Oops (:");
        },
    };

    file.into_response(&req)
}

#[get("/")]
async fn index() -> impl Responder {
    //HttpResponse::Ok().json(file_manage::list_dir(None))
    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    env_logger::init();

    println!(env!("startup_msg"));

    HttpServer::new(|| {
        App::new()
            .service(index)
            //.service(path_req_index) // Path in URL
            .service(path_index) // Path in JSON
            //.service(file_index) // Path and filename in URL
            .service(file_json_index) // Path and filename in JSON
            .service(test)
            .wrap(Logger::default())
            
            //.wrap(encryption_middleware::E2E) // Enforces request end of end-to-end encryption
            .wrap(read_response_body::EncryptedResponse) // Enforces response end of end-to-end encryption
            
            //.wrap(from_fn(encrypt_res::encrypt_payloads))
    })
    .bind(("127.0.0.1", 25507))?
    .run()
    .await
}