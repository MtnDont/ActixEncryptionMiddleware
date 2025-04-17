use regex::Regex;
use std::cmp::Ordering;
use std::{fs, time};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::io::{BufReader, Cursor, Seek, SeekFrom};
use thumbnailer::{create_thumbnails, ThumbnailSize};
use serde::{Deserialize, Serialize};

const ROOT_DIR: &str = env!("root_path");

#[derive(Serialize)]
pub struct FileDesc {
    filename: String,
    is_dir: bool,
    location: String,
    size: u64,
    created: u64,
    modified: i64
}

#[derive(Deserialize, Serialize)]
pub struct FileReq {
    pub path: String,
    pub filename: Option<String>
}

#[allow(dead_code)]
impl FileReq {
    /*pub fn get_path(self) -> String {
        self.path
    }

    pub fn get_filename(self) -> Option<String> {
        self.filename
    }*/
    pub fn json(self) -> String {
        match self.filename {
            Some(n) => format!("{{\"path\":\"{0}\",\"filename\":\"{n}\"}}", self.path),
            None => format!("{{\"path\":\"{0}\"}}", self.path)
        }
    }
}

pub fn parse_path(path_arg: String, file_arg: Option<String>) -> Option<PathBuf> {
    let re = Regex::new(r"^[\\/]?((?:[^\t\n\v\f\r\\/]+)(?:[\\/][^\t\n\v\f\r\\/]+)*)?[\\/]?$$").unwrap();
    let cap = match re.captures(path_arg.as_str()) {
        Some(caps) => caps,
        None => {
            return None;
        }
    };
    let path_req: String = if let Some(file) = file_arg {
            match cap.get(1) {
                Some(i) => format!("{}{}/{}", ROOT_DIR, i.as_str(), file),
                None => format!("{}{}", ROOT_DIR, file)
            }
        } else {
            match cap.get(1) {
                Some(i) => format!("{}{}/", ROOT_DIR, i.as_str()),
                None => ROOT_DIR.to_string()
            }
        };
    if path_req.contains("/../") {
        return None;
    }
    Some(Path::new(&path_req).to_path_buf())
}

pub fn parse_path_unrestricted(path_arg: String, file_arg: Option<String>) -> Option<PathBuf> {
    let path_req: String = if let Some(file) = file_arg {
            format!("{}/{}", path_arg, file)
        } else {
            format!("{}/", path_arg)
        };
    if path_req.contains("/../") {
        return None;
    }
    Some(Path::new(&path_req).to_path_buf())
}

pub fn list_dir(path_arg: Option<&Path>) -> Vec<FileDesc> {
    let dir_entries = if let Some(path) = path_arg {
            path.read_dir().unwrap()
        } else {
            fs::read_dir(ROOT_DIR).unwrap()
        };
    let mut files: Vec<FileDesc> = Vec::new();

    for dir_entry in dir_entries {
        // Get unwrap dir_entry so to get values from result once
        // and reference from there
        let entry = dir_entry.unwrap();
        let path = entry.path();
        let parent_path = path.parent().unwrap();
        let parent_path_str = if Path::new(ROOT_DIR).cmp(parent_path) == Ordering::Equal {
            "/".to_string()
        } else {
            parent_path.to_string_lossy().to_string().replacen(ROOT_DIR, "", 1)
        };
        let metadata = path.metadata().unwrap();

        if metadata.is_symlink() { continue; }
        
        files.push(
            FileDesc {
                filename: entry.file_name().into_string().unwrap(),
                is_dir: path.is_dir(),
                location: parent_path_str,
                size: metadata.st_size(),
                created: if let Ok(time) = metadata.created() {
                    time.duration_since(time::UNIX_EPOCH).expect("").as_secs()
                } else {
                    0
                },
                modified: metadata.st_mtime()
            }
        );
    }

    files.sort_by(|a,b| {
        match b.is_dir.cmp(&a.is_dir) {
            Ordering::Equal => a.filename.cmp(&b.filename),
            other => other
        }
    });

    files
}

pub fn create_thumb(file_str: &str) -> Cursor<Vec<u8>> {
    let file = fs::File::open(file_str).unwrap();

    let f_meta = file.metadata().unwrap().file_type();
    println!("{:?}", f_meta);

    let reader = BufReader::new(file);

    let mut thumbnails = create_thumbnails(reader, mime::IMAGE_JPEG, [ThumbnailSize::Larger]).unwrap();

    let thumbnail = thumbnails.pop().unwrap();
    let mut buf = Cursor::new(Vec::new());

    thumbnail.write_jpeg(&mut buf, 32).unwrap();

    buf.seek(SeekFrom::Start(0)).unwrap();
    buf
}