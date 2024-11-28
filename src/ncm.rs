pub fn apply(input: String, output: String) {
    if let Err(error) = unboxing(input, output) {
        eprintln!("Error: {}", error);
    };
}

fn pre_opt(input: String, output: String) -> anyhow::Result<(PathBuf, PathBuf)> {
    let input = PathBuf::from(input);

    let output = PathBuf::from(output);

    if !input.exists() {
        bail!("input: {:?} does not exist", input);
    }

    if input.is_dir() {
        bail!("input: {:?} is a directory", input);
    }

    if output.exists() && output.is_file() {
        bail!("output: {:?} is a file", input);
    }

    if !output.exists() {
        fs::create_dir_all(&output)?;
    }

    return Ok((input, output));
}
fn unboxing(input: String, output: String) -> anyhow::Result<()> {
    let (input, output) = pre_opt(input, output)?;

    let mut input_file = File::open(&input)?;

    magic_header(&mut input_file)?;

    let key = cr4key(&mut input_file)?;

    let meta = meta_data(&mut input_file)?;

    let image = album_image(&mut input_file)?;

    let artist = &meta.artist
        .iter()
        .map(|item| item.get(0))
        .filter(Option::is_some)
        .map(Option::unwrap)
        .map(Value::as_str)
        .filter(Option::is_some)
        .map(Option::unwrap)
        .map(String::from)
        .collect::<Vec<String>>()
        .join(",");

    let output = output.join(format!("{} - {}.{}", &meta.music_name, artist, &meta.format));

    let mut output_file = File::create(&output)?;

    music_data(&mut input_file, &mut output_file, key)?;

    combine_file(meta, &output, image)?;

    drop(output_file);

    drop(input_file);

    return Ok(());
}

use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

fn magic_header(file: &mut File) -> Result<(), std::io::Error> {
    file.seek(SeekFrom::Current(10))?;
    return Ok(());
}

fn cr4key(file: &mut File) -> anyhow::Result<Vec<u8>> {
    let mut buffer = [0u8; 4];

    file.read(&mut buffer)?;

    let len = get_length(&buffer);

    let mut buffer = vec![0u8; len as usize];

    file.read(&mut buffer)?;

    for i in 0..len {
        buffer[i as usize] ^= 0x64;
    }

    let bytes = aes_decode(buffer.clone(), CODE_KEY)?;

    let temp = Vec::from(bytes);

    return Ok(Vec::from(&temp[17..]));
}

fn meta_data(file: &mut File) -> anyhow::Result<Meta> {
    let mut buffer = [0u8; 4];

    file.read(&mut buffer)?;

    let len = get_length(&buffer);

    let mut buffer = vec![0u8; len as usize];

    file.read(&mut buffer)?;

    file.seek(SeekFrom::Current(9))?;

    for i in 0..len {
        buffer[i as usize] ^= 0x63;
    }

    let temp = buffer[22..].to_vec();

    let temp = base64::prelude::BASE64_STANDARD.decode(&temp)?;

    let temp = aes_decode(temp.clone(), META_KEY)?;

    let json_string = String::from_utf8(temp[6..].to_vec())?;

    let meta: Meta = serde_json::from_str(json_string.as_str())?;

    return Ok(meta);
}

fn album_image(file: &mut File) -> anyhow::Result<Vec<u8>> {
    let mut buffer = [0u8; 4];

    file.read(&mut buffer)?;

    let len = get_length(&buffer);

    let mut buffer = vec![0u8; len as usize];

    file.read(&mut buffer)?;

    return Ok(buffer);
}

fn music_data(
    input_file: &mut File,
    output_file: &mut File,
    cr4_key: Vec<u8>,
) -> anyhow::Result<()> {
    let mut cr4 = CR4::new();

    cr4.ksa(cr4_key);

    let mut buffer = [0u8; 0x8000];

    let mut len;

    loop {
        len = input_file.read(&mut buffer)?;

        if len <= 0 {
            break;
        }

        cr4.prga(&mut buffer, len);

        output_file.write(&buffer)?;
    }

    output_file.flush()?;

    return Ok(());
}

fn combine_file(meta: Meta, output: &PathBuf, image_data: Vec<u8>) -> anyhow::Result<()> {
    let mut tag = Tag::new().read_from_path(&output)?;

    tag.set_title(meta.music_name.as_str());

    tag.set_album_title(meta.album.as_str());

    meta.artist.iter().for_each(|artist| {
        if let Some(artist) = artist.get(0).and_then(Value::as_str) {
            tag.add_artist(artist);
        }
    });

    let cover = Picture {
        mime_type: album_image_mime_type(&image_data),
        data: image_data.as_slice(),
    };

    tag.set_album_cover(cover);

    tag.write_to_path(
        output
            .to_str()
            .ok_or(anyhow::Error::msg("output path error"))?,
    )?;

    Ok(())
}

use aes::Aes128;
use anyhow::bail;
use audiotags::{MimeType, Picture, Tag};
use base64::Engine;
use block_modes::block_padding::Pkcs7;
use block_modes::Ecb;
use block_modes::{BlockMode, BlockModeError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

const CODE_KEY: [u8; 16] = [
    0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57,
];
const META_KEY: [u8; 16] = [
    0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28,
];

fn aes_decode(mut ciphertext: Vec<u8>, key: [u8; 16]) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes128Ecb::new_from_slices(&key, &[]).unwrap();

    return cipher
        .decrypt(ciphertext.as_mut_slice())
        .map(|x| x.to_vec());
}

fn get_length(bytes: &[u8; 4]) -> u32 {
    let mut len = 0u32;
    len |= bytes[0] as u32 & 0xff;
    len |= (bytes[1] as u32 & 0xff) << 8;
    len |= (bytes[2] as u32 & 0xff) << 16;
    len |= (bytes[3] as u32 & 0xff) << 24;
    return len;
}

struct CR4 {
    trunk: [usize; 256],
}

impl CR4 {
    fn new() -> CR4 {
        CR4 { trunk: [0; 256] }
    }

    fn ksa(&mut self, key: Vec<u8>) {
        let len = key.len();
        for i in 0..256 {
            self.trunk[i] = i;
        }
        let mut j = 0;

        for i in 0..256 {
            j = (j + self.trunk[i] + key[i % len] as usize) & 0xff;
            let swap = self.trunk[i];
            self.trunk[i] = self.trunk[j];
            self.trunk[j] = swap;
        }
    }

    fn prga(&self, data: &mut [u8; 0x8000], len: usize) {
        for k in 0..len {
            let i = (k + 1) & 0xff;
            let j = (self.trunk[i] + i) & 0xff;
            data[k] ^= self.trunk[(self.trunk[i] + self.trunk[j]) & 0xff] as u8;
        }
    }
}

fn album_image_mime_type(album_image: &Vec<u8>) -> MimeType {
    let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG file header
    if album_image.len() <= 8 {
        return MimeType::Png;
    }

    for i in 0..8 {
        if album_image[i] != png[i] {
            return MimeType::Jpeg;
        }
    }
    return MimeType::Png;
}

#[derive(Serialize, Deserialize, Debug)]
struct Meta {
    pub format: String,

    #[serde(rename = "musicName")]
    pub music_name: String,

    pub artist: Vec<Vec<Value>>,

    pub album: String,

    pub bitrate: Option<i64>,

    #[serde(rename = "transNames")]
    pub trans_names: Option<Vec<String>>,

    #[serde(rename = "albumPic")]
    pub album_pic: Option<String>,
}
