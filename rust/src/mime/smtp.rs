/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::mime;
use crate::filecontainer::FileContainer;
use std::os::raw::c_uchar;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub enum MimeSmtpParserState {
    MimeSmtpStart = 0,
    MimeSmtpHeader = 1,
    MimeSmtpBody = 2,
    MimeSmtpParserError = 3,
}

impl Default for MimeSmtpParserState {
    fn default() -> Self {
        MimeSmtpParserState::MimeSmtpStart
    }
}

#[derive(Debug, Default)]
pub struct MimeHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct MimeStateSMTP<'a> {
    pub state_flag: MimeSmtpParserState,
    headers: Vec<MimeHeader>,
    filename: Vec<u8>,
    boundary: Vec<u8>,
    quoted_buffer: Vec<u8>,
    encoding: MimeSmtpEncoding,
    files: &'a mut FileContainer,
}

pub fn mime_smtp_state_init(files: &mut FileContainer) -> Option<MimeStateSMTP> {
    let r = MimeStateSMTP {
        state_flag: MimeSmtpParserState::MimeSmtpStart,
        headers: Vec::new(),
        filename: Vec::new(),
        boundary: Vec::new(),
        quoted_buffer: Vec::new(),
        encoding: MimeSmtpEncoding::Plain,
        files: files,
    };
    return Some(r);
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_state_init(files: &mut FileContainer) -> *mut MimeStateSMTP {
    if let Some(ctx) = mime_smtp_state_init(files) {
        let boxed = Box::new(ctx);
        return Box::into_raw(boxed) as *mut _;
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_state_free(ctx: &mut MimeStateSMTP) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum MimeSmtpParserResult {
    MimeSmtpNeedsMore = 0,
    MimeSmtpFileOpen = 1,
    MimeSmtpFileClose = 2,
    MimeSmtpFileChunk = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub enum MimeSmtpEncoding {
    Plain = 0,
    Base64 = 1,
    QuotedPrintable = 2,
}

impl Default for MimeSmtpEncoding {
    fn default() -> Self {
        MimeSmtpEncoding::Plain
    }
}

// Cannot use BIT_U32 macros as they do not get exported by cbindgen :-/
pub const MIME_ANOM_INVALID_BASE64: u32 = 0x1;
pub const MIME_ANOM_INVALID_QP: u32 = 0x2;
pub const MIME_ANOM_LONG_LINE: u32 = 0x4;
pub const MIME_ANOM_LONG_ENC_LINE: u32 = 0x8;
pub const MIME_ANOM_LONG_HEADER_NAME: u32 = 0x10;
pub const MIME_ANOM_LONG_HEADER_VALUE: u32 = 0x20;
pub const MIME_ANOM_MALFORMED_MSG: u32 = 0x40;
pub const MIME_ANOM_LONG_BOUNDARY: u32 = 0x80;
pub const MIME_ANOM_LONG_FILENAME: u32 = 0x100;

fn mime_smtp_process_headers(ctx: &mut MimeStateSMTP) {
    let mut sections_values = Vec::new();
    for h in &ctx.headers {
        if mime::rs_equals_lowercase(&h.name, b"content-disposition") {
            if ctx.filename.len() == 0 {
                if let Ok(value) =
                    mime::mime_find_header_token(&h.value, b"filename", &mut sections_values)
                {
                    ctx.filename.extend_from_slice(value);
                    sections_values.clear();
                }
            }
        } else if mime::rs_equals_lowercase(&h.name, b"content-transfer-encoding") {
            if mime::rs_equals_lowercase(&h.value, b"base64") {
                ctx.encoding = MimeSmtpEncoding::Base64;
            } else if mime::rs_equals_lowercase(&h.value, b"quoted-printable") {
                ctx.encoding = MimeSmtpEncoding::QuotedPrintable;
            }
        }
    }
    for h in &ctx.headers {
        if mime::rs_equals_lowercase(&h.name, b"content-type") {
            if ctx.filename.len() == 0 {
                if let Ok(value) =
                    mime::mime_find_header_token(&h.value, b"name", &mut sections_values)
                {
                    ctx.filename.extend_from_slice(value);
                    sections_values.clear();
                }
            }
            if let Ok(value) =
                mime::mime_find_header_token(&h.value, b"boundary", &mut sections_values)
            {
                ctx.boundary.extend_from_slice(value);
                sections_values.clear();
            }
            break;
        }
    }
}

// Defined in util-file.h
extern "C" {
    pub fn FileAppendData(
        c: *mut FileContainer, data: *const c_uchar, data_len: u32,
    ) -> std::os::raw::c_int;
}

fn hex(i: u8) -> Option<u8> {
    if i >= b'0' && i <= b'9' {
        return Some(i - b'0');
    }
    if i >= b'A' && i <= b'F' {
        return Some(i - b'A' + 10);
    }
    return None;
}

fn mime_smtp_parse_line(
    ctx: &mut MimeStateSMTP, i: &[u8], full: &[u8],
) -> (MimeSmtpParserResult, u32) {
    match ctx.state_flag {
        MimeSmtpParserState::MimeSmtpStart => {
            if i.len() == 0 {
                ctx.state_flag = MimeSmtpParserState::MimeSmtpBody;
                mime_smtp_process_headers(ctx);
                return (MimeSmtpParserResult::MimeSmtpFileOpen, 0);
            } else if let Ok((name, value)) = mime::mime_parse_header_line(i) {
                ctx.state_flag = MimeSmtpParserState::MimeSmtpHeader;
                let mut h = MimeHeader::default();
                h.name.extend_from_slice(name);
                h.value.extend_from_slice(value);
                ctx.headers.push(h);
            } // else event ?
        }
        MimeSmtpParserState::MimeSmtpHeader => {
            if i.len() == 0 {
                ctx.state_flag = MimeSmtpParserState::MimeSmtpBody;
                mime_smtp_process_headers(ctx);
                return (MimeSmtpParserResult::MimeSmtpFileOpen, 0);
            } else if i[0] == b' ' || i[0] == b'\t' {
                let last = ctx.headers.len() - 1;
                ctx.headers[last].value.extend_from_slice(&i[1..]);
            } else if let Ok((name, value)) = mime::mime_parse_header_line(i) {
                let mut h = MimeHeader::default();
                h.name.extend_from_slice(name);
                h.value.extend_from_slice(value);
                ctx.headers.push(h);
            }
        }
        MimeSmtpParserState::MimeSmtpBody => {
            if ctx.boundary.len() > 0 && i.len() >= ctx.boundary.len() {
                if &i[..ctx.boundary.len()] == ctx.boundary {
                    ctx.state_flag = MimeSmtpParserState::MimeSmtpStart;
                    let toclose = ctx.filename.len() > 0;
                    ctx.filename.clear();
                    ctx.headers.clear();
                    ctx.encoding = MimeSmtpEncoding::Plain;
                    if toclose {
                        return (MimeSmtpParserResult::MimeSmtpFileClose, 0);
                    }
                    return (MimeSmtpParserResult::MimeSmtpNeedsMore, 0);
                }
            }
            if ctx.filename.len() == 0 {
                return (MimeSmtpParserResult::MimeSmtpNeedsMore, 0);
            }
            match ctx.encoding {
                MimeSmtpEncoding::Plain => unsafe {
                    FileAppendData(ctx.files, full.as_ptr(), full.len() as u32);
                },
                MimeSmtpEncoding::Base64 => {
                    //TODOrust1 base64
                }
                MimeSmtpEncoding::QuotedPrintable => {
                    let mut c = 0;
                    while c < i.len() {
                        if i[c] == b'=' {
                            if c == i.len() - 1 {
                                break;
                            } else if c + 2 > i.len() {
                                // log event ?
                                break;
                            }
                            if let Some(v) = hex(i[c + 1]) {
                                if let Some(v2) = hex(i[c + 2]) {
                                    ctx.quoted_buffer.push((v << 4) | v2);
                                }
                            }
                            c += 3;
                        } else {
                            ctx.quoted_buffer.push(i[c]);
                            c += 1;
                        }
                    }
                    ctx.quoted_buffer.extend_from_slice(&full[i.len()..]);
                    unsafe {
                        FileAppendData(
                            ctx.files,
                            ctx.quoted_buffer.as_ptr(),
                            ctx.quoted_buffer.len() as u32,
                        );
                    }
                    ctx.quoted_buffer.clear();
                }
            }
            return (MimeSmtpParserResult::MimeSmtpFileChunk, 0);
        }
        _ => {}
    }
    return (MimeSmtpParserResult::MimeSmtpNeedsMore, 0);
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_mime_parse_line(
    input: *const u8, input_len: u32, delim_len: u8, warnings: *mut u32, ctx: &mut MimeStateSMTP,
) -> MimeSmtpParserResult {
    let full_line = build_slice!(input, input_len as usize + delim_len as usize);
    let line = &full_line[..input_len as usize];
    let (r, w) = mime_smtp_parse_line(ctx, line, full_line);
    *warnings = w;
    return r;
}

fn mime_smtp_complete(ctx: &mut MimeStateSMTP) -> (MimeSmtpParserResult, u32) {
    return (MimeSmtpParserResult::MimeSmtpFileClose, 0);
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_mime_complete(
    ctx: &mut MimeStateSMTP, warnings: *mut u32,
) -> MimeSmtpParserResult {
    let (r, w) = mime_smtp_complete(ctx);
    *warnings = w;
    return r;
}

//TODOrust3 move to log.rs ?
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_subject_md5(js: &mut JsonBuilder, ctx: &mut MimeStateSMTP) -> Result<(), JsonError> {
    js.set_string("subject_md5", "TODO")?;
    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_subject_md5(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_body_md5(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_field_array(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP, str: *const std::os::raw::c_char,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_field_comma(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP, str: *const std::os::raw::c_char,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_field_string(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP, str: *const std::os::raw::c_char,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_log_data(
    js: &mut JsonBuilder, ctx: &mut MimeStateSMTP,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_set_state(
    ctx: &mut MimeStateSMTP, state: MimeSmtpParserState,
) {
    ctx.state_flag = state;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_get_state(ctx: &mut MimeStateSMTP) -> MimeSmtpParserState {
    return ctx.state_flag;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_get_filename(
    ctx: &mut MimeStateSMTP, buffer: *mut *const u8, filename_len: *mut u16,
) {
    if ctx.filename.len() > 0 {
        *buffer = ctx.filename.as_ptr();
        if ctx.filename.len() < u16::MAX.into() {
            *filename_len = ctx.filename.len() as u16;
        } else {
            *filename_len = u16::MAX;
        }
    } else {
        *buffer = std::ptr::null_mut();
        *filename_len = 0;
    }
}
//TODOrust2 = lua
