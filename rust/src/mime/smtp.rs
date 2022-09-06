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
#[repr(C)]
pub struct MimeStateSMTP {
    pub state_flag: MimeSmtpParserState,
}

pub fn mime_smtp_state_init() -> Option<MimeStateSMTP> {
    let r = MimeStateSMTP::default();
    return Some(r);
}

#[no_mangle]
pub unsafe extern "C" fn rs_mime_smtp_state_init() -> *mut MimeStateSMTP {
    if let Some(ctx) = mime_smtp_state_init() {
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

fn mime_smpt_parse_line(ctx: &mut MimeStateSMTP, i: &[u8]) -> (MimeSmtpParserResult, u32) {
    return (MimeSmtpParserResult::MimeSmtpNeedsMore, 0);
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_mime_parse_line(
    input: *const u8, input_len: u32, delim_len: u8, warnings: *mut u32, ctx: &mut MimeStateSMTP,
) -> MimeSmtpParserResult {
    let slice = build_slice!(input, input_len as usize);
    let (r, w) = mime_smpt_parse_line(ctx, slice);
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

//TODOrust2 = lua
