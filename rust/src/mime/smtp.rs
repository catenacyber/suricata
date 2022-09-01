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
